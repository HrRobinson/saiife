//! Windows path canonicalization (W6): a protected file cannot be reached
//! under another spelling. Everything here is text: no filesystem access but
//! `resolved`, which reaches the OS only under `cfg(windows)`, so any host's
//! tests run every rule.
//!
//! `canonical` returns `c:/…` (drive letter lower-cased, the rest as spelled)
//! or `//host/share/…`:
//!
//! - `\` and `/` both separate;
//! - `\\?\C:\…`, `\\.\C:\…` and `\??\C:\…` are `c:/…`; `\\?\UNC\host\share`
//!   is `//host/share`; an admin share of this machine is what it shares
//!   (`\\localhost\c$\x` is `c:/x`), under any name of this machine;
//! - Git Bash's `/c/…`, `/cygdrive/c/…`, `/proc/cygdrive/c/…` and WSL's
//!   `/mnt/c/…` are `c:/…`;
//! - PowerShell's `FileSystem::` provider prefix is dropped;
//! - each component loses its stream suffix (`:s`, `::$DATA`), then its
//!   trailing dots and spaces;
//! - `~`, `$HOME`, `$env:NAME`, `${env:NAME}`, `%NAME%` expand from `PathVars`;
//! - relative paths join the working directory; `C:x` only one on that drive.
//!
//! It never guesses a form that could be wrong. `read` says why there is none:
//!
//! - `Unread::Unreadable`: an unknown variable, a device namespace path
//!   (`\\?\Volume{…}`, `\\.\PhysicalDrive0`), a PowerShell drive (`HKLM:\`,
//!   `temp:\`), or a character Win32 refuses or reads as a wildcard (`<`, `>`,
//!   `"`, `|`, control characters). It could name anything, so the engine
//!   denies it.
//! - `Unread::NoAnchor`: an empty path, or a relative one with no working
//!   directory known. The engine treats it as it does in POSIX style.
//!
//! Not lexically knowable, and left to `resolved` when the path exists: 8.3
//! short names (`PROGRA~1`), junctions and symlinks.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::canon::PathVars;

/// The variable holding this machine's name (not a path).
pub const COMPUTER_NAME: &str = "COMPUTERNAME";

/// Why a spelling has no canonical form (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unread {
    /// Empty, or relative with no working directory known.
    NoAnchor,
    /// It could name anything: the text says what it is.
    Unreadable(&'static str),
}

/// `raw` as the canonical text of what it names, or `None` if it cannot be
/// read. `cwd` is the working directory at this point of a command line, else
/// the one in `vars` applies.
pub fn canonical(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Option<String> {
    read(raw, cwd, vars).ok()
}

/// `canonical`, saying why when there is no form.
pub fn read(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Result<String, Unread> {
    let anchor = match cwd {
        Some(c) => c.to_str().and_then(|c| absolute_text(c, None, vars).ok()),
        None => vars.cwd().and_then(Path::to_str).map(str::to_string),
    };
    let anchor = anchor.as_deref();
    let expanded = expand_vars(strip_provider(raw), anchor, vars)?;
    absolute_text(&expanded, anchor, vars)
}

/// `s` as path rules compare it: each character by its simple case mapping,
/// one at a time, as NTFS does. (`str::to_lowercase` will not do: it reads a
/// `Σ` by its position in the word, so `ΑΣ` and `ασ` would differ.)
pub fn fold(s: &str) -> String {
    fn single(mut it: impl Iterator<Item = char>) -> Option<char> {
        let c = it.next()?;
        it.next().is_none().then_some(c)
    }
    s.chars()
        .map(|c| {
            let upper = single(c.to_uppercase()).unwrap_or(c);
            single(upper.to_lowercase()).unwrap_or(upper)
        })
        .collect()
}

/// A canonical path's root (`c:/`, `//host/share/`, `//host`) and the rest.
pub fn split_root(canon: &str) -> (&str, &str) {
    let end = match canon.strip_prefix("//") {
        Some(unc) => match unc.match_indices('/').nth(1) {
            Some((i, _)) => i + 3,
            None => canon.len(),
        },
        None => canon.len().min(3),
    };
    canon.split_at(end)
}

/// The forms a variable or working directory is bound to, like POSIX's
/// `with_var`: the resolved one first, then as spelled. Empty when the value
/// is not an absolute Windows path. No variables are expanded in it.
pub(crate) fn value_forms(value: &Path, vars: &PathVars) -> Vec<String> {
    let Some(spelled) = value
        .to_str()
        .and_then(|v| absolute_text(v, None, vars).ok())
    else {
        return Vec::new();
    };
    let real = resolved(&spelled, vars);
    if real == spelled {
        vec![spelled]
    } else {
        vec![real, spelled]
    }
}

/// What the OS says a canonical path names: 8.3 names, junctions and
/// symlinks resolved in the longest prefix that exists. The path itself
/// when nothing does, and always on a host that is not Windows.
pub(crate) fn resolved(canon: &str, vars: &PathVars) -> String {
    resolved_with(canon, vars, os_canonicalize)
}

#[cfg(windows)]
fn os_canonicalize(path: &str) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

#[cfg(not(windows))]
fn os_canonicalize(_path: &str) -> Option<String> {
    None
}

/// Longest path Win32 accepts; anything longer cannot exist on disk.
const WIN_PATH_MAX: usize = 32767;
/// Prefixes tried per path: each one is a system call on the hook path.
const RESOLVE_TRIES: usize = 32;

fn resolved_with(canon: &str, vars: &PathVars, os: impl Fn(&str) -> Option<String>) -> String {
    if canon.len() > WIN_PATH_MAX {
        return canon.to_string();
    }
    let (root, _) = split_root(canon);
    let mut head = canon;
    for _ in 0..RESOLVE_TRIES {
        // What the OS returns is a real name: no variables to expand in it.
        if let Some(real) = os(head).and_then(|r| absolute_text(&r, None, vars).ok()) {
            let tail = canon[head.len()..].trim_start_matches('/');
            return if tail.is_empty() {
                real
            } else {
                format!("{}/{tail}", real.trim_end_matches('/'))
            };
        }
        if head.len() <= root.len() {
            break;
        }
        head = match head.rfind('/') {
            Some(i) if i >= root.len() => &head[..i],
            _ => root,
        };
    }
    canon.to_string()
}

fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// `raw` without PowerShell's provider prefix.
fn strip_provider(raw: &str) -> &str {
    [
        r"Microsoft.PowerShell.Core\FileSystem::",
        "Microsoft.PowerShell.Core/FileSystem::",
        "FileSystem::",
    ]
    .iter()
    .find_map(|p| strip_ci(raw, p))
    .unwrap_or(raw)
}

/// The value of a variable a path may be spelled with. Names are matched
/// without case. Some come from the profile dir when not bound on their own.
fn lookup(name: &str, cwd: Option<&str>, vars: &PathVars) -> Option<String> {
    let name = name.to_ascii_uppercase();
    let home = || vars.home().and_then(Path::to_str);
    let drive_of = |p: &str| p.get(..2).filter(|d| d.ends_with(':')).map(str::to_string);
    let bound = |n: &str| vars.value_ignoring_case(n).map(str::to_string);
    let system_drive = || {
        bound("SYSTEMDRIVE")
            .and_then(|d| drive_of(&d))
            .or_else(|| home().and_then(drive_of))
    };
    match name.as_str() {
        "HOME" | "USERPROFILE" => home().map(str::to_string),
        "PWD" | "CD" => cwd.map(str::to_string),
        "TEMP" | "TMP" => bound("TEMP").or_else(|| bound("TMP")),
        "HOMEDRIVE" => home().and_then(drive_of),
        "HOMEPATH" => home().map(|h| format!("/{}", split_root(h).1)),
        "USERNAME" => home()
            .and_then(|h| h.rsplit('/').next())
            .map(str::to_string),
        "SYSTEMDRIVE" => system_drive(),
        "SYSTEMROOT" | "WINDIR" => bound("SYSTEMROOT")
            .or_else(|| bound("WINDIR"))
            .or_else(|| Some(format!("{}/Windows", system_drive()?))),
        other => bound(other),
    }
}

/// `lookup`, saying why there is no value: the working directory's own
/// variables are `NoAnchor` when it is unknown, as a relative path is.
fn var(name: &str, cwd: Option<&str>, vars: &PathVars) -> Result<String, Unread> {
    lookup(name, cwd, vars).ok_or_else(|| {
        let of_cwd = name.eq_ignore_ascii_case("PWD") || name.eq_ignore_ascii_case("CD");
        if of_cwd && cwd.is_none() {
            Unread::NoAnchor
        } else {
            Unread::Unreadable("a variable with no known value")
        }
    })
}

/// `raw` with its variables replaced. An error for what looks like a variable
/// and has no value, except a bare `$name` inside a path: `$` is an ordinary
/// character there (`C:\$Recycle.Bin`, `\\host\c$`).
fn expand_vars(raw: &str, cwd: Option<&str>, vars: &PathVars) -> Result<String, Unread> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    if let Some(after) = rest.strip_prefix('~') {
        let end = after.find(['/', '\\']);
        match (&after[..end.unwrap_or(after.len())], end) {
            ("", _) => {
                out.push_str(&var("HOME", cwd, vars)?);
                rest = after;
            }
            ("+", _) => {
                out.push_str(cwd.ok_or(Unread::NoAnchor)?);
                rest = &after[1..];
            }
            ("-", _) => return Err(Unread::Unreadable("the previous directory, `~-`")),
            // `~name/…`, as bash reads it: a sibling of this profile dir.
            (_, Some(_)) => {
                let home = var("HOME", cwd, vars)?;
                let parent = home.rsplit_once('/').map(|(parent, _)| parent);
                out.push_str(parent.ok_or(Unread::Unreadable("another user's home"))?);
                out.push('/');
                rest = after;
            }
            // `~$doc.docx`: an ordinary name.
            (_, None) => {}
        }
    }
    let mut at_start = out.is_empty();
    while let Some(i) = rest.find(['%', '$']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let (text, used) = if tail.starts_with('%') {
            percent_var(tail, cwd, vars)?
        } else {
            dollar_var(tail, at_start && i == 0, cwd, vars)?
        };
        at_start = false;
        out.push_str(&text);
        rest = &tail[used..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The expansion of the `%…` at the start of `s` and the bytes it used. A `%`
/// that does not open a variable (`100%.txt`, `%%`) is itself.
fn percent_var(s: &str, cwd: Option<&str>, vars: &PathVars) -> Result<(String, usize), Unread> {
    let name = s[1..].find('%').map(|end| &s[1..1 + end]);
    match name {
        Some(n) if !n.is_empty() && !n.contains(['/', '\\', ':']) => {
            Ok((var(n, cwd, vars)?, n.len() + 2))
        }
        _ => Ok(("%".to_string(), 1)),
    }
}

/// The expansion of the `$…` at the start of `s` and the bytes it used.
fn dollar_var(
    s: &str,
    at_start: bool,
    cwd: Option<&str>,
    vars: &PathVars,
) -> Result<(String, usize), Unread> {
    let after = &s[1..];
    if after.starts_with('(') {
        return Err(Unread::Unreadable("a command substitution"));
    }
    if let Some(inner) = after.strip_prefix('{') {
        let end = inner
            .find('}')
            .ok_or(Unread::Unreadable("an unterminated `${`"))?;
        let name = &inner[..end];
        let name = strip_ci(name, "env:").unwrap_or(name);
        return Ok((var(name, cwd, vars)?, end + 3));
    }
    let word = |t: &str| {
        t.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(t.len())
    };
    if let Some(env) = strip_ci(after, "env:") {
        let n = word(env);
        if n == 0 {
            return Err(Unread::Unreadable("a `$env:` with no name"));
        }
        return Ok((var(&env[..n], cwd, vars)?, "$env:".len() + n));
    }
    let n = word(after);
    if n == 0 || after.as_bytes()[0].is_ascii_digit() {
        return Ok(("$".to_string(), 1));
    }
    match var(&after[..n], cwd, vars) {
        Ok(v) => Ok((v, n + 1)),
        Err(e) if at_start => Err(e),
        Err(_) => Ok(("$".to_string(), 1)),
    }
}

/// Characters Win32 refuses in a path; `<`, `>` and `"` are also wildcards to
/// `FindFirstFile`, so `.en<` can name `.env`.
fn illegal(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|'))
}

/// `first`, `rest` of `s`, split at the first separator.
fn split_seg(s: &str) -> (&str, &str) {
    s.split_once('/').unwrap_or((s, ""))
}

/// The drive a component names: one ASCII letter, lower-cased.
fn drive_letter(seg: &str) -> Option<char> {
    let mut chars = seg.chars();
    let c = chars.next().filter(char::is_ascii_alphabetic)?;
    chars.next().is_none().then(|| c.to_ascii_lowercase())
}

/// `s` (variables already expanded) made absolute. `cwd` is canonical.
fn absolute_text(s: &str, cwd: Option<&str>, vars: &PathVars) -> Result<String, Unread> {
    if s.is_empty() {
        return Err(Unread::NoAnchor);
    }
    if illegal(s) {
        return Err(Unread::Unreadable(
            "a character Windows refuses or reads as a wildcard",
        ));
    }
    let cwd_root = || cwd.map(split_root).ok_or(Unread::NoAnchor);
    let t = s.replace('\\', "/");
    let device_ns = ["//?/", "//./"]
        .iter()
        .find_map(|p| t.strip_prefix(p))
        // `/??/x` written with slashes is a glob, not the NT namespace.
        .or_else(|| t.strip_prefix("/??/").filter(|_| s.starts_with('\\')));
    let (root, rest): (String, String) = if let Some(after) = device_ns {
        device(after, vars).ok_or(Unread::Unreadable("a device namespace path"))?
    } else if t.starts_with("//") && !t.starts_with("///") {
        unc(&t[2..], vars).ok_or(Unread::Unreadable("a UNC path with no usable host"))?
    } else if let Some(body) = t.strip_prefix('/') {
        // Three or more slashes are one to Git Bash.
        let body = body.trim_start_matches('/');
        // A leading backslash is Win32's "root of this drive"; only a `/`
        // can be Git Bash's drive form.
        match s.starts_with('/').then(|| git_bash_drive(body)).flatten() {
            Some((drive, tail)) => (format!("{drive}:/"), tail.to_string()),
            None => (cwd_root()?.0.to_string(), body.to_string()),
        }
    } else if t.chars().nth(1) == Some(':') {
        let first = t.chars().next().unwrap_or(':');
        let drive = drive_letter(first.encode_utf8(&mut [0; 4]))
            .ok_or(Unread::Unreadable("a drive that is not a letter"))?;
        let after = &t[2..];
        match after.strip_prefix('/') {
            Some(tail) => (format!("{drive}:/"), tail.to_string()),
            // `C:x` is relative to that drive's own working directory; only
            // the current drive's is known.
            None => {
                let (root, base) = cwd_root()?;
                if !root.starts_with(drive) {
                    return Err(Unread::Unreadable(
                        "a path relative to another drive's working directory",
                    ));
                }
                (root.to_string(), format!("{base}/{after}"))
            }
        }
    } else {
        let is_ps_drive = split_seg(&t).0.strip_suffix(':').is_some_and(|n| {
            n.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
        if is_ps_drive {
            return Err(Unread::Unreadable("a PowerShell drive"));
        }
        let (root, base) = cwd_root()?;
        (root.to_string(), format!("{base}/{t}"))
    };
    Ok(assemble(&root, &rest))
}

/// `body` (no leading slash) as a Git Bash, Cygwin or WSL drive path.
fn git_bash_drive(body: &str) -> Option<(char, &str)> {
    let mounted = ["proc/cygdrive/", "cygdrive/", "mnt/"]
        .iter()
        .find_map(|p| strip_ci(body, p));
    let (seg, tail) = split_seg(mounted.unwrap_or(body));
    Some((drive_letter(component_name(seg))?, tail))
}

/// After `\\?\`: a drive, `UNC\…`, or a device namespace nothing here can
/// read (`Volume{…}`, `GLOBALROOT`, `PhysicalDrive0`, `pipe`).
fn device(after: &str, vars: &PathVars) -> Option<(String, String)> {
    let (seg, tail) = split_seg(after);
    if seg.eq_ignore_ascii_case("UNC") {
        return unc(tail, vars);
    }
    let drive = drive_letter(seg.strip_suffix(':')?)?;
    Some((format!("{drive}:/"), tail.to_string()))
}

/// After `\\`: `host/share/rest`. An admin share of this machine is what it
/// shares; any other share is judged by its own name.
fn unc(after: &str, vars: &PathVars) -> Option<(String, String)> {
    let (host, tail) = split_seg(after);
    let host = host.trim_end_matches(['.', ' ']);
    if host.is_empty() || host == "?" {
        return None;
    }
    let (share, tail) = split_seg(tail.trim_start_matches('/'));
    let share = component_name(share);
    if share.is_empty() {
        return Some((format!("//{host}"), String::new()));
    }
    if is_local_host(host, vars) {
        if let Some(drive) = share.strip_suffix('$').and_then(drive_letter) {
            return Some((format!("{drive}:/"), tail.to_string()));
        }
        if share.eq_ignore_ascii_case("admin$") {
            let windows = lookup("SYSTEMROOT", None, vars)?;
            let (root, base) = split_root(&windows);
            return Some((root.to_string(), format!("{base}/{tail}")));
        }
    }
    Some((format!("//{host}/{share}"), tail.to_string()))
}

/// A component without its stream suffix and trailing dots and spaces. A
/// component of only dots and spaces comes back empty.
fn component_name(c: &str) -> &str {
    c.split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches(['.', ' '])
}

/// `root` and the normalized components of `rest`. `..` stops at the root.
fn assemble(root: &str, rest: &str) -> String {
    let mut comps: Vec<&str> = Vec::new();
    for c in rest.split('/') {
        let name = component_name(c);
        if !name.is_empty() {
            comps.push(name);
        } else if c.split(':').next().unwrap_or("").matches('.').count() == 2 {
            // `..`, also as `.. ` or `..::$DATA`: Win32 strips those back to
            // `..`. `.`, `...` and the like add nothing to where a path
            // lands: dropping them judges the tail as if they were not there.
            comps.pop();
        }
    }
    let root = root.trim_end_matches('/');
    if comps.is_empty() {
        return if root.starts_with("//") {
            root.to_string()
        } else {
            format!("{root}/")
        };
    }
    format!("{root}/{}", comps.join("/"))
}

/// A host name that is this machine: `localhost`, a loopback or unspecified
/// address in any spelling `getaddrinfo` takes, or the computer's name.
fn is_local_host(host: &str, vars: &PathVars) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_start_matches('[').trim_end_matches(']');
    let label = h.split('.').next().unwrap_or(h);
    if label == "localhost"
        || vars
            .value_ignoring_case(COMPUTER_NAME)
            .is_some_and(|n| n.eq_ignore_ascii_case(label))
    {
        return true;
    }
    if let Some(a) = aton(h) {
        return a.is_loopback() || a.is_unspecified();
    }
    // `0--1.ipv6-literal.net` is Windows's UNC spelling of `::1`.
    let literal = h
        .strip_suffix(".ipv6-literal.net")
        .map(|l| l.replace('-', ":"));
    match literal.as_deref().unwrap_or(h).parse::<IpAddr>() {
        Ok(IpAddr::V6(a)) => {
            a.is_loopback()
                || a.is_unspecified()
                || a.to_ipv4_mapped()
                    .is_some_and(|m| m.is_loopback() || m.is_unspecified())
        }
        Ok(IpAddr::V4(a)) => a.is_loopback() || a.is_unspecified(),
        Err(_) => false,
    }
}

/// An IPv4 address as `inet_aton` reads it: one to four parts, each decimal,
/// `0x` hex or `0` octal, the last filling the remaining bytes (`127.1`,
/// `2130706433`, `0x7f.0.0.1`).
fn aton(h: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let mut value: u32 = 0;
    for (i, p) in parts.iter().enumerate() {
        let n = if let Some(x) = p.strip_prefix("0x") {
            u32::from_str_radix(x, 16).ok()?
        } else if p.len() > 1 && p.starts_with('0') {
            u32::from_str_radix(p, 8).ok()?
        } else if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
            p.parse().ok()?
        } else {
            return None;
        };
        if i + 1 == parts.len() {
            let room = 4 - i as u32;
            if room < 4 && u64::from(n) >= 1u64 << (8 * room) {
                return None;
            }
            value = value.checked_add(n)?;
        } else {
            if n > 255 {
                return None;
            }
            value += n << (24 - 8 * i as u32);
        }
    }
    Some(Ipv4Addr::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::builtin_packs;
    use crate::canon::{path_forms, PathStyle};
    use crate::engine::{AllowTrace, Decision, Engine};
    use crate::pack::load_pack_str;
    use crate::pathrule::Access;

    fn vars() -> PathVars {
        PathVars::new()
            .with_style(PathStyle::Windows)
            .with_cwd(r"C:\p")
            .with_var("USERPROFILE", r"C:\Users\a")
            .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
            .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
            .with_var("TEMP", r"C:\Users\a\AppData\Local\Temp")
            .with_var("COMPUTERNAME", "MYPC")
    }

    fn c(raw: &str) -> Option<String> {
        canonical(raw, None, &vars())
    }

    fn want(raw: &str, expected: &str) {
        assert_eq!(c(raw).as_deref(), Some(expected), "{raw}");
    }

    const ID_RSA: &str = "c:/Users/a/.ssh/id_rsa";

    /// Every spelling that reaches `id_rsa`, folded equal to the plain path.
    const ID_RSA_SPELLINGS: &[&str] = &[
        r"C:\Users\a\.ssh\id_rsa",
        "c:/USERS/a/.SSH/ID_RSA",
        r"\\?\C:\Users\a\.ssh\id_rsa",
        r"\\.\C:\Users\a\.ssh\id_rsa",
        r"\??\C:\Users\a\.ssh\id_rsa",
        "//?/C:/Users/a/.ssh/id_rsa",
        "/c/Users/a/.ssh/id_rsa",
        "/C/Users/a/.ssh/id_rsa",
        "///c/Users/a/.ssh/id_rsa",
        "/c:/Users/a/.ssh/id_rsa",
        "/cygdrive/c/Users/a/.ssh/id_rsa",
        "/proc/cygdrive/c/Users/a/.ssh/id_rsa",
        "/mnt/c/Users/a/.ssh/id_rsa",
        r"~\.ssh\id_rsa",
        "~/.ssh/id_rsa",
        r"~a\.ssh\id_rsa",
        r"$HOME\.ssh\id_rsa",
        "${HOME}/.ssh/id_rsa",
        "$home/.ssh/id_rsa",
        "$USERPROFILE/.ssh/id_rsa",
        r"$env:USERPROFILE\.ssh\id_rsa",
        r"$ENV:userprofile\.ssh\id_rsa",
        r"${env:USERPROFILE}\.ssh\id_rsa",
        r"%USERPROFILE%\.ssh\id_rsa",
        r"%userprofile%\.ssh\id_rsa",
        r"%HOMEDRIVE%%HOMEPATH%\.ssh\id_rsa",
        r"$env:HOMEDRIVE$env:HOMEPATH\.ssh\id_rsa",
        r"%SystemDrive%\Users\a\.ssh\id_rsa",
        r"C:\Users\%USERNAME%\.ssh\id_rsa",
        r"C:\Users\$env:USERNAME\.ssh\id_rsa",
        r"\\localhost\c$\Users\a\.ssh\id_rsa",
        r"\\LOCALHOST\C$\Users\a\.ssh\id_rsa",
        r"\\localhost.\c$\Users\a\.ssh\id_rsa",
        r"\\localhost.localdomain\c$\Users\a\.ssh\id_rsa",
        r"\\127.0.0.1\c$\Users\a\.ssh\id_rsa",
        r"\\127.1\c$\Users\a\.ssh\id_rsa",
        r"\\127.9.9.9\c$\Users\a\.ssh\id_rsa",
        r"\\2130706433\c$\Users\a\.ssh\id_rsa",
        r"\\0x7f.0.0.1\c$\Users\a\.ssh\id_rsa",
        r"\\0177.0.0.1\c$\Users\a\.ssh\id_rsa",
        r"\\[::1]\c$\Users\a\.ssh\id_rsa",
        r"\\0--1.ipv6-literal.net\c$\Users\a\.ssh\id_rsa",
        r"\\::ffff:127.0.0.1\c$\Users\a\.ssh\id_rsa",
        r"\\MYPC\c$\Users\a\.ssh\id_rsa",
        r"\\mypc.corp.example\c$\Users\a\.ssh\id_rsa",
        r"\\%COMPUTERNAME%\c$\Users\a\.ssh\id_rsa",
        r"\\?\UNC\localhost\c$\Users\a\.ssh\id_rsa",
        r"\\.\UNC\127.0.0.1\C$\Users\a\.ssh\id_rsa",
        r"FileSystem::C:\Users\a\.ssh\id_rsa",
        r"Microsoft.PowerShell.Core\FileSystem::C:\Users\a\.ssh\id_rsa",
        r"FileSystem::\\localhost\c$\Users\a\.ssh\id_rsa",
        r"C:\Users\a\.ssh\.\id_rsa",
        r"C:\Users\a\x\..\.ssh\id_rsa",
        r"C:\Users\a\x\.. \.ssh\id_rsa",
        r"C:\Users\a\x\..::$DATA\.ssh\id_rsa",
        r"C:\Users\a\.ssh\...\id_rsa",
        r"C:\..\..\Users\a\.ssh\id_rsa",
        r"C:\\Users\\a\\.ssh\\id_rsa",
        r"C:/Users\a//.ssh\id_rsa",
        r"C:\Users.\a \.ssh.\id_rsa. ",
        r"C:\Users\a\.ssh::$INDEX_ALLOCATION\id_rsa",
        r"C:\Users\a\.ssh\id_rsa::$DATA",
        r"C:\Users\a\.ssh\id_rsa:$DATA",
        r"C:\Users\a\.ssh\id_rsa:s:$DATA",
        r"C:\Users\a\.ssh\id_rsa. ::$DATA",
        r"..\Users\a\.ssh\id_rsa",
        r"\Users\a\.ssh\id_rsa",
        r"C:..\Users\a\.ssh\id_rsa",
    ];

    #[test]
    fn windows_spellings_canonicalize_alike() {
        for raw in ID_RSA_SPELLINGS {
            let got = c(raw).unwrap_or_else(|| panic!("{raw} has no form"));
            assert_eq!(fold(&got), fold(ID_RSA), "{raw} gave {got}");
        }
        want(r"C:\Users\a\.ssh\id_rsa", ID_RSA);
        // Case is preserved; only the drive letter is lowered.
        want("C:/USERS/a/.SSH/ID_RSA", "c:/USERS/a/.SSH/ID_RSA");
    }

    /// Every spelling, mutated the ways Win32 ignores, still lands on it.
    #[test]
    fn mutated_spellings_still_canonicalize_alike() {
        let mutations: &[fn(&str) -> String] = &[
            |s| s.to_ascii_uppercase(),
            |s| s.to_ascii_lowercase(),
            |s| format!("{s}."),
            |s| format!("{s} "),
            |s| format!("{s} . ."),
            |s| format!("{s}::$DATA"),
            |s| format!("{s}:zone.identifier"),
            |s| s.replace(".ssh", ".ssh."),
            |s| s.replace(".ssh", ".ssh "),
            |s| s.replace(".ssh", ".ssh::$INDEX_ALLOCATION"),
            |s| s.replace(r".ssh\", r".ssh\.\"),
            |s| s.replace(r".ssh\", r".ssh\\"),
            |s| s.replace(".ssh", r"x\..\.ssh"),
        ];
        for raw in ID_RSA_SPELLINGS {
            for (i, m) in mutations.iter().enumerate() {
                let spelled = m(raw);
                let got = c(&spelled).unwrap_or_else(|| panic!("#{i} {spelled} has no form"));
                assert_eq!(fold(&got), fold(ID_RSA), "#{i} {spelled} gave {got}");
            }
        }
    }

    #[test]
    fn ads_and_trailing_dots_stripped() {
        for raw in [
            ".env.",
            ".env..",
            ".env ",
            ".env  ",
            ".env. .",
            ".env::$DATA",
            ".env:$DATA",
            ".env:x",
            ".env:x:$DATA",
            ".env::$data",
            ".env. ::$DATA",
            ".env::$DATA.",
        ] {
            want(raw, "c:/p/.env");
            want(&format!(r"C:\q\{raw}"), "c:/q/.env");
        }
        // Inner and leading dots and spaces are part of the name.
        want(".env.local", "c:/p/.env.local");
        want(" .env", "c:/p/ .env");
    }

    #[test]
    fn localhost_admin_share_is_local() {
        want(r"\\localhost\c$\x", "c:/x");
        want(r"\\127.0.0.1\C$\x", "c:/x");
        want(r"\\?\UNC\localhost\c$\x", "c:/x");
        want(r"\\localhost\d$", "d:/");
        want(r"\\localhost\c$\..\..\x", "c:/x");
        want(r"\\localhost\ADMIN$\System32", "c:/Windows/System32");
        want(r"\\server\share\x", "//server/share/x");
        want(r"\\?\UNC\server\share\x", "//server/share/x");
        want(r"\\.\unc\server\share\x", "//server/share/x");
        want("//server/share/x", "//server/share/x");
        want(r"\\server\share", "//server/share");
        want(r"\\server", "//server");
        // A remote admin share is remote, and a local share that is not an
        // admin share cannot be mapped to a directory by its name.
        want(r"\\server\c$\x", "//server/c$/x");
        want(r"\\128.0.0.1\c$\x", "//128.0.0.1/c$/x");
        want(r"\\localhost\docs\x", "//localhost/docs/x");
        want(r"\\server\share\..\..\x", "//server/share/x");
        want(r"\\Server\Share.\x.", "//Server/Share/x");
    }

    #[test]
    fn git_bash_drive_paths() {
        want("/c/Users/a", "c:/Users/a");
        want("/cygdrive/c/Users/a", "c:/Users/a");
        want("/C/Users/a", "c:/Users/a");
        want("/d", "d:/");
        want("/cygdrive/d", "d:/");
        // A longer first component is a directory on the current drive.
        want("/etc/passwd", "c:/etc/passwd");
        want("/cygdrive", "c:/cygdrive");
        want("/mnt/data", "c:/mnt/data");
        // A backslash is Win32's: this is `c`, on the current drive.
        assert_eq!(
            canonical(r"\c\x", Some(Path::new(r"D:\p")), &vars()).as_deref(),
            Some("d:/c/x")
        );
        // `//c/x` is a share of the host `c`, in Git Bash too.
        want("//c/x/y", "//c/x/y");
    }

    #[test]
    fn relative_paths_join_cwd() {
        let cwd = Some(Path::new(r"C:\p"));
        assert_eq!(
            canonical(r"..\q\.env", cwd, &vars()).as_deref(),
            Some("c:/q/.env")
        );
        want(r"..\q\.env", "c:/q/.env");
        want(".env", "c:/p/.env");
        want(r".\x\..\.env", "c:/p/.env");
        want(r"..\..\..\.env", "c:/.env");
        want(r"$PWD\.env", "c:/p/.env");
        want(r"${PWD}\.env", "c:/p/.env");
        want(r"%CD%\.env", "c:/p/.env");
        want(r"~+\.env", "c:/p/.env");
        // An explicit working directory wins, a UNC one too.
        assert_eq!(
            canonical(".env", Some(Path::new(r"\\h\s\d")), &vars()).as_deref(),
            Some("//h/s/d/.env")
        );
        assert_eq!(
            canonical(r"\x", Some(Path::new(r"\\h\s\d")), &vars()).as_deref(),
            Some("//h/s/x")
        );
        // Drive-relative: known on the current drive only.
        want("C:.env", "c:/p/.env");
        want("c:", "c:/p");
        assert_eq!(c("D:.env"), None);
        // Nothing to anchor it.
        let bare = PathVars::new().with_style(PathStyle::Windows);
        for raw in [".env", r"\x", "/etc/x", "C:x", "$PWD/x"] {
            assert_eq!(canonical(raw, None, &bare), None, "{raw}");
        }
        assert_eq!(
            canonical(r"C:\x", Some(Path::new("relative")), &bare).as_deref(),
            Some("c:/x")
        );
        assert_eq!(canonical(".env", Some(Path::new("relative")), &bare), None);
    }

    #[test]
    fn env_var_spellings() {
        let want_dir = "c:/Users/a/AppData/Local/saiife";
        for raw in [
            r"$env:LOCALAPPDATA\saiife",
            r"%LOCALAPPDATA%\saiife",
            r"${env:LOCALAPPDATA}\saiife",
            r"$LOCALAPPDATA\saiife",
            r"${LOCALAPPDATA}/saiife",
            r"$ENV:localappdata/saiife",
            r"%LocalAppData%/saiife",
        ] {
            want(raw, want_dir);
        }
        for raw in [r"$env:APPDATA\x", r"%APPDATA%\x", r"${env:APPDATA}\x"] {
            want(raw, "c:/Users/a/AppData/Roaming/x");
        }
        for raw in [r"$env:TEMP\x", r"%TEMP%\x", r"%TMP%\x", r"$env:TMP\x"] {
            want(raw, "c:/Users/a/AppData/Local/Temp/x");
        }
        want("%LOCALAPPDATA%", "c:/Users/a/AppData/Local");
    }

    #[test]
    fn dollars_and_percents_that_are_names_stay_names() {
        want(r"C:\$Recycle.Bin\x", "c:/$Recycle.Bin/x");
        want(r"C:\$Windows.~BT\x", "c:/$Windows.~BT/x");
        want(r"C:\p\100%.txt", "c:/p/100%.txt");
        want(r"C:\p\a$", "c:/p/a$");
        want("~$doc.docx", "c:/p/~$doc.docx");
        want(r"C:\PROGRA~1\x", "c:/PROGRA~1/x");
    }

    /// What cannot be read gets no form at all: never a wrong one.
    #[test]
    fn unreadable_spellings_have_no_form() {
        for raw in [
            "",
            "a\0b",
            "a\nb",
            r"%NOPE%\.ssh\id_rsa",
            r"C:\Users\%NOPE%\.ssh\id_rsa",
            r"$env:NOPE\.ssh\id_rsa",
            r"C:\Users\$env:NOPE\.ssh",
            r"${env:NOPE}\.ssh\id_rsa",
            r"${NOPE}\.ssh\id_rsa",
            r"${HOME\.ssh\id_rsa",
            r"$NOPE\.ssh\id_rsa",
            r"$(whoami)\.ssh\id_rsa",
            r"C:\$(whoami)\.ssh\id_rsa",
            r"$env:\x",
            r"~-\.ssh\id_rsa",
            r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\Users\a\.ssh\id_rsa",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\Users\a",
            r"\\.\GLOBALROOT\Device\HarddiskVolume1\Users\a",
            r"\\.\PhysicalDrive0",
            r"\\.\pipe\x",
            r"\\?\C:x",
            r"\\?\\\?\C:\x",
            r"\\?",
            r"\\.",
            r"\\?\UNC",
            r"HKLM:\SOFTWARE\x",
            r"Env:\USERPROFILE",
            r"temp:\x",
            r"1:\x",
            r"é:\x",
            r"C:\Users\a\.ssh\id_rs<",
            r"C:\Users\a\.ssh\id_rs>",
            "C:\\Users\\a\\.ssh\\\"id_rsa\"",
            r"C:\x|y",
        ] {
            assert_eq!(c(raw), None, "{raw:?}");
        }
        // No profile known: `~` cannot be read either.
        let bare = PathVars::new()
            .with_style(PathStyle::Windows)
            .with_cwd(r"C:\p");
        for raw in ["~", r"~\x", "$HOME/x", "%USERPROFILE%", r"~a\x"] {
            assert_eq!(canonical(raw, None, &bare), None, "{raw}");
        }
    }

    #[test]
    fn canonical_text_canonicalizes_to_itself() {
        for raw in ID_RSA_SPELLINGS.iter().copied().chain([
            r"\\server\share\x",
            r"\\server\share",
            r"\\server",
            "c:",
            "/d",
        ]) {
            let once = c(raw).unwrap();
            assert_eq!(c(&once).as_deref(), Some(once.as_str()), "{raw}");
        }
    }

    /// Byte soup over the characters this parser cares about: it never
    /// panics (slicing at a non-boundary would), and a form is stable and
    /// always rooted.
    #[test]
    fn soup_never_panics_and_forms_are_stable() {
        let alphabet: Vec<&str> = vec![
            "\\",
            "/",
            ":",
            ".",
            " ",
            "$",
            "%",
            "~",
            "{",
            "}",
            "(",
            "?",
            "c",
            "C",
            "env:",
            "é",
            "Σ",
            "𝒳",
            "UNC",
            "localhost",
            "c$",
            "HOME",
            "..",
            "$DATA",
            "-",
            "0",
            "x",
        ];
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let v = vars();
        for _ in 0..50_000 {
            let len = next() % 9;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            if let Some(form) = canonical(&s, None, &v) {
                let rooted = form.starts_with("//")
                    || (form.as_bytes().get(1) == Some(&b':')
                        && form.as_bytes().get(2) == Some(&b'/'));
                assert!(rooted, "{s:?} gave {form:?}");
                assert!(!form.contains('\\'), "{s:?} gave {form:?}");
                assert_eq!(
                    canonical(&form, None, &v).as_deref(),
                    Some(form.as_str()),
                    "{s:?}"
                );
            }
        }
    }

    #[test]
    fn fold_compares_as_ntfs_does() {
        assert_eq!(fold("C:/Users/A/.SSH"), "c:/users/a/.ssh");
        // Greek sigma in any position and form.
        assert_eq!(fold("ΑΣ"), fold("ας"));
        assert_eq!(fold("ΑΣ"), fold("ασ"));
        assert_eq!(fold("ÅÄÖ"), "åäö");
        // No character grows: `ß` is not `ss`, and paths stay comparable.
        assert_eq!(fold("ß"), "ß");
        assert_ne!(fold("ß"), fold("ss"));
    }

    #[test]
    fn split_root_parts() {
        assert_eq!(split_root("c:/"), ("c:/", ""));
        assert_eq!(split_root("c:/x/y"), ("c:/", "x/y"));
        assert_eq!(split_root("//h"), ("//h", ""));
        assert_eq!(split_root("//h/s"), ("//h/s", ""));
        assert_eq!(split_root("//h/s/x/y"), ("//h/s/", "x/y"));
    }

    /// 8.3 names, junctions and symlinks are the OS's to resolve: a fake OS
    /// that knows `PROGRA~1` and `SSH~1`, answering as `fs::canonicalize` does.
    #[test]
    fn short_names_resolve_through_the_os() {
        let os = |p: &str| -> Option<String> {
            let fp = fold(p);
            match fp.as_str() {
                "c:/progra~1" => Some(r"\\?\C:\Program Files".to_string()),
                "c:/users/a/ssh~1" => Some(r"\\?\C:\Users\a\.ssh".to_string()),
                "c:/users/a/ssh~1/id_rsa" => Some(r"\\?\C:\Users\a\.ssh\id_rsa".to_string()),
                "c:/share-link/x" => Some(r"\\?\UNC\server\share\x".to_string()),
                "c:/" => Some(r"\\?\C:\".to_string()),
                _ => None,
            }
        };
        let v = vars();
        let r = |p: &str| resolved_with(p, &v, os);
        assert_eq!(r("c:/PROGRA~1"), "c:/Program Files");
        // The longest prefix that exists; a file not yet there keeps its name.
        assert_eq!(r("c:/PROGRA~1/new/file"), "c:/Program Files/new/file");
        assert_eq!(r("c:/Users/a/SSH~1/id_rsa"), ID_RSA);
        assert_eq!(r("c:/Users/a/SSH~1/new"), "c:/Users/a/.ssh/new");
        assert_eq!(r("c:/share-link/x/y"), "//server/share/x/y");
        assert_eq!(r("c:/"), "c:/");
        assert_eq!(r("c:/nothing/here"), "c:/nothing/here");
        // Nothing resolves at all: the lexical form stands.
        assert_eq!(resolved_with("d:/x/y", &v, |_| None), "d:/x/y");
        assert_eq!(resolved_with("//h/s/x", &v, |_| None), "//h/s/x");
        // An answer that cannot be read (`\\?\Volume{…}`) is no answer.
        let odd = |_: &str| Some(r"\\?\Volume{1}\x".to_string());
        assert_eq!(resolved_with("c:/x", &v, odd), "c:/x");
    }

    #[test]
    fn resolving_a_path_tries_a_bounded_number_of_prefixes() {
        let calls = std::cell::Cell::new(0);
        let deep = format!("c:/{}", vec!["d"; 500].join("/"));
        let v = vars();
        let out = resolved_with(&deep, &v, |_| {
            calls.set(calls.get() + 1);
            None
        });
        assert_eq!(out, deep);
        assert_eq!(calls.get(), RESOLVE_TRIES);
        let long = format!("c:/{}", "d".repeat(WIN_PATH_MAX));
        assert_eq!(
            resolved_with(&long, &v, |_| panic!("too long to exist")),
            long
        );
    }

    fn secrets_engine(v: PathVars) -> Engine {
        let (packs, warnings) = builtin_packs();
        assert!(warnings.is_empty(), "{warnings:?}");
        let secrets: Vec<_> = packs
            .into_iter()
            .filter(|p| p.id == "core.secrets")
            .collect();
        assert_eq!(secrets.len(), 1);
        Engine::new(secrets).with_paths(v)
    }

    #[test]
    fn secret_rule_matches_windows_profile() {
        let e = secrets_engine(vars());
        for raw in ID_RSA_SPELLINGS {
            assert!(e.evaluate_path(Access::Read, raw).is_deny(), "{raw}");
        }
        for raw in [
            ".env",
            ".ENV",
            ".env.",
            ".env ",
            ".env::$DATA",
            ".env:x",
            r"C:\p\.env",
            r"\\?\C:\p\.env",
            "/c/p/.env",
        ] {
            assert!(e.evaluate_path(Access::Read, raw).is_deny(), "{raw}");
        }
        // The reason names the path as it was resolved, its case intact.
        match e.evaluate_path(Access::Read, "C:/Users/A/.SSH/ID_RSA") {
            Decision::Deny { reason, .. } => {
                assert!(reason.contains("c:/Users/A/.SSH/ID_RSA"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
        for raw in [
            r"C:\p\README.md",
            r"C:\Users\b\notes.txt",
            r"\\server\share\x",
        ] {
            assert!(!e.evaluate_path(Access::Read, raw).is_deny(), "{raw}");
        }
    }

    const UNREADABLE: &[&str] = &[
        r"%NOPE%\.ssh\id_rsa",
        r"C:\Users\%NOPE%\.ssh\id_rsa",
        r"$env:NOPE\.ssh\id_rsa",
        r"${env:NOPE}\.ssh\id_rsa",
        r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\Users\a\.ssh\id_rsa",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\Users\a\.ssh\id_rsa",
        r"\\.\PhysicalDrive0",
        r"HKLM:\SOFTWARE\x",
        r"D:.env",
        r"C:\Users\a\.ssh\id_rs<",
    ];

    fn assert_unreadable_deny(d: &Decision, raw: &str) {
        match d {
            Decision::Deny { pack, reason, .. } => {
                assert_eq!(pack, "guard.winpath", "{raw}");
                assert!(reason.contains("cannot read the Windows path"), "{reason}");
            }
            other => panic!("{raw}: {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_spelling_is_denied_by_the_engine() {
        let e = secrets_engine(vars());
        for raw in UNREADABLE {
            let d = e.evaluate_path(Access::Read, raw);
            assert_unreadable_deny(&d, raw);
            assert_unreadable_deny(&e.evaluate_path(Access::Write, raw), raw);
        }
        // The reason says which path and why.
        match e.evaluate_path(Access::Read, r"%NOPE%\x") {
            Decision::Deny { reason, .. } => {
                assert!(reason.contains("%NOPE%"), "{reason}");
                assert!(reason.contains("no known value"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// A command, end to end: the lexer, `operands` and `judge_operands`.
    #[test]
    fn an_unreadable_shell_operand_is_denied() {
        let e = secrets_engine(vars());
        for raw in UNREADABLE {
            for cmd in [
                format!("cat '{raw}'"),
                format!("cp '{raw}' /c/p/out"),
                format!("cp /c/p/in '{raw}'"),
                format!("rm '{raw}'"),
                format!("echo hi > '{raw}'"),
                format!("git status; cat '{raw}'"),
            ] {
                assert_unreadable_deny(&e.evaluate(&cmd), &cmd);
            }
            // Escaped for the double quotes, so the inner shell sees `raw`.
            let escaped = raw.replace('\\', r"\\");
            let nested = format!("bash -c \"cat '{escaped}'\"");
            assert_unreadable_deny(&e.evaluate(&nested), &nested);
        }
        // A `cd` to where nothing can be judged would hide what follows.
        for cmd in [
            r"cd '\\?\Volume{1}\Users\a\.ssh' && cat id_rsa",
            r"pushd '%NOPE%' && cat id_rsa",
        ] {
            assert_unreadable_deny(&e.evaluate(cmd), cmd);
        }
        // Ordinary commands and odd but readable names stay allowed.
        for cmd in [
            "git status",
            "cat README.md",
            r"cat 'C:\p\100%.txt'",
            r"cat 'C:\$Recycle.Bin\x'",
            r"cd 'C:\q' && cat notes.txt",
            "cd - && cat notes.txt",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "{cmd}");
        }
    }

    /// With no path rule active nothing is protected: nothing to fail closed for.
    #[test]
    fn no_path_rules_means_no_unreadable_deny() {
        let e = Engine::new(Vec::new()).with_paths(vars());
        assert!(matches!(
            e.evaluate_path(Access::Read, r"%NOPE%\x"),
            Decision::Allow {
                trace: AllowTrace::Unjudgeable { .. }
            }
        ));
        assert!(!e.evaluate(r"cat '%NOPE%\x'").is_deny());
    }

    /// A relative path with no working directory is what POSIX style makes of
    /// it: `Unjudgeable` from a file tool, skipped in a command.
    #[test]
    fn relative_without_a_cwd_keeps_the_posix_behaviour() {
        let win = secrets_engine(
            PathVars::new()
                .with_style(PathStyle::Windows)
                .with_var("USERPROFILE", r"C:\Users\a"),
        );
        let posix = secrets_engine(
            PathVars::new()
                .with_style(PathStyle::Posix)
                .with_var("HOME", "/nonexistent-p19a/home"),
        );
        for raw in ["notes.txt", "x/notes.txt", ".env", "../x"] {
            let d = win.evaluate_path(Access::Read, raw);
            assert_eq!(
                d,
                Decision::Allow {
                    trace: AllowTrace::Unjudgeable {
                        reason: format!("cannot resolve {raw:?} to an absolute path"),
                    }
                },
                "{raw}"
            );
            if !cfg!(windows) {
                assert_eq!(posix.evaluate_path(Access::Read, raw), d, "{raw}");
            }
        }
        // Windows-only spellings that also need the working directory.
        for raw in [
            r"..\x", r"\x", "/etc/x", "C:x", r"$PWD\x", r"%CD%\x", r"~+\x",
        ] {
            assert!(
                matches!(
                    win.evaluate_path(Access::Read, raw),
                    Decision::Allow {
                        trace: AllowTrace::Unjudgeable { .. }
                    }
                ),
                "{raw}"
            );
        }
        for cmd in ["cat notes.txt", "cp notes.txt other.txt"] {
            let d = win.evaluate(cmd);
            assert_eq!(
                d,
                Decision::Allow {
                    trace: AllowTrace::NoMatch
                },
                "{cmd}"
            );
            if !cfg!(windows) {
                assert_eq!(posix.evaluate(cmd), d, "{cmd}");
            }
        }
        // What cannot be read is denied with or without a working directory.
        for raw in [r"%NOPE%\x", r"\\?\Volume{1}\x"] {
            assert_unreadable_deny(&win.evaluate_path(Access::Read, raw), raw);
            let cmd = format!("cat '{raw}'");
            assert_unreadable_deny(&win.evaluate(&cmd), raw);
        }
    }

    /// The same text under POSIX is an ordinary file name.
    #[test]
    fn posix_style_does_not_deny_the_same_text() {
        if cfg!(windows) {
            return;
        }
        let e = secrets_engine(
            PathVars::new()
                .with_style(PathStyle::Posix)
                .with_cwd("/nonexistent-p19a/p")
                .with_var("HOME", "/nonexistent-p19a/home"),
        );
        let clean = Decision::Allow {
            trace: AllowTrace::NoMatch,
        };
        for raw in UNREADABLE {
            assert_eq!(e.evaluate_path(Access::Read, raw), clean, "{raw}");
            assert_eq!(e.evaluate(&format!("cat '{raw}'")), clean, "{raw}");
        }
        assert_eq!(e.evaluate(r"cd '%NOPE%' && cat notes.txt"), clean);
    }

    const MIXED_CASE_PACK: &str = r#"
[pack]
id = "test.mixed"

[[deny_path]]
glob = "**/Secrets/TOKEN.*"
access = "read"
reason = "token"

[[allow_path]]
glob = "**/Secrets/TOKEN.Example"
access = "read"
reason = "template"

[[deny_path]]
glob = "~/MyKeys/**"
access = "any"
reason = "keys"

[[deny_path]]
glob = "**/ΑΣ/Å.txt"
access = "read"
reason = "non-ASCII"

[[deny_path]]
glob = "$SAIIFE_DATA_DIR/Audit"
access = "write"
reason = "data dir"
ancestors = true
"#;

    /// The engine never folds the path it judges: the folded glob and the
    /// regex's `(?i)` must cover every matcher between them, in any case mix
    /// on either side.
    #[test]
    fn mixed_case_rules_match_any_case() {
        let mut w = Vec::new();
        let pack = load_pack_str("<t>", MIXED_CASE_PACK, &mut w).unwrap();
        assert!(w.is_empty(), "{w:?}");
        let e = Engine::new(vec![pack])
            .with_paths(vars().with_var("SAIIFE_DATA_DIR", r"C:\Users\a\AppData\Local\Saiife"));
        for raw in [
            r"C:\p\Secrets\TOKEN.txt",
            r"C:\p\secrets\token.txt",
            r"C:\P\SECRETS\TOKEN.TXT",
            r"c:\p\sEcReTs\tOkEn.TxT",
            r"secrets\token.txt",
            r"~\mykeys\a",
            r"~\MYKEYS",
            r"C:\USERS\A\mykeys\a",
            r"c:\p\ασ\å.txt",
            r"c:\p\ας\Å.TXT",
            r"c:\p\ΑΣ\å.txt",
        ] {
            assert!(e.evaluate_path(Access::Read, raw).is_deny(), "{raw}");
        }
        // The allow rule carves out in any case too.
        for raw in [r"C:\p\Secrets\TOKEN.Example", r"c:\p\secrets\token.example"] {
            assert!(
                matches!(
                    e.evaluate_path(Access::Read, raw),
                    Decision::Allow {
                        trace: AllowTrace::AllowRule { .. }
                    }
                ),
                "{raw}"
            );
        }
        // Ancestor rules: removing a directory above the data dir.
        for raw in [
            r"C:\",
            r"c:\users",
            r"C:\USERS\A\APPDATA\LOCAL",
            r"C:\Users\a\AppData\Local\saiife",
        ] {
            assert!(e.evaluate_path(Access::Write, raw).is_deny(), "{raw}");
        }
        assert!(!e.evaluate_path(Access::Write, r"c:\users\b").is_deny());
        // And through a command.
        assert!(e.evaluate(r"cat 'C:\P\SECRETS\token.txt'").is_deny());
        assert!(e.evaluate(r"rm -rf 'C:\USERS\A\APPDATA'").is_deny());
        assert!(!e.evaluate(r"cat 'C:\P\notes.txt'").is_deny());
    }

    /// POSIX stays case-sensitive on the same rules (off macOS, which folds).
    #[test]
    fn mixed_case_rules_stay_exact_under_posix() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let mut w = Vec::new();
        let pack = load_pack_str("<t>", MIXED_CASE_PACK, &mut w).unwrap();
        let e = Engine::new(vec![pack]).with_paths(
            PathVars::new()
                .with_style(PathStyle::Posix)
                .with_cwd("/nonexistent-p19a/p"),
        );
        assert!(e.evaluate_path(Access::Read, "Secrets/TOKEN.txt").is_deny());
        assert!(!e.evaluate_path(Access::Read, "secrets/token.txt").is_deny());
    }

    #[test]
    fn path_forms_hold_one_lexical_form_off_windows() {
        if cfg!(windows) {
            return;
        }
        let v = vars();
        assert_eq!(
            path_forms(r"~\.ssh\id_rsa", None, &v),
            vec![std::path::PathBuf::from(ID_RSA)]
        );
        assert!(path_forms(r"%NOPE%\x", None, &v).is_empty());
    }
}
