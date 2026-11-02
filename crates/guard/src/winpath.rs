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
//! - `Unread::Unreadable`: an unknown variable, a cmd substring or replace
//!   (`%VAR:~0%`), a device namespace path (`\\?\Volume{…}`,
//!   `\\.\PhysicalDrive0`) or a `..` after a device prefix, Git Bash's `/proc`
//!   and `/dev/fd`, a `..` above the root of a path spelled with `/`, a relative
//!   path into a Git Bash mount (`c/Users` from `/`), a
//!   PowerShell drive (`HKLM:\`, `HKLM:x`, `Registry::HKLM\x`, `temp:\`), a drive
//!   or `admin$` share on a host
//!   not known to be this machine, a wildcard under a UNC root (it is never
//!   expanded), a component of only dots, spaces or a stream (only exact `.`
//!   and `..` navigate), or a character Win32 refuses or reads as a wildcard
//!   (`<`, `>`, `"`, `|`, control characters). It could name anything, so the
//!   engine denies it.
//! - `Unread::NoAnchor`: an empty path, or a relative one with no working
//!   directory known. The engine treats it as it does in POSIX style.
//!
//! A command on a provider drive touches no file, so a shell's words get a
//! verdict of their own: `provider_access`. A file tool has no provider.
//!
//! A shell's word is more than its text: `path_words` makes a word whose value
//! the shell decides (`./$x`, `$(x)`) read as the variable it is. That is what
//! a command's paths go through; a file tool's path has no shell in front of it.
//!
//! Not lexically knowable, and left to `resolved` when the path exists: 8.3
//! short names (`PROGRA~1`), junctions and symlinks. A UNC path stays lexical:
//! asking the OS would call a host the command chose.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::canon::{PathStyle, PathVars};
use crate::lexer::Word;

/// The variable holding this machine's name (not a path).
pub const COMPUTER_NAME: &str = "COMPUTERNAME";
/// What `\\.\NUL` and `NUL:` canonicalize to: it names no file.
const NULL_DEVICE: &str = "//./NUL";

/// Why a spelling has no canonical form (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unread {
    /// Empty, or relative with no working directory known.
    NoAnchor,
    /// It could name anything: the text says what it is.
    Unreadable(&'static str),
}

/// A PowerShell provider path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider<'a> {
    Hklm(&'a str),
    Hkcu(&'a str),
    Cert,
    Env(&'a str),
    /// `Env:` and friends: a drive by that name, whatever follows it.
    Named {
        slash: bool,
    },
    /// `foo:\x`: a drive by shape, and nothing is known about it.
    Unknown,
}

/// `t` (`/` separated) as a provider path, or `None` when it is not one. A name
/// alone does not make a drive: `test:unit`, `nginx:latest` and `foo::bar` are in
/// ordinary commands, and `.env:s` is a stream. So after the colon a slash is
/// needed, unless the name is one PowerShell gives a provider; a `::` needs the
/// provider's name and, for the registry, a hive.
fn provider_path(t: &str) -> Option<Provider<'_>> {
    let t = strip_ci(t, "microsoft.powershell.core/").unwrap_or(t);
    if let Some(rest) = strip_ci(t, "registry::") {
        let (hive, tail) = split_seg(rest.trim_start_matches('/'));
        return match hive.to_ascii_lowercase().as_str() {
            "hklm" | "hkey_local_machine" => Some(Provider::Hklm(tail)),
            "hkcu" | "hkey_current_user" => Some(Provider::Hkcu(tail)),
            h if h.starts_with("hk") => Some(Provider::Unknown),
            _ => None,
        };
    }
    if let Some(rest) = strip_ci(t, "environment::") {
        return Some(Provider::Env(rest.trim_start_matches('/')));
    }
    if strip_ci(t, "certificate::").is_some() {
        return Some(Provider::Cert);
    }
    let (name, rest) = t.split_once(':')?;
    let plain = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if name.len() < 2 || !plain || rest.starts_with(':') {
        return None;
    }
    let slash = rest.is_empty() || rest.starts_with('/');
    let tail = rest.trim_start_matches('/');
    match name.to_ascii_lowercase().as_str() {
        "hklm" => Some(Provider::Hklm(tail)),
        "hkcu" => Some(Provider::Hkcu(tail)),
        "cert" => Some(Provider::Cert),
        "env" => Some(Provider::Env(tail)),
        "temp" | "function" | "variable" | "alias" | "wsman" => Some(Provider::Named { slash }),
        _ => slash.then_some(Provider::Unknown),
    }
}

/// What a command may do on a provider drive (`raw`, as a shell's word). `None`:
/// no verdict, because it is no provider path, or nothing is known about the
/// drive, and `read` says what it says.
///
/// - `HKCU:` and `HKLM:` read; `HKLM:\SAM` and `HKLM:\SECURITY` hold secrets.
/// - `HKCU:` writes, but for `Environment`: every later program starts with it.
/// - `HKLM:` and `Cert:` writes change the machine, so they are denied.
/// - `Env:` reads. Writes are this process's, but for `SAIIFE_*`, and a wildcard
///   or the whole drive may reach it.
pub fn provider_access(raw: &str, write: bool) -> Option<Result<(), &'static str>> {
    let t = raw.replace('\\', "/");
    let first = |tail: &'_ str| split_seg(tail).0.to_ascii_lowercase();
    match provider_path(&t)? {
        Provider::Hklm(tail) if matches!(first(tail).as_str(), "sam" | "security") => {
            Some(Err("the registry hives that hold secrets"))
        }
        Provider::Hklm(_) if write => Some(Err("a write to HKLM")),
        Provider::Hkcu(tail) if write && first(tail) == "environment" => {
            Some(Err("a write to the environment later programs start with"))
        }
        Provider::Hklm(_) | Provider::Hkcu(_) => Some(Ok(())),
        Provider::Cert if write => Some(Err("a write to the certificate store")),
        Provider::Cert => Some(Ok(())),
        Provider::Env(tail) if write => {
            let name = tail.to_ascii_lowercase();
            let reaches =
                name.is_empty() || name.starts_with("saiife_") || name.contains(['*', '?', '[']);
            if reaches {
                Some(Err("a write to saiife's own environment"))
            } else {
                Some(Ok(()))
            }
        }
        Provider::Env(_) => Some(Ok(())),
        Provider::Named { slash: false } if write => Some(Err("a write to a PowerShell drive")),
        Provider::Named { .. } | Provider::Unknown => None,
    }
}

/// A provider path a command can change without running anything later: the
/// registry, the certificate store, the environment. `Function:` and `Alias:`
/// make commands.
pub fn is_data_provider(raw: &str) -> bool {
    let t = raw.replace('\\', "/");
    matches!(
        provider_path(&t),
        Some(Provider::Hklm(_) | Provider::Hkcu(_) | Provider::Cert | Provider::Env(_))
    )
}

/// The name of the variable `raw` writes on `Env:`, if that is what it is.
pub fn provider_env_name(raw: &str) -> Option<String> {
    let t = raw.replace('\\', "/");
    match provider_path(&t) {
        Some(Provider::Env(tail)) if !tail.is_empty() => Some(tail.to_string()),
        _ => None,
    }
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
    // A UNC path is a call to a host the command chose: SMB can stall past
    // the budget, which fails open, and it sends NTLM to that host.
    if canon.len() > WIN_PATH_MAX || canon.starts_with("//") {
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
/// that does not open a variable (`100%.txt`, `%%`) is itself. cmd also
/// expands `%VAR:~0%`, `%VAR:a=b%` (separators in them included) and `%=C:%`:
/// what those produce is not worked out here.
fn percent_var(s: &str, cwd: Option<&str>, vars: &PathVars) -> Result<(String, usize), Unread> {
    let name = s[1..].find('%').map(|end| &s[1..1 + end]);
    match name {
        Some(n)
            if n.split_once(':')
                .is_some_and(|(v, _)| !v.contains(['/', '\\'])) =>
        {
            Err(Unread::Unreadable(
                "a cmd variable with a colon, such as a substring or replace",
            ))
        }
        Some(n) if !n.is_empty() && !n.contains(['/', '\\', ':']) => {
            Ok((var(n, cwd, vars)?, n.len() + 2))
        }
        _ => Ok(("%".to_string(), 1)),
    }
}

/// The length of the identifier at the start of `t`: 0 when there is none.
fn identifier_len(t: &str) -> usize {
    if t.starts_with(|c: char| c.is_ascii_digit()) {
        return 0;
    }
    t.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(t.len())
}

/// A command's words as the path rules read them. On Windows a word whose
/// value the shell decides reads as what it is, a variable with no known value
/// or a substitution, so `read` calls it unreadable: every position a path is
/// read from (operands, redirections, `cd`, a wrapper's files) denies alike.
/// Unchanged in POSIX style, and for a file tool's path, which no shell expands.
pub(crate) fn path_words<'a>(words: &'a [Word], vars: &PathVars) -> Cow<'a, [Word]> {
    if vars.style() != PathStyle::Windows {
        return Cow::Borrowed(words);
    }
    Cow::Owned(words.iter().map(|w| path_word(w, vars)).collect())
}

fn path_word(w: &Word, vars: &PathVars) -> Word {
    let mut text = if w.literal_dollars {
        w.text.clone()
    } else {
        brace_unknown_parameters(&w.text, vars)
    };
    if w.has_substitution && !text.contains("$(") {
        text.insert_str(text.find('`').unwrap_or(0), "$(");
    }
    Word {
        text,
        has_substitution: false,
        ..w.clone()
    }
}

/// `raw` with each parameter that has no known value in the `${name}` form
/// `read` never takes for a name: `./$x` looks like a directory called `$x`.
/// A `$` that opens nothing stays (`c$/`, `admin$`), as does what `read` has its
/// own answer for (`$env:X`, `${x}`, `$(x)`). Bash's special parameters count,
/// since `$1`, `$@` and `$*` hold whatever a caller passed.
fn brace_unknown_parameters(raw: &str, vars: &PathVars) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let n = if after.starts_with(|c: char| c.is_ascii_digit() || "@*#?-$!".contains(c)) {
            1
        } else if strip_ci(after, "env:").is_some() {
            0
        } else {
            let n = identifier_len(after);
            if lookup(&after[..n], None, vars).is_some() {
                0
            } else {
                n
            }
        };
        if n == 0 {
            out.push('$');
        } else {
            out.push_str("${");
            out.push_str(&after[..n]);
            out.push('}');
        }
        rest = &after[n..];
    }
    out.push_str(rest);
    out
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
    if let Some(env) = strip_ci(after, "env:") {
        let n = env
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(env.len());
        if n == 0 {
            return Err(Unread::Unreadable("a `$env:` with no name"));
        }
        return Ok((var(&env[..n], cwd, vars)?, "$env:".len() + n));
    }
    let n = identifier_len(after);
    if n == 0 {
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
    let is_unc = t.starts_with("//") && !t.starts_with("///");
    let device_ns = ["//?/", "//./"]
        .iter()
        .find_map(|p| t.strip_prefix(p))
        // `/??/x` written with slashes is a glob, not the NT namespace.
        .or_else(|| t.strip_prefix("/??/").filter(|_| s.starts_with('\\')));
    // Spelled with `/` it may be Git Bash's: `..` cannot climb past a root it
    // would stop at, and `/proc` is the process table on every drive. With a
    // `\` it is Win32's: `..` stops at the root, and `\proc` is a directory.
    let slash_spelled = !is_unc && device_ns.is_none() && (s.starts_with('/') || !s.contains('\\'));
    let (root, rest): (String, String) = if let Some(after) = device_ns {
        // After `\\.\` a `..` can pop the drive itself.
        if after.split('/').any(|c| c == "..") {
            return Err(Unread::Unreadable("a `..` after a device prefix"));
        }
        device(after, vars)?
    } else if is_unc {
        unc(&t[2..], vars)?
    } else if let Some(body) = t.strip_prefix('/') {
        if s.starts_with('/') {
            // `.` and `..` first, or `/./proc` and `/c/../c` pass the checks.
            let body = normalize_rooted(body)?;
            if is_git_bash_virtual(&body) {
                return Err(Unread::Unreadable("Git Bash's /proc or /dev/fd"));
            }
            match git_bash_drive(&body) {
                Some((drive, tail)) => (format!("{drive}:/"), tail.to_string()),
                None => (cwd_root()?.0.to_string(), body),
            }
        } else {
            // A leading backslash is Win32's "root of this drive".
            (cwd_root()?.0.to_string(), body.to_string())
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
        if t.eq_ignore_ascii_case("NUL:") {
            return Ok(NULL_DEVICE.to_string());
        }
        // `temp:x` read as a file is what it was before: a stream of `temp`.
        let is_ps_drive = provider_path(&t).is_some_and(|p| p != Provider::Named { slash: false });
        if is_ps_drive {
            return Err(Unread::Unreadable("a PowerShell drive"));
        }
        let (root, base) = cwd_root()?;
        (root.to_string(), format!("{base}/{t}"))
    };
    let out = assemble(&root, &rest, slash_spelled)?;
    if slash_spelled && is_git_bash_virtual(split_root(&out).1) {
        return Err(Unread::Unreadable("Git Bash's /proc or /dev/fd"));
    }
    let relative = slash_spelled && !s.starts_with('/') && t.chars().nth(1) != Some(':');
    if relative && enters_git_bash_mount(&out, cwd) {
        return Err(Unread::Unreadable("a relative path into a Git Bash mount"));
    }
    // Never expanded (`canon` will not list a host's share), so its literal
    // text would match no rule: `.en*` misses `**/.env`.
    if out.starts_with("//") && out.contains(['*', '?', '[']) {
        return Err(Unread::Unreadable("a wildcard under a UNC path"));
    }
    Ok(out)
}

/// `body` (no leading slash) with exact `.` and `..` applied. `..` above the
/// root is an error: Git Bash's root is not the drive's.
fn normalize_rooted(body: &str) -> Result<String, Unread> {
    let mut comps: Vec<&str> = Vec::new();
    for c in body.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                comps
                    .pop()
                    .ok_or(Unread::Unreadable("a `..` above the root"))?;
            }
            _ => comps.push(c),
        }
    }
    Ok(comps.join("/"))
}

/// `body` (no leading slash) is under Git Bash's process table or its file
/// descriptors, which are no directories on a drive. `proc/cygdrive` is a
/// drive path.
fn is_git_bash_virtual(body: &str) -> bool {
    body.eq_ignore_ascii_case("proc")
        || body.eq_ignore_ascii_case("dev/fd")
        || strip_ci(body, "dev/fd/").is_some()
        || (strip_ci(body, "proc/").is_some() && strip_ci(body, "proc/cygdrive/").is_none())
}

/// `out`, a relative path made absolute, may be a drive that Git Bash mounts:
/// `c/Users` from `/`, `c/Users` from `/cygdrive`. A one-letter directory the
/// working directory is already in is a directory (`D:\a\repo`).
fn enters_git_bash_mount(out: &str, cwd: Option<&str>) -> bool {
    if out.starts_with("//") {
        return false;
    }
    let body = split_root(out).1;
    if git_bash_drive(body).is_none() {
        return false;
    }
    let first = split_seg(body).0;
    let is_mount_dir = drive_letter(component_name(first)).is_none();
    is_mount_dir || !cwd.is_some_and(|c| split_seg(split_root(c).1).0.eq_ignore_ascii_case(first))
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
fn device(after: &str, vars: &PathVars) -> Result<(String, String), Unread> {
    let (seg, tail) = split_seg(after);
    if seg.eq_ignore_ascii_case("UNC") {
        return unc(tail, vars);
    }
    if seg.eq_ignore_ascii_case("NUL") && tail.is_empty() {
        return Ok((NULL_DEVICE.to_string(), String::new()));
    }
    let drive = seg
        .strip_suffix(':')
        .and_then(drive_letter)
        .ok_or(Unread::Unreadable("a device namespace path"))?;
    Ok((format!("{drive}:/"), tail.to_string()))
}

/// After `\\`: `host/share/rest`. An admin share of this machine is what it
/// shares. On any other host it could still be this machine's (`\\<own-IP>\c$`
/// cannot be told from a remote host's), so it is not read. Any other share is
/// judged by its own name.
fn unc(after: &str, vars: &PathVars) -> Result<(String, String), Unread> {
    let (host, tail) = split_seg(after);
    let host = host.trim_end_matches(['.', ' ']);
    if host.is_empty() || host == "?" {
        return Err(Unread::Unreadable("a UNC path with no usable host"));
    }
    let (spelled, tail) = split_seg(tail.trim_start_matches('/'));
    if spelled.is_empty() {
        return Ok((format!("//{host}"), String::new()));
    }
    let share = component_name(spelled);
    if share.is_empty() {
        return Err(Unread::Unreadable("a UNC share of only dots or spaces"));
    }
    let drive = share.strip_suffix('$').and_then(drive_letter);
    let admin = share.eq_ignore_ascii_case("admin$");
    if !is_local_host(host, vars) {
        if drive.is_some() || admin {
            return Err(Unread::Unreadable(
                "an admin share on a host not known to be this machine",
            ));
        }
    } else if let Some(drive) = drive {
        return Ok((format!("{drive}:/"), tail.to_string()));
    } else if admin {
        let windows = var("SYSTEMROOT", None, vars)?;
        let (root, base) = split_root(&windows);
        return Ok((root.to_string(), format!("{base}/{tail}")));
    }
    Ok((format!("//{host}/{share}"), tail.to_string()))
}

/// A component without its stream suffix and trailing dots and spaces. A
/// component of only dots, spaces or a stream comes back empty.
fn component_name(c: &str) -> &str {
    c.split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches(['.', ' '])
}

/// `root` and the normalized components of `rest`. `..` stops at the root, or
/// is an error there when `strict`. Only exact `.` and `..` navigate: what
/// `...`, `.. ` or `..::$DATA` do depends on where they stand and on the API,
/// so they are not read.
fn assemble(root: &str, rest: &str, strict: bool) -> Result<String, Unread> {
    let mut comps: Vec<&str> = Vec::new();
    for c in rest.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if comps.pop().is_none() && strict {
                    return Err(Unread::Unreadable("a `..` above the root"));
                }
            }
            _ => {
                let name = component_name(c);
                if name.is_empty() {
                    return Err(Unread::Unreadable(
                        "a path component of only dots, spaces or a stream",
                    ));
                }
                comps.push(name);
            }
        }
    }
    let root = root.trim_end_matches('/');
    Ok(if !comps.is_empty() {
        format!("{root}/{}", comps.join("/"))
    } else if root.starts_with("//") {
        root.to_string()
    } else {
        format!("{root}/")
    })
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
    use crate::builtins::builtin_packs_for;
    use crate::canon::path_forms;
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
                // A `..` after a device prefix is unreadable on purpose.
                if spelled.contains(r"x\..\")
                    && [r"\\?\", r"\\.\", r"\??\", "//?/"]
                        .iter()
                        .any(|p| spelled.starts_with(p))
                {
                    assert_eq!(c(&spelled), None, "#{i} {spelled}");
                    continue;
                }
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
        // A local share that is not an admin share cannot be mapped to a
        // directory by its name.
        want(r"\\localhost\docs\x", "//localhost/docs/x");
        want(r"\\server\ipc$", "//server/ipc$");
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
        let (packs, warnings) = builtin_packs_for(v.style());
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
        // A shell's word on a known provider drive has its own verdict
        // (`provider_access`); a drive nothing is known about is unreadable.
        let shell = UNREADABLE
            .iter()
            .filter(|raw| !raw.starts_with("HKLM:"))
            .chain(&[r"Foo:\SOFTWARE\x"]);
        for raw in shell {
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

    fn unreadable(raw: &str) {
        assert!(
            matches!(read(raw, None, &vars()), Err(Unread::Unreadable(_))),
            "{raw}: {:?}",
            read(raw, None, &vars())
        );
    }

    /// `build_argv` collapses leading slashes for the pack regexes; the path
    /// rules must see what was written: `//host` is not `/host`.
    #[test]
    fn leading_slashes_reach_the_path_rules_uncollapsed() {
        let e = secrets_engine(vars());
        for cmd in [
            "cat //localhost/c$/Users/a/.claude/.credentials.json",
            "cat //./C:/Users/a/.claude/.credentials.json",
            "cat '//?/C:/Users/a/.ssh/id_rsa'",
            "cp //localhost/c$/Users/a/.ssh/id_rsa /c/p/x",
            "xargs -a //localhost/c$/Users/a/.ssh/id_rsa echo",
            "cd //localhost/c$/Users/a/.ssh && cat id_rsa",
            r"cd '\\localhost\c$\Users\a\.ssh' && cat id_rsa",
            r"cd '$env:USERPROFILE\.ssh' && cat id_rsa",
            r"cd '%USERPROFILE%\.ssh' && cat id_rsa",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "{cmd}");
        }
        for cmd in [
            "cat '//?/GLOBALROOT/Device/HarddiskVolume1/Users/a/.ssh/id_rsa'",
            "cat //./PhysicalDrive0",
            "cd '//?/GLOBALROOT/Device/HarddiskVolume1/Users/a/.ssh' && cat id_rsa",
            "cd //./PhysicalDrive0",
        ] {
            assert_unreadable_deny(&e.evaluate(cmd), cmd);
        }
        // Single-quoted, a `$` is a name: the directory is known.
        assert_eq!(
            e.evaluate(r"cd 'C:\$Recycle.Bin' && cat notes.txt"),
            Decision::Allow {
                trace: AllowTrace::NoMatch
            }
        );
        // The pack regexes keep the collapsed line.
        let (packs, _) = builtin_packs_for(PathStyle::Windows);
        let fs: Vec<_> = packs
            .into_iter()
            .filter(|p| p.id == "core.filesystem")
            .collect();
        let e = Engine::new(fs).with_paths(vars());
        assert!(e.evaluate("rm -rf //").is_deny());
    }

    /// Only exact `.` and `..` navigate: Win32's handling of `...`, `.. ` and
    /// `..::$DATA` is not one a text rule can stand behind.
    #[test]
    fn dot_only_components_do_not_navigate() {
        want(
            r"~\x\..\.claude\.credentials.json",
            "c:/Users/a/.claude/.credentials.json",
        );
        want(r"C:\a\.\b\..\c", "c:/a/c");
        for raw in [
            r"~\...\..\.claude\.credentials.json",
            r"C:\Users\a\.ssh\...\id_rsa",
            r"C:\Users\a\b\.. \..\a\.claude\.credentials.json",
            r"C:\Users\a\b\..::$DATA\..\a\.claude\.credentials.json",
            r"C:\Users\a\x\.. \.ssh\id_rsa",
            r"C:\Users\a\x\. \.ssh\id_rsa",
            r"C:\Users\a\x\.:s\.ssh\id_rsa",
            r"C:\Users\a\ \.ssh\id_rsa",
            r"C:\Users\a\:s\.ssh\id_rsa",
            r"...\x",
            r"C:\p\...",
        ] {
            unreadable(raw);
        }
        let e = secrets_engine(vars());
        let raw = r"~\...\..\.claude\.credentials.json";
        assert_unreadable_deny(&e.evaluate_path(Access::Read, raw), raw);
    }

    #[test]
    fn dot_dot_after_a_device_prefix_is_unreadable() {
        for raw in [
            r"\\.\C:\..\C:\Users\a\.claude\.credentials.json",
            "//./C:/../C:/Users/a/.claude/.credentials.json",
            r"\\?\C:\..\C:\Users\a\.ssh\id_rsa",
            r"\??\C:\x\..\y",
            r"\\.\UNC\localhost\c$\..\x",
        ] {
            unreadable(raw);
        }
        want(r"\\.\C:\x\.\y", "c:/x/y");
    }

    /// cmd expands `%VAR:~0%` and `%VAR:a=b%`, separators in them included.
    #[test]
    fn cmd_substring_and_replace_are_unreadable() {
        for raw in [
            r"%USERPROFILE:~0%\.claude\.credentials.json",
            r"%USERPROFILE:a=a%\.claude\.credentials.json",
            r"%USERPROFILE:\=\%\.claude\.credentials.json",
            r"%USERPROFILE:/=/%\.claude\.credentials.json",
            r"C:\Users\%USERNAME:~0%\.ssh\id_rsa",
            r"%NOPE:~0%\x",
        ] {
            unreadable(raw);
        }
        want(r"C:\p\100%.txt", "c:/p/100%.txt");
        want(r"C:\a%b\c%d", "c:/a%b/c%d");
        want(".env:a%", "c:/p/.env");
    }

    /// `/proc` in Git Bash is the process table, not a directory on the drive.
    #[test]
    fn git_bash_proc_is_unreadable() {
        for raw in [
            "/proc",
            "/proc/self/environ",
            "/proc/1234/environ",
            "/PROC/self/environ",
            "/proc/self/cwd/.claude/.credentials.json",
            "///proc/self/environ",
            "/proc/cygdrive",
        ] {
            unreadable(raw);
        }
        want("/proc/cygdrive/c/x", "c:/x");
        want(r"\proc\x", "c:/proc/x");
        want("/process/x", "c:/process/x");
        let e = secrets_engine(vars());
        for cmd in ["cat /proc/self/environ", "cat /proc/self/cwd/.env"] {
            assert_unreadable_deny(&e.evaluate(cmd), cmd);
        }
        for cmd in [
            "echo hi > /dev/null",
            "cat /etc/hosts",
            "git status 2> /dev/null",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "{cmd}");
        }
    }

    /// The guard never calls the OS on a host a command names: SMB can stall
    /// past the budget (a fail-open) and sends NTLM to that host.
    #[test]
    fn unc_paths_never_reach_the_os() {
        let v = vars();
        let never = |p: &str| -> Option<String> { panic!("asked the OS about {p}") };
        for p in ["//10.255.255.1/s/f", "//h/s", "//h"] {
            assert_eq!(resolved_with(p, &v, never), p);
        }
        // A local path still does.
        let local = |_: &str| Some(r"\\?\C:\Program Files".to_string());
        assert_eq!(resolved_with("c:/PROGRA~1", &v, local), "c:/Program Files");
    }

    /// Copy targets and sources: `is_dir` and `read_dir` on a UNC path are
    /// calls to that host. `//…` is a real local path to a POSIX test host,
    /// so an OS call shows up as a verdict.
    #[cfg(unix)]
    #[test]
    fn copies_do_not_list_or_probe_unc_paths() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::create_dir(root.join("source")).unwrap();
        std::fs::write(root.join("source/entry.txt"), "").unwrap();
        let toml = r#"
[pack]
id = "test.landing"

[[deny_path]]
glob = "**/target/marker.txt"
access = "write"
reason = "reached only by asking the OS that target is a directory"

[[deny_path]]
glob = "**/landed/entry.txt"
access = "write"
reason = "reached only by listing the source"
"#;
        let mut w = Vec::new();
        let pack = load_pack_str("<t>", toml, &mut w).unwrap();
        let e = Engine::new(vec![pack]).with_paths(vars());
        let target = format!("/{}/target", root.display());
        let source = format!("/{}/source", root.display());
        assert!(target.starts_with("//"));
        let probe = format!("cp marker.txt '{target}'");
        assert!(!e.evaluate(&probe).is_deny(), "{probe}");
        let list = format!("cp -rT '{source}' 'C:\\p\\landed'");
        assert!(!e.evaluate(&list).is_deny(), "{list}");
    }

    /// `/x` is on whichever drive the shell is on, and a `cd` may have moved it.
    #[test]
    fn rooted_paths_are_judged_against_every_cwd() {
        let e = secrets_engine(
            PathVars::new()
                .with_style(PathStyle::Windows)
                .with_cwd(r"D:\p")
                .with_var("USERPROFILE", r"C:\Users\a"),
        );
        for cmd in [
            r"cd 'C:\'; cat /Users/a/.claude/.credentials.json",
            r"cd 'C:\'; cat '\Users\a\.ssh\id_rsa'",
            r"cd 'C:\p'; cat '~+\.env'",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "{cmd}");
        }
        assert!(!e
            .evaluate("cat /Users/a/.claude/.credentials.json")
            .is_deny());
    }

    #[test]
    fn a_unc_share_that_is_only_dots_is_unreadable() {
        for raw in [
            r"\\host\.\.ssh\id_rsa",
            r"\\host\..\x",
            r"\\host\ \x",
            r"\\host\...\x",
        ] {
            unreadable(raw);
        }
        want(r"\\host\", "//host");
    }

    /// `\\<own-IP>\c$` cannot be told from a remote host's: an admin share on
    /// any host not known to be this machine could be this machine's.
    #[test]
    fn admin_shares_on_unknown_hosts_are_unreadable() {
        for raw in [
            r"\\192.168.1.5\C$\Users\a\.ssh\id_rsa",
            r"\\server\c$\x",
            r"\\server\D$",
            r"\\server\ADMIN$\System32",
            r"\\128.0.0.1\c$\x",
            r"\\?\UNC\server\c$\x",
        ] {
            unreadable(raw);
        }
        want(r"\\server\share\x", "//server/share/x");
        want(r"\\server\share$\x", "//server/share$/x");
        want(r"\\localhost\c$\x", "c:/x");
    }

    /// The null device names no file: `> NUL:` is not worth a deny.
    #[test]
    fn the_null_device_is_harmless() {
        for raw in [
            r"\\.\NUL", r"\\.\nul", "//./NUL", r"\\?\NUL", "NUL:", "nul:",
        ] {
            want(raw, "//./NUL");
        }
        unreadable(r"\\.\NUL\x");
        unreadable(r"\\.\NULL");
        unreadable("NULL:");
        let e = secrets_engine(vars());
        for cmd in [r"echo hi > '\\.\NUL'", "echo hi > NUL:", r"cat '\\.\NUL'"] {
            assert!(!e.evaluate(cmd).is_deny(), "{cmd}");
        }
        assert!(!e.evaluate_path(Access::Write, "NUL:").is_deny());
    }

    /// `.` and `..` collapse before the `/proc` and drive checks look at the
    /// path, or `/./proc` and `/c/../c` slip past them.
    #[test]
    fn slash_spelled_paths_normalize_before_the_checks() {
        for raw in [
            "/./proc/self/environ",
            "/c/../proc/self/environ",
            "/x/../proc/self/environ",
            "/proc/cygdrive/c/../../self/environ",
            "/./dev/fd/0",
            // `..` above the root.
            "/..",
            "/../c/x",
            "/c/../..",
            "/c/../../x",
            "../../c/Users/a/.claude/.credentials.json",
            "../../x",
            "C:/../x",
            "C:/a/../../x",
            // A canonical `/proc`, spelled with `/`.
            "c:/proc/self/environ",
            "C:/PROC/self/environ",
            "/c/proc/self/environ",
            "/d/proc/x",
            // A sibling that may be a mount: `cd /usr; cat ../c/Users/…`.
            "../x",
            "../c/Users/a/x",
        ] {
            unreadable(raw);
        }
        assert!(matches!(
            read("proc/self/environ", Some(Path::new(r"C:\")), &vars()),
            Err(Unread::Unreadable(_))
        ));
        for (raw, form) in [
            ("/./c/Users/a/x", "c:/Users/a/x"),
            ("/c/../c/Users/a/x", "c:/Users/a/x"),
            ("/c/./Users/a/x", "c:/Users/a/x"),
            ("/x/../c/Users/a/x", "c:/Users/a/x"),
            ("/c/a/../b", "c:/b"),
            ("/cygdrive/./c/x", "c:/x"),
            ("/mnt/../c/x", "c:/x"),
            ("/c/..", "c:/"),
            ("/.", "c:/"),
            ("../xy", "c:/xy"),
            ("./x", "c:/p/x"),
            ("C:/a/../x", "c:/x"),
        ] {
            want(raw, form);
        }
        // A backslash is Win32's: `..` stops at the root, and `\proc` is a
        // directory on the drive.
        want(r"C:\..\..\x", "c:/x");
        want(r"..\..\..\x", "c:/x");
        want(r"\proc\x", "c:/proc/x");
        want(r"C:\proc\x", "c:/proc/x");
        let e = secrets_engine(vars());
        for cmd in [
            "cat /./proc/self/environ",
            "cat /c/../proc/self/environ",
            "cat /proc/cygdrive/c/../../self/environ",
            "cat ../../c/Users/a/.claude/.credentials.json",
            "cd /; cat proc/self/environ",
            "cd /proc/self; cat environ",
        ] {
            assert_unreadable_deny(&e.evaluate(cmd), cmd);
        }
        for cmd in [
            "cat /./c/Users/a/.claude/.credentials.json",
            "cat /c/../c/Users/a/.claude/.credentials.json",
            "cat /c/Users/x/../a/.claude/.credentials.json",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "{cmd}");
        }
    }

    #[test]
    fn git_bash_dev_fd_is_like_proc() {
        for raw in ["/dev/fd", "/dev/fd/3", "/DEV/FD/3"] {
            unreadable(raw);
        }
        want("/dev/null", "c:/dev/null");
        want("/dev/fda", "c:/dev/fda");
    }

    /// A glob under a UNC root is never expanded (that would call the host),
    /// so its literal text would match no rule: `.en*` misses `**/.env`.
    #[test]
    fn a_glob_under_a_unc_root_is_unreadable() {
        for raw in [
            "//localhost/docs/.en*",
            "//server/share/*",
            "//server/share/.en?",
            "//server/share/.en[v]",
            r"\\server\share\d\*\x",
            r"\\?\UNC\server\share\*",
        ] {
            unreadable(raw);
        }
        assert!(matches!(
            read("*", Some(Path::new(r"\\server\share")), &vars()),
            Err(Unread::Unreadable(_))
        ));
        // A drive path is expanded as usual; a local admin share is one.
        want("//localhost/c$/.en*", "c:/.en*");
        want(r"C:\p\.en*", "c:/p/.en*");
        let e = secrets_engine(vars());
        assert_unreadable_deny(
            &e.evaluate("cat //localhost/docs/.en*"),
            "cat //localhost/docs/.en*",
        );
        assert_unreadable_deny(
            &e.evaluate_path(Access::Read, "//localhost/docs/.en*"),
            "//localhost/docs/.en*",
        );
        assert!(!e.evaluate("cat //localhost/docs/notes.txt").is_deny());
    }

    /// What a live word may expand to, in every position a path is read from.
    const LIVE_WORDS: &[&str] = &[
        "./$x/id_rsa",
        "$x/id_rsa",
        r"$x\id_rsa",
        r"./$x\id_rsa",
        "${x}/id_rsa",
        "./${x}/id_rsa",
        r"$env:NOPE\id_rsa",
        r"./$env:NOPE\id_rsa",
        "foo$x/id_rsa",
        "\"./$x/id_rsa\"",
        "\"foo$x/id_rsa\"",
        // A literal part does not make the rest literal.
        "'lit'/$x/id_rsa",
        r"\$y/$x/id_rsa",
        // Each brace alternative carries the word's reading.
        "./{$x,b}/id_rsa",
        "./$x/*",
        // Parameters that hold what a caller passed: `bash -c '…' _ .ssh`.
        "./$0/id_rsa",
        "./$1/id_rsa",
        "./$@/id_rsa",
        "./$*/id_rsa",
        "./$_/id_rsa",
        // Substitutions whose value is not known.
        "$(getdir)/id_rsa",
        "./$(getdir)/id_rsa",
        "\"./$(getdir)/id_rsa\"",
        "`getdir`/id_rsa",
        "./`getdir`/id_rsa",
    ];

    /// Every place a word is read as a path, where `F` is that word.
    const PATH_POSITIONS: &[&str] = &[
        "cat F",
        "git status; cat F",
        "sudo cat F",
        "cat < F",
        "echo x > F",
        "echo x >> F",
        "make 2> F",
        "> F",
        "cp F out",
        "cp in F",
        "cp in F/",
        "mv F out",
        "mv in F",
        "rm F",
        "dd if=F",
        "xargs -a F cat",
        "cd F && cat notes.txt",
        "pushd F && cat notes.txt",
    ];

    /// `$` and a name with no known value, unquoted or double-quoted, may be
    /// anything at run time: `./$x/id_rsa` with `x=.ssh`.
    #[test]
    fn a_word_the_shell_may_expand_is_unreadable_as_a_path() {
        let e = secrets_engine(vars());
        for word in LIVE_WORDS {
            for at in PATH_POSITIONS {
                let cmd = at.replace('F', word);
                assert_unreadable_deny(&e.evaluate(&cmd), &cmd);
            }
            // The same when it reaches the lexer a second time.
            let nested = format!("bash -c 'cat {word}'");
            if !word.contains('\'') {
                assert_unreadable_deny(&e.evaluate(&nested), &nested);
            }
        }
    }

    /// `%x%` is cmd's, and expands even inside single quotes there.
    #[test]
    fn an_unknown_percent_variable_is_unreadable_as_a_path() {
        let e = secrets_engine(vars());
        for word in [
            r"%x%\id_rsa",
            r"'%x%\id_rsa'",
            r#""%x%\id_rsa""#,
            r"foo%x%\id_rsa",
            r"./%x%\id_rsa",
            "./%x%/id_rsa",
        ] {
            for at in PATH_POSITIONS {
                let cmd = at.replace('F', word);
                assert_unreadable_deny(&e.evaluate(&cmd), &cmd);
            }
        }
    }

    /// Single quotes, an escape and `$'…'` leave a `$` as text: the path is
    /// judged as spelled, and a file it names is still found.
    #[test]
    fn a_dollar_the_shell_leaves_alone_is_a_name() {
        let e = secrets_engine(vars());
        let clean = Decision::Allow {
            trace: AllowTrace::NoMatch,
        };
        for word in [
            "'./$x/id_rsa'",
            r"./\$x/id_rsa",
            "\"./\\$x/id_rsa\"",
            "$'./$x/id_rsa'",
            "'foo$x/id_rsa'",
            r"'C:\$Recycle.Bin\x'",
            r"'.\$x\id_rsa'",
            "'./$1/id_rsa'",
        ] {
            for at in PATH_POSITIONS {
                let cmd = at.replace('F', word);
                assert_eq!(e.evaluate(&cmd), clean, "{cmd}");
            }
        }
        for cmd in [
            "cat './$x/.env'",
            "cd './$x' && cat .env",
            r"cd 'C:\$Recycle.Bin' && cat .env",
            "cd '~/.ssh::$INDEX_ALLOCATION' && cat id_rsa",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "{cmd}");
        }
    }

    /// A `$` that opens nothing is a share name or part of one, and a variable
    /// with a known value is that value.
    #[test]
    fn share_names_and_known_variables_stay_readable() {
        let e = secrets_engine(vars());
        let clean = Decision::Allow {
            trace: AllowTrace::NoMatch,
        };
        for word in [
            "c$/x",
            "admin$/x",
            "docs$/x",
            "docs$",
            r#""docs$/x""#,
            "//localhost/c$/x",
            "//localhost/docs$/x",
            "//localhost/admin$/x",
            "//server/docs$/x",
            "\"$HOME/x\"",
            "$USERPROFILE/x",
            "./$USERNAME/x",
            r"'$env:USERPROFILE\x'",
            "$env:USERPROFILE/x",
            "${HOME}/x",
            "$PWD/x",
            "%USERPROFILE%/x",
        ] {
            for at in PATH_POSITIONS {
                let cmd = at.replace('F', word);
                assert_eq!(e.evaluate(&cmd), clean, "{cmd}");
            }
        }
        assert!(e
            .evaluate("cat //localhost/c$/Users/a/.ssh/id_rsa")
            .is_deny());
        assert!(e.evaluate("cat \"$HOME/.ssh/id_rsa\"").is_deny());
    }

    /// Words no path rule reads stay out of it.
    #[test]
    fn a_variable_outside_a_path_is_not_judged() {
        let e = secrets_engine(vars());
        for cmd in [
            "git status",
            "git commit -m \"$msg\"",
            "git commit -m \"$(cat <<'EOF'\nhello\nEOF\n)\"",
            "git log --format=%H",
            "git diff $(git merge-base a b)",
            "echo \"$x\" > out.txt",
            "echo $(date) > out.txt",
            "echo \"$(getdir)\"",
            "npm test $x",
            "ls $x",
            "grep \"$pat\" README.md",
            "grep \"$(getpat)\" README.md",
            "sed -e \"s/$x/y/\" README.md",
            "curl -H \"A: $T\" https://x.test",
            "x=1; echo $x",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "{cmd}");
        }
        // Nothing is protected without a path rule.
        let none = Engine::new(Vec::new()).with_paths(vars());
        for cmd in ["cat ./$x/id_rsa", "cd ./$x && cat id_rsa", "cat $(getdir)"] {
            assert!(!none.evaluate(cmd).is_deny(), "{cmd}");
        }
    }

    /// POSIX style keeps what it did, word for word.
    #[test]
    fn posix_style_reads_a_live_word_as_before() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let v = PathVars::new()
            .with_style(PathStyle::Posix)
            .with_cwd("/nonexistent-p19a/p")
            .with_var("HOME", "/nonexistent-p19a/home");
        let e = secrets_engine(v);
        let clean = Decision::Allow {
            trace: AllowTrace::NoMatch,
        };
        for cmd in [
            "cat ./$x/id_rsa",
            "cat foo$x/id_rsa",
            "cat '$x/id_rsa'",
            "cat $(getdir)/id_rsa",
            "cat `getdir`/id_rsa",
            "echo x > ./$x/id_rsa",
            "cat %x%/id_rsa",
        ] {
            assert_eq!(e.evaluate(cmd), clean, "{cmd}");
        }
        let unknown = Decision::Allow {
            trace: AllowTrace::Unjudgeable {
                reason: "working directory unknown after cd".to_string(),
            },
        };
        for cmd in [
            "cd ./$x && cat id_rsa",
            "cd '$x' && cat id_rsa",
            "cd $(getdir) && cat id_rsa",
        ] {
            assert_eq!(e.evaluate(cmd), unknown, "{cmd}");
        }
    }

    /// Every spelling, end to end: as an operand, a redirect, a copy source,
    /// nested, and through a `cd` to its directory.
    #[test]
    fn spellings_are_denied_end_to_end() {
        let e = secrets_engine(vars());
        for raw in ID_RSA_SPELLINGS {
            let escaped = raw.replace('\\', r"\\");
            let mut cmds = vec![
                format!("cat '{raw}'"),
                format!("cat < '{raw}'"),
                format!("cp '{raw}' out"),
                format!("mv '{raw}' out"),
                format!("git status; cat '{raw}'"),
                format!("bash -c \"cat '{escaped}'\""),
            ];
            let split = raw.rfind(['\\', '/']).expect("a separator");
            let (dir, file) = (&raw[..split], &raw[split + 1..]);
            cmds.push(format!("cd '{dir}' && cat '{file}'"));
            cmds.push(format!("pushd '{dir}'; cat '{file}'"));
            cmds.push(format!("cd '{dir}' && cp '{file}' /c/p/out"));
            for cmd in cmds {
                assert!(e.evaluate(&cmd).is_deny(), "{cmd}");
            }
        }
    }

    /// Git Bash's `/` holds its drive mounts: from there `c/Users` is the
    /// drive, though it reads as `c:/c/Users`. A `~`-rooted rule would miss it.
    #[test]
    fn a_relative_walk_into_a_git_bash_mount_is_unreadable() {
        let mut w = Vec::new();
        let pack = load_pack_str("<t>", MIXED_CASE_PACK, &mut w).unwrap();
        let e = Engine::new(vec![pack]).with_paths(vars());
        for cmd in [
            "cd /; cat c/Users/a/MyKeys/x",
            "cd /; cat ./c/Users/a/MyKeys/x",
            "cd /; cat cygdrive/c/Users/a/MyKeys/x",
            "cd /; cat mnt/c/Users/a/MyKeys/x",
            "cd /; cat proc/cygdrive/c/Users/a/MyKeys/x",
            "cd /cygdrive; cat c/Users/a/MyKeys/x",
            "cd /mnt; cat c/Users/a/MyKeys/x",
            "cd /; cd c/Users/a; cat MyKeys/x",
            "cd /cygdrive; cd c; cat Users/a/MyKeys/x",
            "cd /x; cat ../c/Users/a/MyKeys/x",
            "cd /usr; cat ../c/Users/a/MyKeys/x",
        ] {
            assert_unreadable_deny(&e.evaluate(cmd), cmd);
        }
        let clean = Decision::Allow {
            trace: AllowTrace::NoMatch,
        };
        for cmd in [
            // A one-letter directory the working directory is already in:
            // CI's `D:\a\repo`, and `C:\p` here.
            "cat c/x",
            "cat p/x",
            r"cd 'D:\a\repo'; cat src/main.rs",
            r"cd 'D:\a\repo'; cat ../other/x",
            "cd C:/c/x; cat y",
            // Named with its drive, or as Win32 reads it.
            "cat C:/c/x",
            "cat C:/mnt/c/x",
            r"cd /; cat 'c\x'",
            // Not a drive.
            "cd /; cat src/x",
            "cd /mnt/data; cat x",
            "cd /; cat mnt/data/x",
            r"cd '\\server\share'; cat c/x",
        ] {
            assert_eq!(e.evaluate(cmd), clean, "{cmd}");
        }
    }

    /// `%=C:%` is cmd's per-drive working directory, and any `%v:…%` with no
    /// separator in `v` may be expanded.
    #[test]
    fn any_percent_colon_variable_is_unreadable() {
        for raw in [
            r"%=C:%\.claude\.credentials.json",
            r"%:x%\y",
            r"%a b:c%\x",
            r"C:\p\%=D:%\x",
            r"%=ExitCode%\x",
        ] {
            unreadable(raw);
        }
        // A separator before the colon: no variable name, ordinary text.
        want(r"C:\a%b\c:d%e", "c:/a%b/c");
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
