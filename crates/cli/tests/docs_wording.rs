//! The wording rule of spec section 10: the docs and the README never say
//! "the agent never holds a credential" on its own. The plans and specs under
//! `docs/superpowers/` quote the phrase and are not checked.

use std::fs;
use std::path::{Path, PathBuf};

const REQUIRED: &str = "the agent never holds a credential for a brokered service; it holds its own model-provider login unless you run a local model";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "superpowers") {
                continue;
            }
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
}

/// Whitespace (including line breaks and quote markers) collapsed.
fn flat(text: &str) -> String {
    text.split(|c: char| c.is_whitespace() || c == '>')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Each use of "never hold(s) (a) credential(s)" that is not followed by
/// "for a brokered service" (any subject: "the agent", "agents", ...).
fn offenders(text: &str) -> Vec<String> {
    let t = flat(text);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = t[from..].find("never hold") {
        let start = from + i;
        let mut rest = &t[start + "never hold".len()..];
        from = start + 1;
        rest = rest.strip_prefix('s').unwrap_or(rest);
        rest = rest
            .strip_prefix(" a")
            .or(rest.strip_prefix(" any"))
            .unwrap_or(rest);
        let Some(rest) = rest.strip_prefix(" credential") else {
            continue;
        };
        let rest = rest.strip_prefix('s').unwrap_or(rest);
        if !rest.starts_with(" for a brokered service") {
            out.push(t[start..(start + 70).min(t.len())].to_string());
        }
    }
    out
}

#[test]
fn checker_flags_a_bare_claim() {
    assert_eq!(offenders("So the agent never holds a credential.").len(), 1);
    assert_eq!(
        offenders("so the agent never\nholds a credential at all").len(),
        1
    );
    assert!(
        offenders("The agent never holds a credential for a brokered\nservice; it holds")
            .is_empty()
    );
    assert_eq!(offenders("Agents never hold credentials.").len(), 1);
    assert!(offenders("> the agent never holds a credential for a brokered service").is_empty());
}

#[test]
fn docs_and_readme_never_make_the_bare_claim() {
    let root = root();
    let mut files = vec![root.join("README.md")];
    collect(&root.join("docs"), &mut files);
    assert!(files.len() > 10, "found only {} pages", files.len());
    let mut bad = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        for o in offenders(&text) {
            bad.push(format!("{}: ...{o}", f.display()));
        }
    }
    assert!(bad.is_empty(), "bare claim:\n{}", bad.join("\n"));
}

#[test]
fn readme_and_threats_carry_the_full_sentence() {
    let root = root();
    for f in ["README.md", "docs/threats.md"] {
        let text = flat(&fs::read_to_string(root.join(f)).unwrap());
        assert!(text.contains(REQUIRED), "{f} lacks the wording rule");
    }
}

#[test]
fn windows_page_states_its_facts_and_limits() {
    let root = root();
    let text = fs::read_to_string(root.join("docs/windows.md")).unwrap();
    for needle in [
        "install.ps1",
        r"%LOCALAPPDATA%\saiife\audit",
        "PowerShell",
        "Windows 11 23H2",
        // The anchors other pages link to.
        "## Developer mode",
        "## Shells and the guard",
        "## Limits",
        "## Locked mode",
        "## Disk encryption",
        "## Approvals",
        "## Personal broker",
        // Honest about what has run.
        "throwaway CI runners",
        // The limits the rulings named.
        "export HOME=",
        "eval 'cd",
        "dead mapped drive",
        "Test-Path .env",
        "UNC paths are lexical",
        "Start-BitsTransfer -Destination",
        "Export-Certificate",
        "Save-Module",
        "pwsh -c '...'",
    ] {
        assert!(text.contains(needle), "docs/windows.md lacks {needle}");
    }
    let locked = text.split("## Locked mode").nth(1).unwrap();
    assert!(locked.contains("plan 19b"), "the locked section names 19b");
}

// ---- Windows locked mode (plan 19b) ----

/// The section of `text` that starts at heading `h`, up to the next `## `.
fn section<'a>(text: &'a str, h: &str) -> &'a str {
    let start = text
        .find(&format!("\n{h}\n"))
        .unwrap_or_else(|| panic!("no heading {h:?}"));
    let rest = &text[start + 1..];
    let end = rest[3..].find("\n## ").map_or(rest.len(), |i| i + 3);
    &rest[..end]
}

#[test]
fn windows_page_has_the_locked_mode_facts() {
    let t = page_text("docs/windows.md");
    let locked = section(&t, "## Locked mode");
    for want in [
        r"NT SERVICE\saiifed",
        r"\\.\pipe\saiife",
        r"C:\ProgramData\saiife",
        r"C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent",
        r"C:\Program Files\ClaudeCode\managed-settings.d",
        r"C:\ProgramData\OpenAI\Codex\requirements.toml",
        r"C:\ProgramData\gemini-cli\settings.json",
    ] {
        assert!(
            locked.contains(want),
            "docs/windows.md#locked-mode lacks {want:?}"
        );
    }
    assert!(
        flat(section(&t, "## Approvals")).contains("approvals need a second account"),
        "docs/windows.md#approvals must say approvals need a second account"
    );
    assert!(
        section(&t, "## Disk encryption").contains("BitLocker"),
        "docs/windows.md#disk-encryption names BitLocker"
    );
    let broker = section(&t, "## Personal broker");
    for want in [
        r"%LOCALAPPDATA%\saiife\personal",
        "Credential Manager",
        "saiife-broker",
    ] {
        assert!(
            broker.contains(want),
            "docs/windows.md#personal-broker lacks {want:?}"
        );
    }
}

/// Owner ruling 2026-11-06: Windows locked mode ships as preview, because a
/// process of the agent's own user can end the hook with exit 0, which the
/// agent reads as allow. Each page that sells locked mode says so.
#[test]
fn windows_locked_mode_is_documented_as_preview() {
    let t = page_text("docs/windows.md");
    for h in ["## Locked mode", "## Limits"] {
        let s = flat(section(&t, h));
        assert!(
            s.contains("preview"),
            "docs/windows.md {h} must say locked mode is preview"
        );
    }
    let locked = flat(section(&t, "## Locked mode"));
    for want in ["terminateprocess", "exit 0", "allow"] {
        assert!(
            locked.contains(want),
            "docs/windows.md#locked-mode must name the reason ({want})"
        );
    }
    for rel in ["README.md", "CHANGELOG.md", "docs/threats.md"] {
        let s = flat(&page_text(rel));
        assert!(
            s.contains("windows locked mode is a preview"),
            "{rel} must say Windows locked mode is a preview"
        );
    }
    let threats = page_text("docs/threats.md");
    assert!(threats.contains("A25"), "docs/threats.md has the A25 row");
    assert!(
        flat(&threats).contains("terminateprocess(hook, 0)"),
        "the A25 row names the forged exit"
    );
}

/// The limits the owner confirmed for the docs (progress note, 2026-11-06).
#[test]
fn windows_limits_name_the_session_and_token_facts() {
    let t = flat(section(&page_text("docs/windows.md"), "## Limits"));
    for want in [
        "openssh",
        "network logon",
        "restricted",
        "low-integrity",
        "group:",
    ] {
        assert!(t.contains(want), "docs/windows.md#limits lacks {want:?}");
    }
}

#[test]
fn threats_lists_the_windows_limits() {
    let text = fs::read_to_string(root().join("docs/threats.md")).unwrap();
    assert!(
        text.contains("Set-Alias"),
        "docs/threats.md lacks Set-Alias"
    );
    assert!(text.contains("windows.md#limits"));
}

#[test]
fn install_and_readme_point_windows_at_its_page() {
    let root = root();
    for f in ["docs/install.md", "README.md"] {
        let text = fs::read_to_string(root.join(f)).unwrap();
        assert!(text.contains("install.ps1"), "{f} lacks install.ps1");
        assert!(text.contains("windows.md"), "{f} lacks the Windows page");
    }
    for f in ["claude-code", "codex", "gemini"] {
        let text = fs::read_to_string(root.join(format!("docs/agents/{f}.md"))).unwrap();
        assert!(text.contains("PowerShell"), "{f}.md lacks PowerShell");
        assert!(text.contains("windows.md"), "{f}.md lacks the Windows page");
    }
}

#[test]
fn new_pages_exist_and_are_linked_from_the_readme() {
    let root = root();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    for page in [
        "docs/forwarding.md",
        "docs/auditors.md",
        "docs/egress.md",
        "docs/threats.md",
        "docs/environments.md",
        "docs/collections.md",
    ] {
        assert!(root.join(page).is_file(), "{page} missing");
        assert!(readme.contains(page), "README does not link {page}");
    }
}

#[test]
fn new_pages_linked() {
    let root = root();
    let index = fs::read_to_string(root.join("docs/connectors/README.md")).unwrap();
    for page in ["environments.md", "collections.md"] {
        assert!(root.join("docs").join(page).is_file(), "{page} missing");
        assert!(
            index.contains(&format!("(../{page})")),
            "the connector index does not link {page}"
        );
    }
    // Every connector page is listed in the index.
    for e in fs::read_dir(root.join("docs/connectors")).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        if name != "README.md" && name.ends_with(".md") {
            assert!(
                index.contains(&format!("({name})")),
                "the connector index does not list {name}"
            );
        }
    }
}

// ---- docs/mcp.md (plan 17) ----

fn mcp_page() -> String {
    fs::read_to_string(root().join("docs/mcp.md")).expect("docs/mcp.md")
}

#[test]
fn mcp_page_is_linked() {
    let root = root();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    assert!(
        readme.contains("docs/mcp.md"),
        "README does not link docs/mcp.md"
    );
    let index = fs::read_to_string(root.join("docs/connectors/README.md")).unwrap();
    assert!(
        index.contains("(../mcp.md)"),
        "the connector index does not link mcp.md"
    );
}

#[test]
fn mcp_page_holds_the_warning_text() {
    let t = flat(&mcp_page());
    assert!(
        t.contains(&flat(
            "MCP server linear bypasses saiife: its requests are not brokered or limited"
        )),
        "docs/mcp.md lacks the exact unbrokered-server warning"
    );
}

#[test]
fn network_is_never_called_sandboxed() {
    let root = root();
    for f in [
        "docs/mcp.md",
        "docs/threats.md",
        "docs/superpowers/specs/2026-10-19-saiife-v2-design.md",
    ] {
        let t = flat(&fs::read_to_string(root.join(f)).unwrap());
        assert!(
            t.contains("network is **not** sandboxed") || t.contains("network is not sandboxed"),
            "{f} does not say the gateway child's network is not sandboxed"
        );
    }
}

#[test]
fn mcp_page_does_not_claim_codex_or_gemini_restrictions() {
    let t = flat(&mcp_page());
    assert!(
        t.contains("saiife does not restrict their mcp servers yet"),
        "docs/mcp.md must say saiife does not restrict Codex or Gemini MCP servers yet"
    );
    assert!(t.contains("restricted by the hook only"));
    for claim in [
        "restricts codex",
        "restricts gemini",
        "writes a codex",
        "writes a gemini",
        "managed keys for codex",
        "managed keys for gemini",
        "codex and gemini are restricted by policy",
        "codex and gemini get a managed",
    ] {
        assert!(!t.contains(claim), "docs/mcp.md claims: {claim}");
    }
    // A sentence that names Codex or Gemini and "restrict" must carry a
    // negation or the hook-only wording.
    for s in t.split(['.', '\n']) {
        let names = s.contains("codex") || s.contains("gemini");
        if names && s.contains("restrict") {
            assert!(
                s.contains(" not ")
                    || s.contains("hook only")
                    || s.contains("no managed")
                    || s.contains("none is written"),
                "docs/mcp.md may claim a Codex/Gemini restriction: {s}"
            );
        }
    }
}

// The page documents the locked-mode MCP gateway with a POSIX command path. The
// gateway does not exist on Windows until plan 19b.
#[cfg(unix)]
#[test]
fn mcp_page_example_loads() {
    let text = mcp_page();
    let mut blocks = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        match &mut cur {
            Some(b) if line.trim_start().starts_with("```") => {
                blocks.push(std::mem::take(b));
                cur = None;
            }
            Some(b) => {
                b.push_str(line);
                b.push('\n');
            }
            None if line.trim() == "```toml" => cur = Some(String::new()),
            None => {}
        }
    }
    let ex: Vec<_> = blocks
        .iter()
        .filter(|b| b.contains("[mcp.linear]"))
        .collect();
    assert_eq!(ex.len(), 1, "expected one [mcp.linear] example");
    #[derive(serde::Deserialize)]
    struct Drop {
        mcp: std::collections::BTreeMap<String, saiife_policy::McpServerCfg>,
    }
    let d: Drop = toml::from_str(ex[0]).expect("the mcp-linear.toml example parses");
    // `read_paths` must exist on a real host; check the other keys.
    let mut c = d.mcp["linear"].clone();
    c.read_paths.clear();
    c.validate("linear").expect("the example validates");
}

// ---- macOS locked mode (plan 13) ----

fn page_text(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn install_page_has_the_macos_locked_mode_facts() {
    let t = page_text("docs/install.md");
    for want in [
        "## Locked mode (macOS)",
        "`_saiife`",
        "`_saiifeaudit`",
        "/var/db/saiife-run",
        "/var/log/saiife/daemon.log",
        "macOS 15",
        saiife_system::layout::REAUTH_UNAVAILABLE,
    ] {
        assert!(t.contains(want), "docs/install.md lacks {want:?}");
    }
    assert!(
        flat(&t).contains("same-user approval is off on macos"),
        "docs/install.md must say same-user approval is off on macOS"
    );
}

#[test]
fn mcp_page_says_the_gateway_is_linux_only() {
    let t = mcp_page();
    assert!(
        flat(&t).contains("the mcp gateway is linux only in v2.1"),
        "docs/mcp.md must say the MCP gateway is Linux only in v2.1"
    );
    assert!(
        t.contains(saiife_policy::mcp::MCP_NEEDS_LINUX),
        "docs/mcp.md must quote the macOS load error"
    );
    // Plan 19b, W18: Windows has no gateway either.
    assert!(
        flat(&t).contains("on windows too"),
        "docs/mcp.md must say the gateway is Linux only on Windows too"
    );
}

/// Same-user approval is off on macOS (plan 13, Task 8): the approvals
/// page and the threat page say so.
#[test]
fn macos_same_user_approval_is_documented_as_off() {
    for rel in ["docs/approvals.md", "docs/threats.md"] {
        assert!(
            flat(&page_text(rel)).contains("same-user approval is off on macos"),
            "{rel} must say same-user approval is off on macOS"
        );
    }
}

// ---- Plan 20: a killed or crashed hook never counts as an allow ----

/// The first fenced block of `lang` after the line `marker` in `text`.
fn block_after<'a>(text: &'a str, marker: &str, lang: &str) -> &'a str {
    let at = text.find(marker).unwrap_or_else(|| panic!("no {marker:?}"));
    let fence = format!("```{lang}\n");
    let start = at + text[at..].find(&fence).expect("no fence") + fence.len();
    let end = start + text[start..].find("```").expect("no closing fence");
    &text[start..end]
}

/// Spec §8.3 shows the Claude Code drop-in saiife writes, byte for byte.
#[test]
fn spec_83_matches_the_drop_in() {
    let spec = page_text("docs/superpowers/specs/2026-10-19-saiife-v2-design.md");
    let shown = block_after(
        &spec,
        "**Claude Code** `/etc/claude-code/managed-settings.d/50-saiife.json`:",
        "json",
    );
    assert_eq!(shown, saiife_agents::claude::managed_settings());
}

#[test]
fn threats_names_the_cosigner_and_the_no_verdict_record() {
    let t = page_text("docs/threats.md");
    for want in ["co-signer", "127.0.0.1:7433", "no_verdict"] {
        assert!(t.contains(want), "docs/threats.md lacks {want:?}");
    }
    let s = flat(&t);
    assert!(
        s.contains("injected into the hook"),
        "docs/threats.md must say code injected into the hook is not prevented on Windows"
    );
}

/// Owner ruling 2026-11-09: no managed NO_PROXY; the docs tell admins to add
/// 127.0.0.1, and doctor warns.
#[test]
fn install_page_has_the_no_proxy_note() {
    let t = page_text("docs/install.md");
    for want in ["NO_PROXY", "127.0.0.1", "HTTPS_PROXY"] {
        assert!(t.contains(want), "docs/install.md lacks {want:?}");
    }
}

#[test]
fn windows_limits_keep_preview_and_name_the_cosigner() {
    let t = page_text("docs/windows.md");
    let limits = flat(section(&t, "## Limits"));
    for want in ["preview", "co-signer", "no_verdict"] {
        assert!(
            limits.contains(want),
            "docs/windows.md#limits lacks {want:?}"
        );
    }
}

/// The co-signer is for Claude Code only; Codex and Gemini CLI get detection.
#[test]
fn agent_pages_say_who_gets_the_cosigner() {
    let claude = page_text("docs/agents/claude-code.md");
    assert!(claude.contains("co-signer") && claude.contains("127.0.0.1:7433"));
    for f in ["codex", "gemini"] {
        let t = page_text(&format!("docs/agents/{f}.md"));
        assert!(t.contains("no_verdict"), "{f}.md lacks no_verdict");
        assert!(
            flat(&t).contains("no co-signer"),
            "{f}.md must say it has no co-signer"
        );
    }
}

/// The live lock check needs a stand-in co-signer, or every Claude Code call
/// is blocked by `onFailure`.
#[test]
fn lock_check_page_names_the_stand_in_cosigner() {
    let t = page_text("docs/lock-check.md");
    assert!(t.contains("127.0.0.1:7433"));
    assert!(flat(&t).contains("stand-in co-signer"));
}
