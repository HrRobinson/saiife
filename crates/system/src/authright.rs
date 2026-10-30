//! The macOS authorization right for same-user approvals (plan 13,
//! decision 4): `com.saiife.approve`, written with
//! `security authorizationdb write` and checked with `… read`.
//!
//! Pure data and parsing only: the calls run through [`crate::Host`].

/// The right's name.
pub const RIGHT: &str = "com.saiife.approve";

/// The right's definition, the stdin of `security authorizationdb write`:
/// `authenticate-session-owner` with the spec's `timeout = 0`, written out
/// in full, so Touch ID or the password is asked for every approval.
pub const RIGHT_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>allow-root</key>
	<false/>
	<key>authenticate-user</key>
	<true/>
	<key>class</key>
	<string>user</string>
	<key>comment</key>
	<string>saiife: the logged-in user approves their own pending request, with Touch ID or the password each time.</string>
	<key>default-prompt</key>
	<dict>
		<key></key>
		<string>saiife wants to approve your own pending request. Check the request number in your terminal first.</string>
	</dict>
	<key>session-owner</key>
	<true/>
	<key>shared</key>
	<false/>
	<key>timeout</key>
	<integer>0</integer>
	<key>version</key>
	<integer>1</integer>
</dict>
</plist>
"#;

/// `security authorizationdb write com.saiife.approve` (the plist on stdin).
pub fn write_args() -> [&'static str; 3] {
    ["authorizationdb", "write", RIGHT]
}

/// `security authorizationdb remove com.saiife.approve`.
pub fn remove_args() -> [&'static str; 3] {
    ["authorizationdb", "remove", RIGHT]
}

/// `security authorizationdb read com.saiife.approve` (the plist on stdout).
pub fn read_args() -> [&'static str; 3] {
    ["authorizationdb", "read", RIGHT]
}

/// The settings a registered right must keep at its top level, whitespace
/// removed: `(key, the value right after it)`.
const REQUIRED: [(&str, &str); 6] = [
    ("class", "<string>user</string>"),
    ("authenticate-user", "<true/>"),
    ("allow-root", "<false/>"),
    ("session-owner", "<true/>"),
    ("shared", "<false/>"),
    ("timeout", "<integer>0</integer>"),
];

/// Keys that replace or widen the rule (a delegated rule, mechanisms, a
/// k-of-n choice): refused anywhere in the output.
const FORBIDDEN: [&str; 3] = ["rule", "mechanisms", "k-of-n"];

/// The text of the first top-level `<dict>` of `squeezed`, with every
/// nested dict left out; `None` when there is none or it is not closed.
fn top_level_dict(squeezed: &str) -> Option<String> {
    let start = squeezed.find("<dict>")? + "<dict>".len();
    let mut rest = &squeezed[start..];
    let mut depth = 1usize;
    let mut top = String::new();
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("<dict/>") {
            rest = r;
        } else if let Some(r) = rest.strip_prefix("<dict>") {
            depth += 1;
            rest = r;
        } else if let Some(r) = rest.strip_prefix("</dict>") {
            depth -= 1;
            if depth == 0 {
                return Some(top);
            }
            rest = r;
        } else {
            let c = rest.chars().next()?;
            if depth == 1 {
                top.push(c);
            }
            rest = &rest[c.len_utf8()..];
        }
    }
    None
}

/// `Ok` when the `authorizationdb read` output is the right install
/// writes: at the top level of its dict, each [`REQUIRED`] key exactly once
/// with its value, and no [`FORBIDDEN`] key anywhere. `Err` names the
/// first fault.
pub fn read_ok(stdout: &str) -> Result<(), String> {
    let squeezed: String = stdout.chars().filter(|c| !c.is_whitespace()).collect();
    if let Some(k) = FORBIDDEN
        .iter()
        .find(|k| squeezed.contains(&format!("<key>{k}</key>")))
    {
        return Err(format!("the right {RIGHT} has a {k} key"));
    }
    let top = top_level_dict(&squeezed)
        .ok_or_else(|| format!("the right {RIGHT} is not a property list dict"))?;
    for (k, v) in REQUIRED {
        let key = format!("<key>{k}</key>");
        if top.matches(&key).count() != 1 || !top.contains(&format!("{key}{v}")) {
            return Err(format!("the right {RIGHT} lacks {key}{v}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_has_decision_4_values() {
        let sq: String = RIGHT_PLIST.chars().filter(|c| !c.is_whitespace()).collect();
        for pair in [
            "<key>class</key><string>user</string>",
            "<key>authenticate-user</key><true/>",
            "<key>session-owner</key><true/>",
            "<key>shared</key><false/>",
            "<key>timeout</key><integer>0</integer>",
            "<key>allow-root</key><false/>",
            "<key>version</key><integer>1</integer>",
        ] {
            assert!(sq.contains(pair), "{pair}");
        }
        assert!(RIGHT_PLIST.contains(
            "<string>saiife wants to approve your own pending request. \
             Check the request number in your terminal first.</string>"
        ));
        assert!(RIGHT_PLIST.contains("<key>comment</key>"));
        assert_eq!(read_ok(RIGHT_PLIST), Ok(()));
    }

    #[test]
    fn args_are_exact() {
        assert_eq!(RIGHT, "com.saiife.approve");
        assert_eq!(
            write_args(),
            ["authorizationdb", "write", "com.saiife.approve"]
        );
        assert_eq!(
            remove_args(),
            ["authorizationdb", "remove", "com.saiife.approve"]
        );
        assert_eq!(
            read_args(),
            ["authorizationdb", "read", "com.saiife.approve"]
        );
    }

    /// `RIGHT_PLIST` with `from` replaced by `to` (exactly once).
    fn weakened(from: &str, to: &str) -> String {
        assert_eq!(RIGHT_PLIST.matches(from).count(), 1, "{from}");
        RIGHT_PLIST.replace(from, to)
    }

    #[test]
    fn read_ok_needs_each_setting() {
        assert!(read_ok("").is_err());
        assert_eq!(read_ok(RIGHT_PLIST), Ok(()));
        for (from, to, says) in [
            (
                "<key>shared</key>\n\t<false/>",
                "<key>shared</key>\n\t<true/>",
                "shared",
            ),
            ("<integer>0</integer>", "<integer>300</integer>", "timeout"),
            (
                "<key>session-owner</key>\n\t<true/>",
                "<key>session-owner</key>\n\t<false/>",
                "session-owner",
            ),
            ("<string>user</string>", "<string>rule</string>", "class"),
            (
                "<key>authenticate-user</key>\n\t<true/>",
                "<key>authenticate-user</key>\n\t<false/>",
                "authenticate-user",
            ),
            (
                "<key>allow-root</key>\n\t<false/>",
                "<key>allow-root</key>\n\t<true/>",
                "allow-root",
            ),
        ] {
            let e = read_ok(&weakened(from, to)).unwrap_err();
            assert!(e.contains(says), "{says}: {e}");
        }
        // A key missing altogether.
        let e = read_ok(&weakened("\t<key>allow-root</key>\n\t<false/>\n", "")).unwrap_err();
        assert!(e.contains("allow-root"), "{e}");
    }

    #[test]
    fn read_ok_refuses_rules_mechanisms_and_k_of_n() {
        for k in ["rule", "mechanisms", "k-of-n"] {
            let extra =
                format!("\t<key>{k}</key>\n\t<array><string>x</string></array>\n</dict>\n</plist>");
            let text = RIGHT_PLIST.replacen("</dict>\n</plist>", &extra, 1);
            let e = read_ok(&text).unwrap_err();
            assert!(e.contains(k), "{k}: {e}");
        }
    }

    #[test]
    fn read_ok_matches_only_the_top_level_dict() {
        // The settings only inside a nested dict do not count.
        let nested = "<plist><dict><key>class</key><string>user</string>\
            <key>x</key><dict><key>authenticate-user</key><true/><key>allow-root</key><false/>\
            <key>session-owner</key><true/><key>shared</key><false/>\
            <key>timeout</key><integer>0</integer></dict></dict></plist>";
        assert!(read_ok(nested).is_err());
        // A second, weaker value for a key at the top level.
        let twice = weakened(
            "\t<key>shared</key>\n\t<false/>\n",
            "\t<key>shared</key>\n\t<false/>\n\t<key>shared</key>\n\t<true/>\n",
        );
        assert!(read_ok(&twice).unwrap_err().contains("shared"));
        // Settings after the top-level dict closes do not count either.
        let after =
            "<plist><dict></dict><dict><key>class</key><string>user</string></dict></plist>";
        assert!(read_ok(after).is_err());
        // Not closed.
        assert!(read_ok(&RIGHT_PLIST.replace("</dict>\n</plist>", "")).is_err());
        // The layout does not matter.
        let flat: String = RIGHT_PLIST
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("  ");
        assert_eq!(read_ok(&flat), Ok(()));
    }
}
