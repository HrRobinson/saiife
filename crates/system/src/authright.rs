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

/// The settings a registered right must keep, whitespace removed.
const REQUIRED: [&str; 3] = [
    "<key>session-owner</key><true/>",
    "<key>shared</key><false/>",
    "<key>timeout</key><integer>0</integer>",
];

/// `Ok` when the `authorizationdb read` output holds the settings that make
/// the right ask every time for the session owner; `Err` names the first
/// one missing.
pub fn read_ok(stdout: &str) -> Result<(), String> {
    let squeezed: String = stdout.chars().filter(|c| !c.is_whitespace()).collect();
    match REQUIRED.iter().find(|r| !squeezed.contains(*r)) {
        None => Ok(()),
        Some(r) => Err(format!("the right {RIGHT} lacks {r}")),
    }
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

    #[test]
    fn read_ok_needs_each_setting() {
        assert!(read_ok("").is_err());
        let shared = RIGHT_PLIST.replace(
            "<key>shared</key>\n\t<false/>",
            "<key>shared</key>\n\t<true/>",
        );
        assert!(read_ok(&shared).unwrap_err().contains("shared"));
        let timeout = RIGHT_PLIST.replace("<integer>0</integer>", "<integer>300</integer>");
        assert!(read_ok(&timeout).unwrap_err().contains("timeout"));
        let owner = RIGHT_PLIST.replace(
            "<key>session-owner</key>\n\t<true/>",
            "<key>session-owner</key>\n\t<false/>",
        );
        assert!(read_ok(&owner).unwrap_err().contains("session-owner"));
        // The layout of the output does not matter.
        assert_eq!(
            read_ok(
                "<dict><key>session-owner</key>  <true/>\n<key>shared</key><false/>\
                 <key>timeout</key>\n  <integer>0</integer></dict>"
            ),
            Ok(())
        );
    }
}
