//! The launchd job for the daemon on macOS (plan 13).
//!
//! [`plist_text`] is a pure function: the fixed text of
//! `/Library/LaunchDaemons/com.saiife.saiifed.plist`. Nothing here talks to
//! launchd.

/// The launchd service target of the daemon.
pub const SERVICE: &str = "system/com.saiife.saiifed";

const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.saiife.saiifed</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/saiife/bin/saiife</string>
		<string>daemon</string>
		<string>--system</string>
	</array>
	<key>UserName</key>
	<string>_saiife</string>
	<key>GroupName</key>
	<string>_saiife</string>
	<key>InitGroups</key>
	<true/>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>1</integer>
	<key>Umask</key>
	<integer>23</integer>
	<key>SoftResourceLimits</key>
	<dict>
		<key>Core</key>
		<integer>0</integer>
	</dict>
	<key>HardResourceLimits</key>
	<dict>
		<key>Core</key>
		<integer>0</integer>
	</dict>
	<key>StandardOutPath</key>
	<string>/var/log/saiife/daemon.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/saiife/daemon.log</string>
</dict>
</plist>
"#;

/// The plist text. `Umask` 23 is octal 027.
pub fn plist_text() -> String {
    PLIST.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_matches_golden() {
        let golden = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
\t<key>Label</key>\n\t<string>com.saiife.saiifed</string>\n\
\t<key>ProgramArguments</key>\n\t<array>\n\
\t\t<string>/opt/saiife/bin/saiife</string>\n\
\t\t<string>daemon</string>\n\
\t\t<string>--system</string>\n\t</array>\n\
\t<key>UserName</key>\n\t<string>_saiife</string>\n\
\t<key>GroupName</key>\n\t<string>_saiife</string>\n\
\t<key>InitGroups</key>\n\t<true/>\n\
\t<key>RunAtLoad</key>\n\t<true/>\n\
\t<key>KeepAlive</key>\n\t<true/>\n\
\t<key>ThrottleInterval</key>\n\t<integer>1</integer>\n\
\t<key>Umask</key>\n\t<integer>23</integer>\n\
\t<key>SoftResourceLimits</key>\n\t<dict>\n\t\t<key>Core</key>\n\t\t<integer>0</integer>\n\t</dict>\n\
\t<key>HardResourceLimits</key>\n\t<dict>\n\t\t<key>Core</key>\n\t\t<integer>0</integer>\n\t</dict>\n\
\t<key>StandardOutPath</key>\n\t<string>/var/log/saiife/daemon.log</string>\n\
\t<key>StandardErrorPath</key>\n\t<string>/var/log/saiife/daemon.log</string>\n\
</dict>\n</plist>\n";
        assert_eq!(plist_text(), golden);
    }

    #[test]
    fn plist_has_spec_keys() {
        let t = plist_text();
        for pair in [
            "<key>UserName</key>\n\t<string>_saiife</string>",
            "<key>GroupName</key>\n\t<string>_saiife</string>",
            "<key>KeepAlive</key>\n\t<true/>",
            "<key>RunAtLoad</key>\n\t<true/>",
            "<key>InitGroups</key>\n\t<true/>",
            "<key>Umask</key>\n\t<integer>23</integer>",
        ] {
            assert!(t.contains(pair), "{pair}");
        }
        assert_eq!(SERVICE, "system/com.saiife.saiifed");
    }
}
