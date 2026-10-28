//! The personal broker's login unit text (plan 16, decision 13).
//! Text only: nothing here installs a unit or runs a service manager.

use std::path::Path;

pub const USER_UNIT_NAME: &str = "saiife-broker.service";
pub const LAUNCHD_LABEL: &str = "com.saiife.broker";

fn exe_str(exe: &Path) -> Result<&str, String> {
    if !exe.is_absolute() {
        return Err(format!(
            "the executable path {} is not absolute",
            exe.display()
        ));
    }
    exe.to_str()
        .ok_or_else(|| format!("the executable path {} is not valid UTF-8", exe.display()))
}

pub fn user_unit_text(exe: &Path) -> Result<String, String> {
    let s = exe_str(exe)?;
    if s.chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        return Err(format!(
            "the executable path {s} contains whitespace, a quote or a backslash; \
             move the binary to a plain path"
        ));
    }
    let exe = s.replace('%', "%%");
    Ok(format!(
        "[Unit]
Description=saiife personal broker (not a security boundary)

[Service]
Type=notify
ExecStart={exe} daemon --user
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=1
RuntimeDirectory=saiife
RuntimeDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
LockPersonality=yes
LimitCORE=0

[Install]
WantedBy=default.target
"
    ))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn launchd_plist_text(exe: &Path) -> Result<String, String> {
    let exe = xml_escape(exe_str(exe)?);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>daemon</string>
    <string>--user</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECT: &str = "[Unit]
Description=saiife personal broker (not a security boundary)

[Service]
Type=notify
ExecStart=/opt/x/saiife daemon --user
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=1
RuntimeDirectory=saiife
RuntimeDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
LockPersonality=yes
LimitCORE=0

[Install]
WantedBy=default.target
";

    #[test]
    fn unit_text_exact() {
        assert_eq!(user_unit_text(Path::new("/opt/x/saiife")).unwrap(), EXPECT);
    }

    #[test]
    fn unit_escapes_percent() {
        let t = user_unit_text(Path::new("/opt/50%/saiife")).unwrap();
        assert!(
            t.contains("ExecStart=/opt/50%%/saiife daemon --user\n"),
            "{t}"
        );
    }

    #[test]
    fn unit_refuses_relative_or_spaced_exe() {
        for p in [
            "saiife",
            "/opt/a b/saiife",
            "/opt/a\tb",
            "/opt/\"q\"/s",
            "/opt/a\\b",
        ] {
            assert!(user_unit_text(Path::new(p)).is_err(), "{p}");
        }
    }

    #[test]
    fn plist_escapes_xml_and_parses_shape() {
        let t = launchd_plist_text(Path::new("/opt/a&b<c>/saiife")).unwrap();
        assert!(t.contains("<string>com.saiife.broker</string>"));
        assert!(t.contains("<string>--user</string>"));
        assert!(t.contains("<string>/opt/a&amp;b&lt;c&gt;/saiife</string>"));
        assert!(t.contains("<key>SuccessfulExit</key>\n    <false/>"));
        assert!(t.contains("<string>Background</string>"));
        assert!(launchd_plist_text(Path::new("rel")).is_err());
    }
}
