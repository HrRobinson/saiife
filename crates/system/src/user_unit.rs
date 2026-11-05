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
    let s = exe
        .to_str()
        .ok_or_else(|| format!("the executable path {} is not valid UTF-8", exe.display()))?;
    if s.chars().any(|c| c.is_control()) {
        return Err(format!(
            "the executable path {s:?} contains a control character"
        ));
    }
    Ok(s)
}

pub fn user_unit_text(exe: &Path) -> Result<String, String> {
    let s = exe_str(exe)?;
    if s.chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\' || c == '$')
    {
        return Err(format!(
            "the executable path {s} contains whitespace, a quote, a backslash or a $; \
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

/// The per-user autostart key on Windows (`HKCU`, no admin rights).
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// The value under [`RUN_KEY`] that starts the personal broker at logon.
pub const RUN_VALUE: &str = "saiife-broker";

/// The command the logon `Run` value holds: `"<exe>" daemon --user`. The path is quoted
/// whole, so a space in it (`C:\Program Files\...`) cannot split the command.
/// [`windows_run_command`] is the checked form that writes it.
pub fn windows_run_value(exe: &Path) -> String {
    format!("\"{}\" daemon --user", exe.display())
}

/// [`windows_run_value`] for a path that is safe to put in the registry: a drive or UNC
/// absolute path, valid UTF-8, with no quote and no control character (a quote would end
/// the quoting early, and Windows paths cannot hold one anyway).
pub fn windows_run_command(exe: &Path) -> Result<String, String> {
    let s = exe
        .to_str()
        .ok_or_else(|| format!("the executable path {} is not valid UTF-8", exe.display()))?;
    let b = s.as_bytes();
    let drive = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    if !(drive || s.starts_with(r"\\")) {
        return Err(format!("the executable path {s} is not absolute"));
    }
    if s.chars().any(|c| c.is_control() || c == '"') {
        return Err(format!(
            "the executable path {s:?} contains a quote or a control character"
        ));
    }
    Ok(windows_run_value(exe))
}

/// The registry key [`autostart`] writes to. A trait so Linux tests run the logic.
pub trait RunKey {
    fn set(&mut self, name: &str, value: &str) -> Result<(), String>;
    /// `false` when there was no such value.
    fn delete(&mut self, name: &str) -> Result<bool, String>;
}

/// Turn the logon start of the personal broker on or off. Returns whether anything
/// changed (`off` with no value is not an error and changes nothing).
pub fn autostart(reg: &mut dyn RunKey, exe: &Path, on: bool) -> Result<bool, String> {
    if on {
        reg.set(RUN_VALUE, &windows_run_command(exe)?)?;
        Ok(true)
    } else {
        reg.delete(RUN_VALUE)
    }
}

/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, through `winreg`.
#[cfg(windows)]
pub struct HkcuRun;

#[cfg(windows)]
impl RunKey for HkcuRun {
    fn set(&mut self, name: &str, value: &str) -> Result<(), String> {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(RUN_KEY)
            .map_err(|e| format!("HKCU\\{RUN_KEY}: {e}"))?;
        key.set_value(name, &value)
            .map_err(|e| format!("HKCU\\{RUN_KEY}\\{name}: {e}"))
    }

    fn delete(&mut self, name: &str) -> Result<bool, String> {
        use winreg::{
            enums::{HKEY_CURRENT_USER, KEY_SET_VALUE},
            RegKey,
        };
        let key = match RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE)
        {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(format!("HKCU\\{RUN_KEY}: {e}")),
        };
        match key.delete_value(name) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("HKCU\\{RUN_KEY}\\{name}: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_run_value_quotes_exe() {
        assert_eq!(
            windows_run_value(Path::new(r"C:\Program Files\saiife\saiife.exe")),
            r#""C:\Program Files\saiife\saiife.exe" daemon --user"#
        );
        assert_eq!(
            windows_run_value(Path::new(r"C:\x\saiife.exe")),
            r#""C:\x\saiife.exe" daemon --user"#
        );
    }

    #[test]
    fn windows_run_command_refuses_what_could_break_the_quoting() {
        assert!(windows_run_command(Path::new(r"C:\Program Files\s\saiife.exe")).is_ok());
        assert!(windows_run_command(Path::new(r"\\host\share\saiife.exe")).is_ok());
        for p in [
            "saiife.exe",
            r"C:saiife.exe",
            "C:\\a\"b\\saiife.exe",
            "C:\\a\nb\\saiife.exe",
            "C:\\a\0b\\saiife.exe",
            "/opt/x/saiife",
        ] {
            assert!(windows_run_command(Path::new(p)).is_err(), "{p:?}");
        }
    }

    #[derive(Default)]
    struct Reg(std::collections::BTreeMap<String, String>);

    impl RunKey for Reg {
        fn set(&mut self, n: &str, v: &str) -> Result<(), String> {
            self.0.insert(n.into(), v.into());
            Ok(())
        }
        fn delete(&mut self, n: &str) -> Result<bool, String> {
            Ok(self.0.remove(n).is_some())
        }
    }

    #[test]
    fn autostart_on_and_off() {
        let mut r = Reg::default();
        let exe = Path::new(r"C:\Program Files\saiife\saiife.exe");
        assert!(!autostart(&mut r, exe, false).unwrap());
        assert!(autostart(&mut r, exe, true).unwrap());
        assert_eq!(
            r.0.get("saiife-broker").map(String::as_str),
            Some(r#""C:\Program Files\saiife\saiife.exe" daemon --user"#)
        );
        assert_eq!(r.0.len(), 1);
        // On again replaces; off removes only our value.
        r.0.insert("other".into(), "x".into());
        assert!(autostart(&mut r, exe, true).unwrap());
        assert!(autostart(&mut r, exe, false).unwrap());
        assert_eq!(r.0.keys().collect::<Vec<_>>(), vec!["other"]);
        // A bad path writes nothing.
        let mut r = Reg::default();
        assert!(autostart(&mut r, Path::new("rel.exe"), true).is_err());
        assert!(r.0.is_empty());
    }

    #[cfg(unix)]
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

    // systemd and launchd units: the personal broker is Linux and macOS only (plan 16),
    // and `/opt/x/saiife` is not absolute to a Windows host.
    #[cfg(unix)]
    #[test]
    fn unit_text_exact() {
        assert_eq!(user_unit_text(Path::new("/opt/x/saiife")).unwrap(), EXPECT);
    }

    // systemd and launchd units: the personal broker is Linux and macOS only (plan 16),
    // and `/opt/x/saiife` is not absolute to a Windows host.
    #[cfg(unix)]
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
            "/opt/$HOME/saiife",
            "/opt/${HOME}/saiife",
            "/opt/a\nExecStartPre=/bin/evil",
        ] {
            assert!(user_unit_text(Path::new(p)).is_err(), "{p}");
        }
    }

    #[test]
    fn control_characters_refused_in_both() {
        for p in ["/opt/a\0b", "/opt/a\x01b", "/opt/a\x7fb", "/opt/a\rb"] {
            assert!(user_unit_text(Path::new(p)).is_err(), "{p:?}");
            assert!(launchd_plist_text(Path::new(p)).is_err(), "{p:?}");
        }
    }

    // systemd and launchd units: the personal broker is Linux and macOS only (plan 16),
    // and `/opt/x/saiife` is not absolute to a Windows host.
    #[cfg(unix)]
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
