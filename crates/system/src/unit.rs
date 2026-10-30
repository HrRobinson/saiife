//! The systemd unit for the daemon (spec §5.4.1).

pub use saiife_policy::installed::VaultKeyMode;

/// The first systemd with `LoadCredentialEncrypted=`.
const ENCRYPTED_CREDENTIALS_SINCE: u32 = 250;

const ENCRYPTED_LINE: &str = "LoadCredentialEncrypted=vault-key:/etc/saiife/credstore/vault-key\n";
const OLD_SYSTEMD_COMMENT: &str =
    "# systemd < 250: LoadCredential=vault-key:/etc/saiife/credstore/vault-key (§5.2)\n";
const PLAIN_LINE: &str = "LoadCredential=vault-key:/etc/saiife/credstore/vault-key\n";

/// Spec §5.4.1, verbatim.
const UNIT: &str = r#"[Unit]
Description=saiife daemon (audit, vault, connector gateway)
After=network-online.target

[Service]
Type=notify
User=saiife
Group=saiife
ExecStart=/opt/saiife/bin/saiife daemon --system
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=1
StateDirectory=saiife
StateDirectoryMode=0700
RuntimeDirectory=saiife
RuntimeDirectoryMode=0755
LogsDirectory=saiife/audit
LogsDirectoryMode=2750
UMask=0027
LoadCredentialEncrypted=vault-key:/etc/saiife/credstore/vault-key
# systemd < 250: LoadCredential=vault-key:/etc/saiife/credstore/vault-key (§5.2)
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=
LimitCORE=0

[Install]
WantedBy=multi-user.target
"#;

/// The unit for this systemd version. From 250 on it is the spec text; older
/// systemd reads the plain key file with `LoadCredential=` (§5.2).
pub fn unit_text(systemd: u32) -> String {
    match vault_key_mode(systemd) {
        VaultKeyMode::Credential => UNIT.to_string(),
        VaultKeyMode::File | VaultKeyMode::DaemonFile => UNIT
            .replacen(ENCRYPTED_LINE, PLAIN_LINE, 1)
            .replacen(OLD_SYSTEMD_COMMENT, "", 1),
    }
}

/// How the vault key is stored for this systemd version.
pub fn vault_key_mode(systemd: u32) -> VaultKeyMode {
    if systemd >= ENCRYPTED_CREDENTIALS_SINCE {
        VaultKeyMode::Credential
    } else {
        VaultKeyMode::File
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Copied from spec §5.4.1.
    const SPEC_UNIT: &str = r#"[Unit]
Description=saiife daemon (audit, vault, connector gateway)
After=network-online.target

[Service]
Type=notify
User=saiife
Group=saiife
ExecStart=/opt/saiife/bin/saiife daemon --system
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=1
StateDirectory=saiife
StateDirectoryMode=0700
RuntimeDirectory=saiife
RuntimeDirectoryMode=0755
LogsDirectory=saiife/audit
LogsDirectoryMode=2750
UMask=0027
LoadCredentialEncrypted=vault-key:/etc/saiife/credstore/vault-key
# systemd < 250: LoadCredential=vault-key:/etc/saiife/credstore/vault-key (§5.2)
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=
LimitCORE=0

[Install]
WantedBy=multi-user.target
"#;

    #[test]
    fn unit_255_is_spec_text() {
        assert_eq!(unit_text(255), SPEC_UNIT);
        assert_eq!(unit_text(250), SPEC_UNIT);
    }

    #[test]
    fn unit_249_uses_load_credential() {
        let u = unit_text(249);
        assert!(u.contains("\nLoadCredential=vault-key:/etc/saiife/credstore/vault-key\n"));
        assert!(!u.contains("LoadCredentialEncrypted"));
        assert!(!u.contains("# systemd < 250"));
        assert!(u.ends_with("multi-user.target\n") && !u.ends_with("\n\n"));
        // Every other line is the spec's.
        let expected: Vec<String> = SPEC_UNIT
            .lines()
            .filter(|l| !l.starts_with("# systemd < 250"))
            .map(|l| {
                if l.starts_with("LoadCredentialEncrypted=") {
                    "LoadCredential=vault-key:/etc/saiife/credstore/vault-key".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect();
        let got: Vec<&str> = u.lines().collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn vault_key_mode_follows_systemd() {
        assert_eq!(vault_key_mode(250), VaultKeyMode::Credential);
        assert_eq!(vault_key_mode(255), VaultKeyMode::Credential);
        assert_eq!(vault_key_mode(249), VaultKeyMode::File);
    }
}
