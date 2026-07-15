//! Golden corpus for `core.filesystem` (default-on, catastrophic-only).

use lfguard::builtins::builtin_packs;
use lfguard::engine::{Decision, Engine};

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    // core.filesystem is default-on, so the default profile suffices.
    Engine::new(packs)
}

fn deny_pack(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_catastrophic_filesystem_commands() {
    let e = engine();
    let deny = [
        "rm -rf /",
        "rm -rf /*",
        "rm -fr ~",
        "rm -Rf /etc",
        "rm -rf $HOME",
        "rm -r -f /",
        "rm -f -r /usr",
        "rm --recursive --force /var",
        "sudo rm -rf /",
        "rm -rf --no-preserve-root /",
        "dd if=/dev/zero of=/dev/sda",
        "sudo dd if=/dev/zero of=/dev/disk0 bs=1m",
        "mkfs.ext4 /dev/sdb",
        "mkfs -t ext4 /dev/sdb1",
        "truncate -s 0 /dev/sda",
        "echo x > /dev/sda",
        "chmod -R 777 /",
        "chmod -R 000 /etc",
        "chown -R root:root /",
        // I3: quoting variants — the target is wrapped in quotes.
        r#"rm -rf "/""#,
        "rm -rf '/'",
        r#"rm -rf "/etc""#,
        "rm -rf '~'",
        // I3: repeated-slash variants of the root.
        "rm -rf //",
        "rm -rf ///",
        "rm -rf //etc",
        // I3: flags after the target instead of before it.
        "rm /etc -rf",
        "rm / --recursive",
        "rm ~ -fr",
        "sudo rm /etc -rf",
    ];
    for cmd in deny {
        assert_eq!(deny_pack(&e, cmd), "core.filesystem", "for {cmd:?}");
    }
}

#[test]
fn allows_ordinary_filesystem_commands() {
    let e = engine();
    let allow = [
        "rm -rf ./build",
        "rm -rf node_modules",
        "rm -rf /tmp/scratch",
        "rm -rf /var/folders/xy/tmpdir", // deep temp path, not a system root
        "rm file.txt",
        "rm -r somedir",
        "dd if=/dev/zero of=./out.img bs=1M count=10",
        "chmod -R 755 ./assets",
        "chmod 600 ~/.ssh/id_rsa",
        "chown user:group ./file",
        "truncate -s 0 logfile.txt",
        "mv a b",
        "cp -r src dst",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
