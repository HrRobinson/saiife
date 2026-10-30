# Fleet install (Linux packages and recipes)

This page is for admins who roll saiife out to many Linux machines. It covers
the `.deb` and `.rpm` packages, an Ansible role and an Intune compliance policy.
They all end in the same place: `saiife system install --fleet`, which sets up
locked mode as described in [Install](install.md#locked-mode-linux).

Supported systems are the same as for locked mode: Ubuntu 22.04+, Debian 12+
and RHEL 9+ (also Rocky and Alma), with systemd running.

## What the package owns

The package owns these paths:

- `/usr/libexec/saiife/saiife`, the staging copy of the binary;
- the directory it is in;
- `/usr/bin/saiife`, a symlink to the staging copy;
- docs under `/usr/share/doc/saiife/`.

It ships nothing under `/opt/saiife`, `/etc`, `/var`, `/run` or
`/usr/share/polkit-1`. `saiife system install` owns all of those. It creates
the users, copies the binary to `/opt/saiife/bin/saiife`, writes the managed
hooks and the unit, and records every path with its SHA-256 in
`installed.toml`. `uninstall` and `doctor` trust that record, so no file has
two owners. The hooks only ever call `/opt/saiife/bin/saiife`.

The package's `postinst` (deb) or `%post` (rpm) runs
`/usr/libexec/saiife/saiife system install --fleet`.

## Fleet files

`--fleet` reads two files in `/etc/saiife/fleet/`. Both are optional. Put them
there before you install the package.

`/etc/saiife/fleet/config.toml` is the system config
([spec 8.1](superpowers/specs/2026-10-19-saiife-v2-design.md)). It must say
`locked = true`:

```toml
version = 2
locked = true

[approval]
approvers = ["group:security"]
```

When it is there, install checks it and copies it to
`/etc/saiife/config.toml` on every run. **The fleet config wins over local
edits.** Change the fleet file, not `/etc/saiife/config.toml`. Without it,
install keeps the current config or writes a commented default.

`/etc/saiife/fleet/install.toml` sets the agents:

```toml
agents = ["claude", "codex", "gemini"]
```

Unknown keys are refused. If `agents` is missing, install uses the agents
recorded in `installed.toml`, so an upgrade never adds an agent you left out.
After a plain `system uninstall` (a package removal), it uses the agents in
the copy that uninstall kept (`/etc/saiife/installed.previous.toml`). With no
record, it uses all three. An empty list means no agent is guarded: install
then prints `saiife: warning: no agents listed: no agent is guarded`, and
`saiife doctor` warns with an `agents` check.

Dropping an agent from `agents` does not remove its managed hooks: install
adds and updates hooks, it never removes them. To stop guarding an agent,
uninstall, then install again with the new list:

```sh
sudo saiife system uninstall
sudo /usr/libexec/saiife/saiife system install --fleet
```

`install.toml` may also set `approvers`, but only without a fleet
`config.toml`: then they go into the commented default config that install
writes when there is none. With a fleet `config.toml`, install refuses
`approvers` in `install.toml` (exit 2, nothing changed), because that file is
copied as it is. Set `[approval] approvers` in `/etc/saiife/fleet/config.toml`
instead, as in the example above.

`--fleet` cannot be combined with `--config`, `--agents` or `--approvers`.

Install refuses (exit 2, nothing changed) unless all of this holds:

- `/etc`, `/etc/saiife` and `/etc/saiife/fleet` are real directories owned by
  root and not writable by group or others. A sticky bit does not excuse this;
- each file is a regular file owned by root, not writable by group or others;
- each file is at most 1 MiB.

`policy.d/*.toml` stays yours. Write `/etc/saiife/policy.d/` directly, then run
`sudo saiife policy reload`. Install checks the fleet config together with the
drop-ins in `/etc/saiife/policy.d/`, the ones the daemon loads, so a config
that conflicts with them is refused before anything changes.

## Exit codes and failures

`system install --fleet` uses the usual install codes:

- 0: installed;
- 1: installed, but `doctor` found a failure (the report is already printed),
  or the running daemon did not take the new config (see below);
- 2: install error or unsupported system.

The maintainer script passes on 0 and 1 and fails on 2. A fleet package exists
to lock, so a silent exit 0 with no lock would be the worst result.

- **deb:** a failing `postinst` leaves the package half-configured until you
  fix the cause and run `sudo dpkg --configure saiife`.
- **rpm:** a failing `%post` prints a scriptlet error, but rpm keeps the
  package installed. Do not trust that install. Check `sudo saiife doctor`.

Either way, run `doctor` after the install. The recipes below do.

When the config changes and the daemon is running, install reloads it
(`systemctl reload saiifed.service`). It restarts the daemon only when the
binary, the unit or the group membership changed.

`systemctl reload` only sends a signal, so install then asks the daemon over
its socket to load the policy again and waits up to 15 s for the answer. On
success it prints `saiife: the daemon reloaded the new config (policy <hash>)`.
If the daemon rejects the config, or does not answer, install exits 1 and its
last lines say so:

```
saiife: error: the daemon did not take the new config (/etc/saiife/config.toml): ...
```

The daemon then still enforces the old policy. Fix the config, then run
`sudo saiife policy reload` or `sudo systemctl restart saiifed`.

A reload cannot change everything. These settings take effect only when the
daemon restarts: `[daemon] user`, `[daemon] socket_dir`, `[gateway] tcp`,
`[audit] dir`, `[audit] checkpoint_every`, `[audit] checkpoint_interval` and
`[audit] fsync`, as well as dropping `locked = true`. The daemon accepts a
reload that changes one of them, keeps running as started, and logs a
`reload_warning` (in the journal and the audit). After changing one, run
`sudo systemctl restart saiifed`.

`doctor` also checks `files.package`. It warns when the staging copy in
`/usr/libexec/saiife/saiife` differs from `/opt/saiife/bin/saiife`, for
example after a package install where `system install` did not finish.

## Upgrades

Install the new package the normal way. dpkg and rpm replace only the staging
copy. The running daemon and the hooks keep using the old
`/opt/saiife/bin/saiife` until the maintainer script runs. Then install
replaces it atomically and restarts `saiifed.service`. The managed hook files
are never removed during an upgrade. While the daemon restarts, the hooks
fail closed.

## Removal

Removing the package uninstalls locked mode. It is never silent. `prerm`
prints this line to stderr and sends it to syslog with
`logger -t saiife -p auth.warning` (when `logger` exists):

```
saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked
```

The daemon's own `stop` record ends the audit chain and is forwarded, if you
set up [forwarding](forwarding.md). There is no removal block: root can remove
anything. Upgrades do not run uninstall.

Removal and purge keep the audit, the vault key, the state, the config and
the users, as `sudo saiife system uninstall` does. The audit is evidence.
For a full wipe, uninstall first, then remove the package:

```sh
sudo saiife system uninstall --purge
sudo apt remove saiife        # or: sudo dnf remove saiife
```

`prerm` then finds nothing to uninstall.

If the uninstall step fails, read its error. Do not assume the machine is
clean, and check that the package state is what you expect. On rpm, a failed
`%preun` stops the removal and keeps the package, but the uninstall may have
gone part of the way (the daemon stopped, some hooks gone). To put locked mode
back after a failed `%preun`, run:

```sh
sudo /usr/libexec/saiife/saiife system install --fleet
```

## Verify packages

A release has these assets:

- two `.deb` files (`saiife_<version>_amd64.deb`, `saiife_<version>_arm64.deb`);
- two `.rpm` files (`saiife-<version>-1.x86_64.rpm`, `saiife-<version>-1.aarch64.rpm`);
- the four static tarballs;
- `SHA256SUMS`, which lists all eight files;
- `SHA256SUMS.asc`, a detached signature of `SHA256SUMS`. It is there only when
  the release was signed.

Download the files you need, plus `SHA256SUMS`, then check:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

To check the signature, import the public key once. The key is
`deploy/keys/saiife-packages.asc` in the repository. Compare its fingerprint
(`<key-id>`) with the one the owner published before you trust it.

```sh
gpg --import saiife-packages.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
```

The `.deb` files carry no signature of their own. apt checks repositories, not
single files, so the signed `SHA256SUMS` is the check. The `.rpm` files are
signed. Import the key into rpm and check one:

```sh
sudo rpm --import saiife-packages.asc
rpm -K saiife-<version>-1.x86_64.rpm
```

`rpm -K` should report the digests and signature as OK. An unsigned rpm (a CI
build) fails the signature check. Run `rpm -K` yourself before you install: a
plain `sudo dnf install ./saiife-<version>-1.x86_64.rpm` does not check the
signature of a local file unless `localpkg_gpgcheck=1` is set in
`/etc/dnf/dnf.conf`. The Ansible role below does check it (unless you set
`saiife_rpm_gpg_check: false`).

## Ansible

The role is in `deploy/ansible/roles/saiife`. The playbook
`deploy/ansible/playbook.yml` targets the inventory group `saiife_fleet`. It
never targets localhost.

An example inventory:

```ini
[saiife_fleet]
dev-01.example.com
dev-02.example.com
```

Variables, for example in `group_vars/saiife_fleet.yml`:

```yaml
saiife_version: "<version>"          # without the leading v
saiife_config_src: /path/on/controller/saiife-config.toml   # locked = true
saiife_agents: [claude, codex, gemini]
saiife_package_sha256:               # from SHA256SUMS, one entry per file
  saiife_<version>_amd64.deb: "<sha256>"
  saiife-<version>-1.x86_64.rpm: "<sha256>"
saiife_rpm_gpg_key_src: https://example.com/saiife-packages.asc
```

Run it on your controller, not on the managed machines:

```sh
ansible-playbook -i inventory deploy/ansible/playbook.yml
```

The approvers go in the config file `saiife_config_src` names (`[approval]
approvers`). The role has no `saiife_approvers`, and fails if you still set it.

The role writes the two fleet files first, then downloads the package for the
host, checks its SHA-256, installs it (so the maintainer script runs
`system install --fleet`) and runs `saiife doctor --json`. When the package is
already in place, it runs `system install --fleet` itself for changed fleet
files, and `saiife policy reload` for changed `policy.d` drop-ins. The play
fails when the daemon did not take a new config, and when `doctor` exits at or
above `saiife_doctor_fail_on` (default 2).

Other variables: `saiife_policy_d_src` (a controller directory of `policy.d`
drop-ins), `saiife_package_base_url` and `saiife_rpm_gpg_check`. On RHEL hosts
`saiife_rpm_gpg_check: true` needs the signing key, so set
`saiife_rpm_gpg_key_src`. An unsigned rpm needs `saiife_rpm_gpg_check: false`.

## Intune Linux

Intune cannot push Linux packages. Pair it with Ansible or another tool that
installs the package. Intune then reports whether each device is compliant.

In the Intune admin center, add a custom compliance policy for Linux:

1. Upload `deploy/intune/linux/discovery.sh` as the discovery script. Intune
   runs it as root. It only reads state: it runs `saiife doctor --json` with the
   output discarded and prints one JSON line with `saiife_installed` and
   `saiife_doctor_exit`.
2. Upload `deploy/intune/linux/rules.json` as the rules file.
3. Assign the policy to a device group.

A device is compliant when `/opt/saiife/bin/saiife` is installed and `doctor`
exits 0 or 1. A `doctor` exit of 2, or a missing install, is non-compliant.

## Limits

- **Containers and image builds.** Locked mode refuses containers and hosts
  without a running systemd. In a chroot or image build, `postinst` fails with
  the refusal line. Install the package at first boot instead, not in the image.
- **rpm test coverage.** CI tests the rpm in a Rocky 9 container. A container
  cannot run locked mode, so that test covers the payload, the modes, the
  scriptlet wiring, the refusal, the upgrade of the staging copy and removal.
  The full flow runs in CI on Ubuntu, for the deb. Try a full rpm install on a
  RHEL 9 VM before you roll out.
- **No apt or yum repository yet.** Install from the release files.
- **Secrets are per machine.** The vault is local. Add secrets on each machine
  with `sudo saiife secret add`.

## macOS (v2.1)

macOS packages, Jamf and Intune for macOS come after plan 13 (macOS locked
mode). This section is filled in then.
