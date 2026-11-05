# Fleet install (packages and recipes)

This page is for admins who roll saiife out to many machines. For Linux it
covers the `.deb` and `.rpm` packages, an Ansible role and an Intune compliance
policy. For macOS, see [macOS (v2.1)](#macos-v21): a `.pkg` with Jamf and Intune
recipes. For Windows, see [Windows](#windows): an MSI with Intune and GPO recipes. They all end in the same place: `saiife system install --fleet`, which
sets up locked mode as described in [Install](install.md#locked-mode-linux).

Supported systems are the same as for locked mode: Ubuntu 22.04+, Debian 12+
and RHEL 9+ (also Rocky and Alma), with systemd running; macOS 15 or later with
System Integrity Protection on.

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
- two `.pkg` files for macOS (`saiife-<version>-arm64.pkg`,
  `saiife-<version>-x86_64.pkg`), when the release has them. See
  [macOS](#macos-v21);
- two `.msi` files for Windows and the two `.intunewin` files built from them
  (`saiife-<version>-x64.msi`, `saiife-<version>-arm64.msi`). See [Windows](#windows);
- `SHA256SUMS`, which lists all of these;
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

### The pkg

A release has one signed and notarized pkg per architecture:

- `saiife-<version>-arm64.pkg` for Apple silicon;
- `saiife-<version>-x86_64.pkg` for Intel.

Send each Mac the one for its chip. There is no universal pkg: `system install`
refuses a universal binary (see
[Signature](install.md#locked-mode-macos)). A release built without the
installer certificate has no pkg at all, and its notes say so. saiife never
publishes an unsigned pkg.

The pkg owns these paths, and ships nothing under `/opt/saiife`, `/etc`, `/var`
or `/Library`:

- `/usr/local/libexec/saiife/saiife`, the staging copy of the binary;
- the directory it is in;
- `/usr/local/bin/saiife`, a symlink to the staging copy.

The pkg's `postinstall` runs
`/usr/local/libexec/saiife/saiife system install --fleet`, the same as on Linux.
[Fleet files](#fleet-files) work the same too. They live at
`/etc/saiife/fleet/`, which macOS resolves through its `/etc` link to
`/private/etc`, and they are `root:wheel`.

**Exit codes.** When install exits 0 or 1, the `postinstall` exits 0. When
install exits 2, the `postinstall` fails too, so `installer` and your MDM report
a failed install, and the payload stays on disk. The reason goes to
`/var/log/install.log` and to syslog (`logger -t saiife -p auth.err`).

What the failure means depends on how far install got, and the message says which.
When install was refused before it changed anything, such as on a Mac with SIP
off, any earlier install is unchanged and keeps locking:

```
saiife: locked mode on macOS needs System Integrity Protection: without it the hardened runtime does not stop library injection (DYLD_INSERT_LIBRARIES). Enable SIP (Recovery: csrutil enable) and run install again.
saiife: install did not complete; any earlier install is unchanged: system install --fleet exited 2: ...
```

When install failed partway, it may be partial. Do not assume locked mode is
active, and run `sudo /opt/saiife/bin/saiife doctor`:

```
saiife: install did not complete and may be partial; do not assume locked mode is active; run /opt/saiife/bin/saiife doctor: system install --fleet exited 2: ...
```

Either way, fix the cause, then install the pkg again.

**The staging path.** SIP does not protect `/usr/local`, and root runs the staging
copy. So before it runs, the `postinstall` and the fleet scripts check
`/usr/local`, `/usr/local/libexec`, `/usr/local/libexec/saiife` and the binary.
Each must be no symlink, owned by root, not writable by group or others, and have
no ACL (an ACL can grant write that the mode bits do not show). Otherwise they exit 2 and name the path, and `doctor` warns in `files.package`:

```
saiife: the staging copy is not safe to run: /usr/local is not owned by root; ...
```

Some Macs have a user-owned `/usr/local`. Make it root's before you install, for
example with `sudo chown root:wheel /usr/local` and `sudo chmod go-w /usr/local`.
Remove an ACL with `sudo chmod -N <path>`.
Check first what else on the Mac needs it to stay as it is. Homebrew on Intel
keeps its files below `/usr/local` and its own dirs can stay the user's: only the
four paths above are checked.

On a target other than the boot volume, the `postinstall` prints
`saiife: not the boot volume; run system install --fleet after boot` and exits
0. Run that command after you boot from the volume. Nothing is locked until then.

**Upgrades.** Install the new pkg. As on Linux, it replaces only the staging
copy, and then install replaces `/opt/saiife/bin/saiife` atomically and restarts
the daemon.

**Reloads.** Where this page says `systemctl`, macOS uses launchd. Restart the
daemon with `sudo launchctl kickstart -k system/com.saiife.saiifed`. A changed
config needs no restart: install asks the daemon to load it and says so, as on
Linux. If the daemon does not take it, read `/var/log/saiife/daemon.log`.

### Removal

A pkg has no removal hook, and Installer has no uninstall. Run
`deploy/jamf/uninstall.sh` as root, from any MDM or by hand. It:

1. prints this line and sends it to syslog with
   `logger -t saiife -p auth.warning`:
   ```
   saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked
   ```
2. runs `/opt/saiife/bin/saiife system uninstall`. If that fails, it stops and
   keeps the staging copy;
3. removes `/usr/local/libexec/saiife` and the symlink;
4. runs `pkgutil --forget com.saiife.pkg`.

It keeps the audit, the vault key, the state, the config and the users, as on
Linux. For a full wipe, run `sudo /opt/saiife/bin/saiife system uninstall --purge`
first. Use that path, not `sudo saiife`: on an Intel Mac with Homebrew, a user owns
`/usr/local/bin` and can replace the `saiife` link there.

### Jamf

Upload the pkgs, then make one policy per chip, scoped to a smart group on the
architecture. In each policy:

1. Add `deploy/jamf/fleet-files.sh` with priority **Before**. Parameter 4 is the
   base64 of your `config.toml` (`base64 -i config.toml`). Parameter 5 is a comma
   list of agents, such as `claude,codex,gemini`. Leave it empty to use the
   agents install already recorded.
2. Add the pkg for that chip.

The script writes `/etc/saiife/fleet/` as `root:wheel`, 0755 and 0644. It refuses
(exit 2) an empty or invalid config or an unknown agent. When the staging copy is
already there, it checks it and runs `system install --fleet`, so running the
script again pushes a changed config.

**Upgrades with a new config.** With priority Before, the script runs first, so
the old staging copy applies the new config, before the pkg replaces that copy. If
the old binary rejects the new config (say it uses a setting only the new version
knows), the script exits 2 and the pkg does not run. To roll out such a config,
first upgrade with the old config, then push the new one.

For reporting, add `deploy/jamf/extension-attribute.sh` as an extension attribute.
It prints `<result>pass</result>`, `warn`, `fail` or `not installed`, from
`doctor`'s exit code.

### Intune for macOS

Intune needs a signed pkg, so take it from a release.

1. Edit `deploy/intune/macos/fleet-files.sh`. Intune scripts take no parameters,
   so set `CONFIG_B64` and `AGENTS` at the top. Treat your copy as you would the
   config itself.
2. Under **Devices > macOS**, add it as a shell script. Set **Run script as
   signed-in user** to **No**.
3. Under **Apps > macOS**, add each pkg as a **macOS app (PKG)**. Assign each one
   to a group of Macs with that chip.
4. Add `deploy/intune/macos/custom-attribute.sh` as a custom attribute, with data
   type string, to report `doctor`'s exit code (`not installed` when there is no
   install).

Intune does not promise that the script runs before the app, and the two can
overlap. An install waits up to 2 minutes for another one (see
[below](#macos-limits)). Once both have run, the fleet config is in place in either
order: the script applies the files if the pkg got there first, and the
`postinstall` applies them otherwise. If the pkg runs first with no fleet files,
install writes the commented default config until the script runs.

**The agents may differ.** If the pkg runs first with no fleet files, install hooks
all three agents. A later `AGENTS=claude` adds nothing and removes no hooks, because
install never removes one. So with a subset of agents, the order matters. To get
just the subset, uninstall, then install again from the fleet files: run
`sudo /opt/saiife/bin/saiife system uninstall`, then install the pkg again.

### macOS limits

- **SIP is required.** A Mac with SIP off fails the pkg install. There is no
  override in a release build.
- **Second account.** Same-user approval is off on macOS, so set approvers in the
  fleet `config.toml`. See
  [Approvals on macOS](install.md#approvals-on-macos-a-second-account).
- **Overlapping installs.** `system install` holds `/etc/saiife-install.lock` (root
  only) while it runs, on Linux too. Another install waits up to 2 minutes, then
  exits 2 and changes nothing. `system uninstall --purge` takes the same lock and
  removes the file.
- **CI coverage.** CI runs the pkg on real macOS runners, which have SIP off, with
  a test build. It checks the staging refusals and the SIP refusal through the real
  `installer`, then runs the `postinstall`'s command by hand with the test seam,
  then `doctor`, the attributes, the Jamf uninstall and a reinstall. A `postinstall`
  that passes, and a signed pkg on a Mac with SIP on, are not covered. Try one Mac
  of each chip before you roll out.
- **`.env*` scan.** Without Full Disk Access, macOS may deny root a user's Desktop,
  Documents, Downloads, iCloud Drive and removable volumes. `doctor` then reports
  the Info check `secrets.incomplete` for what it could not scan. An Info check does
  not change the exit code, so the extension attribute and the custom attribute can
  still say pass. saiife ships no PPPC profile.
- **Syslog.** Long records lose verifiability over `unix:/var/run/syslog`. See
  [Forwarding](forwarding.md#syslog).

## Windows

Locked mode on Windows ships as an MSI, one per architecture
(`saiife-<version>-x64.msi`, `saiife-<version>-arm64.msi`). For Intune each MSI also comes
as an `.intunewin` file (`saiife-<version>-x64.intunewin` and the arm64 twin). They end
in the same place as the other platforms: `saiife system install --fleet`, as described
in [Windows](windows.md).

### What the MSI owns

The MSI is per-machine and installs to `C:\Program Files\saiife`:

- `saiife.exe`, the staging copy of the binary;
- `LICENSE` and `README.md`;
- a system `PATH` entry for that folder.

It owns nothing under `C:\ProgramData`. Its install action runs as SYSTEM, after the
files are in place:

```
"C:\Program Files\saiife\saiife.exe" system install --fleet --package
```

That copies the binary to `C:\ProgramData\saiife\bin`, creates the `saiifed` service,
writes the managed agent files and records all of it in `installed.toml`. With `--package`,
an exit of 1 (installed, but `doctor` found warnings) counts as success, and `doctor`'s
text goes to `C:\ProgramData\saiife\log\install.log`. An exit of 2 fails the action and
the MSI rolls back, so `C:\Program Files\saiife` is gone afterwards. Read the MSI's own
log (`msiexec /i ... /l*v msi.log`) for the reason.

### Fleet files

`--fleet` reads `C:\ProgramData\saiife\etc\fleet\config.toml` and `install.toml`. The
formats are the ones in [Fleet files](#fleet-files). The config must say
`locked = true`. **Write them before the MSI installs.**

On a fresh machine `C:\ProgramData\saiife` does not exist, and a folder made the usual
way would inherit entries from `C:\ProgramData` that let any user write to it. saiife
refuses fleet files in a folder like that, because a user could have planted them. So do
not copy the files in by hand. Use `deploy/intune-windows/fleet-files.ps1`: it creates
`C:\ProgramData\saiife` and `etc` with the permissions saiife expects, then writes the
files. It refuses (exit 2) to write through a junction or a symbolic link, or into a
folder that a user made or can write to. Move such a folder away first.

The script takes `-ConfigB64` (the base64 of `config.toml`) and `-Agents` (for example
`claude,codex,gemini`). Intune runs scripts without parameters, so edit the two defaults
at the top. It must run elevated, in 64-bit PowerShell.

If the MSI runs with no fleet files, install writes the default config, and a later
`fleet-files.ps1` does not apply until the next install. Apply it with:

```powershell
& "C:\Program Files\saiife\saiife.exe" system install --fleet --package
```

### Intune (Windows)

1. Edit `deploy/intune-windows/fleet-files.ps1`: set `$ConfigB64` and `$Agents` in the
   `param` defaults. Treat your copy as you would the config itself.
2. Under **Devices > Windows > Scripts and remediations > Platform scripts**, add it.
   Set **Run this script using the logged on credentials** to **No** and **Run script
   in 64-bit PowerShell Host** to **Yes**.
3. Under **Apps > Windows**, add an app of type **Windows app (Win32)** and upload each
   `.intunewin` file. Use these values:
   - Install command: `msiexec /i "saiife-<version>-x64.msi" /qn` (the file name of that
     package);
   - Uninstall command: `msiexec /x "{product code}" /qn`. The product code is on the app
     once Intune has read the package;
   - Install behavior: **System**; device restart behavior: **No specific action**;
   - Requirements: the architecture of that package;
   - Detection rules: **Use a custom detection script**, upload
     `deploy/intune-windows/detect.ps1`, run it in 64-bit PowerShell, and do not
     enforce a signature check unless you sign your copy.
4. Assign each app to a group of devices with that architecture.
5. For compliance, add a custom compliance policy for Windows: upload
   `deploy/intune-windows/discovery.ps1` as the discovery script and
   `deploy/intune-windows/rules.json` as the rules file. A device is compliant when
   saiife is installed and `doctor` exits 0 or 1.

Intune does not promise that the script runs before the app. If the app comes first,
install writes the default config, and the machine stays on it until the next install
(see above). The agents may differ too: install never removes a managed hook, so
narrowing `Agents` later needs an uninstall first. Run
`& "C:\Program Files\saiife\saiife.exe" system uninstall`, then install again.

### GPO

Group Policy's software installation can assign the MSI to computers, but a computer
startup script may run before or after it, so the fleet files are not sure to be in place.
Use one startup script that does both, in order. Put the MSI and `fleet-files.ps1` on a
share that only administrators can write, and set the policy under **Computer
Configuration > Policies > Windows Settings > Scripts > Startup > PowerShell Scripts**:

```powershell
$share = '\\fileserver\saiife'
& "$share\fleet-files.ps1" -ConfigB64 '<base64>' -Agents 'claude,codex,gemini'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i', "$share\saiife-<version>-x64.msi", '/qn', '/l*v', 'C:\ProgramData\saiife\log\saiife-msi.log'
exit $p.ExitCode
```

The log goes to `C:\ProgramData\saiife\log`, never to `C:\Windows\Temp`: the startup
script runs as SYSTEM, and a user can plant a link in a folder like Temp. The script's
first line already made that folder's parent, because `fleet-files.ps1` creates
`C:\ProgramData\saiife` but not `log`. On a first install `log` does not exist yet, so
`msiexec` cannot open the log and fails. Create it from the script first, with the
permissions saiife expects, or drop `/l*v` on the first run: after the first install the
folder is there. Do not create `log` by hand with `mkdir`, as it would inherit
Users-writable entries and saiife would refuse it.

The startup script runs as SYSTEM, so nobody has to be an administrator on the device. To
change the fleet files, edit the script: every boot writes them and runs the MSI again.
The same version is meant to run the install action again, which is safe to repeat, and
that is what applies the new files. **Unverified:** whether Windows Installer runs a custom
action for `msiexec /i` of the package that is already installed (it may only open
maintenance mode). Test it in your rollout. If it does not run, use `msiexec /fa` (repair
all files) or run `system install --fleet --package` from the script instead. To upgrade, replace the MSI on the share and change
its name in the script.

### Upgrades and removal on Windows

Install a newer MSI the usual way (Intune supersedence, GPO, or `msiexec /i`). The new
version installs first, then the old one is removed without its uninstall action, so the
service is never uninstalled halfway. The install action then restarts the service once,
and managed files whose content did not change keep their bytes. While it restarts, the
hooks fail closed. Same-version reinstalls and repairs (`msiexec /f`) run the same install
action and are safe to repeat.

Uninstalling from **Settings > Apps**, or with `msiexec /x`, runs
`saiife.exe system uninstall` as SYSTEM first, so the service is removed with the files.
It is never silent: the line
`saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked`
is written to the MSI log. As on Linux, removal keeps the audit, the vault key, the
state, the config and the fleet files, because the audit is evidence. For a full wipe,
run `saiife system uninstall --purge` first, then remove the package.

### Windows limits

- **Signing.** A release is signed with Authenticode only when the owner has set the
  signing secrets. Without them the MSIs are unsigned, and the release notes say so.
  Windows then shows an unknown publisher, and some policies (AppLocker, WDAC) refuse the
  MSI.
- **Versions.** An MSI version is `major.minor.patch`. A prerelease suffix such as `-rc1`
  is dropped, so `0.4.0-rc1` and `0.4.0` look equal to Windows Installer, and the final
  release does not upgrade the candidate. Uninstall the candidate first; that keeps the
  audit and the config.
- **Install folder.** The folder is fixed at `C:\Program Files\saiife`. It is not a
  property you can set: the install and uninstall actions run as SYSTEM and start
  `[ProgramFiles64Folder]saiife\saiife.exe`, so a folder chosen on the command line cannot
  make them run another binary.
- **Preview.** Windows locked mode is a preview. See [Windows](windows.md). Every lock
  label there is unverified until it has been tried on real machines. The Codex and
  Gemini CLI hooks are preview on Windows too. Same-user approval is off, by the owner's
  ruling, so approvals come from a second account in a separate session. Set approvers in
  the fleet `config.toml`.
- **Rollback.** The MSI rolls back its files when the install action fails, but it does
  not undo what `system install` already did (the service, the managed files). Run
  `saiife system uninstall` from the daemon's copy,
  `C:\ProgramData\saiife\bin\saiife.exe`, to clean up, then fix the cause and install again.
- **CI coverage.** CI builds the MSI on a `windows-2025` runner and runs a refused fleet
  file, install, upgrade, removal, `detect.ps1` and the `.intunewin` header. A signed MSI
  and a real Intune or GPO rollout are not covered. Try one machine of each architecture
  before you roll out.
