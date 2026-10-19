# Install saiife

saiife is one file. It makes no network calls. Only `install.sh` downloads anything.

## Quick install

```sh
curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | sh
```

The script downloads the right build for your machine. It checks the SHA-256 checksum
and stops if it does not match. It installs `saiife` to `~/.local/bin`.
Make sure that folder is on your `PATH`.

Then check it works:

```sh
saiife --version
```

## Pin a version

Set `SAIIFE_VERSION` to install a specific release:

```sh
curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | SAIIFE_VERSION=0.1.0 sh
```

To use another folder, set `SAIIFE_INSTALL_DIR`.

## Install for all users

Pass `--system` to install to `/usr/local/bin`. This needs `sudo`.

```sh
curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | sh -s -- --system
```

## Manual install

If you do not want to pipe a script into your shell:

1. Open the [releases page](https://github.com/HrRobinson/saiife/releases).
2. Download the tarball for your platform and the `SHA256SUMS` file.
3. Check the checksum. Run this in the folder with both files:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

   On macOS, use `shasum -a 256 -c --ignore-missing SHA256SUMS`.
4. Extract it and copy the binary to a folder on your `PATH`:

   ```sh
   tar xzf saiife-0.1.0-x86_64-unknown-linux-musl.tar.gz
   cp saiife-0.1.0-x86_64-unknown-linux-musl/saiife ~/.local/bin/
   ```

## Supported platforms

| Platform | Target |
|---|---|
| Linux, Intel/AMD 64-bit | `x86_64-unknown-linux-musl` |
| Linux, ARM 64-bit | `aarch64-unknown-linux-musl` |
| macOS, Intel | `x86_64-apple-darwin` |
| macOS, Apple silicon | `aarch64-apple-darwin` |

Windows is not supported.

## Build from source

You need Rust installed. From a clone of the repository:

```sh
cargo install --path crates/cli
```

This puts `saiife` in `~/.cargo/bin`.

## Uninstall

1. In each project where you ran `saiife init`, run `saiife init --off`.
   This removes the hooks from your agent settings.
2. Delete the binary, for example `rm ~/.local/bin/saiife`.
3. Optional: delete saiife's data. It holds the integrity records and the audit log.
   If `SAIIFE_DATA_DIR` is set to an absolute path, that folder is used.
   Otherwise the default is:
   - Linux: `~/.local/share/saiife`
   - macOS: `~/Library/Application Support/saiife`

   The audit log is in the `audit` folder inside it, unless `SAIIFE_AUDIT_DIR` is set.
   The log is your record of what the agents did. Keep it if you may need it.
4. Optional: delete the `.saiife` folder in each project.

## Network use

saiife makes no network calls. Only `install.sh` downloads files, and only when you run it.
