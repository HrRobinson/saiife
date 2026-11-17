#!/usr/bin/env bash
# Guest side of the box base image bake. Runs as root from cloud-init
# (runcmd) on the bake VM; ported from the spike's spike-bake.sh. The host
# attaches the payload disk (LABEL=SAIIFE) with saiife, claude,
# claude-managed-settings.json, guest/, recipe.env, git's saiife-ssh,
# saiife-ssh-config and saiife-gitconfig, and an empty out/
# directory, plus the optional agent files of plan 42 (codex.tar.gz,
# gemini.zip, node.tar.xz and their configs).
set -euxo pipefail

TTY=/dev/ttyS0
MNT=/mnt/saiife

APT_PACKAGES=""
PULL_IMAGES=""
DIRECT_KERNEL=0

mount_payload() {
  mkdir -p "$MNT"
  mount LABEL=SAIIFE "$MNT"
}

# recipe.env holds three KEY=value lines checked on the host. It is parsed
# line by line and never sourced or evaluated.
read_recipe() {
  local k v
  while IFS='=' read -r k v; do
    case $k in
      APT_PACKAGES) APT_PACKAGES=$v ;;
      PULL_IMAGES) PULL_IMAGES=$v ;;
      DIRECT_KERNEL) DIRECT_KERNEL=$v ;;
      '') ;;
      *)
        echo "recipe.env: unknown key" >&2
        return 1
        ;;
    esac
  done <"$MNT/recipe.env"
  case $DIRECT_KERNEL in 0 | 1) ;; *)
    echo "recipe.env: bad DIRECT_KERNEL" >&2
    return 1
    ;;
  esac
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # APT_PACKAGES is a space separated list of validated package names;
  # globbing is off so nothing expands as root
  local pkgs
  set -f
  read -ra pkgs <<<"$APT_PACKAGES"
  set +f
  apt-get install -y --no-install-recommends "${pkgs[@]}"
}

install_binaries() {
  install -m 0755 "$MNT/saiife" /usr/local/bin/saiife
  install -m 0755 "$MNT/claude" /usr/local/bin/claude
}

# Guest units and enable.list come from plan 38; both may be absent.
install_guest_units() {
  local f u
  if [ -d "$MNT/guest/units" ]; then
    for f in "$MNT"/guest/units/*; do
      [ -f "$f" ] || continue
      install -m 0644 "$f" /etc/systemd/system/
    done
  fi
  systemctl daemon-reload || true
  if [ -f "$MNT/guest/enable.list" ]; then
    while IFS= read -r u || [ -n "$u" ]; do
      [ -n "$u" ] || continue
      case $u in \#*) continue ;; esac
      if ! [[ $u =~ ^[A-Za-z0-9][A-Za-z0-9@._-]*$ ]]; then
        echo "enable.list: bad unit name" >&2
        return 1
      fi
      systemctl enable -- "$u"
    done <"$MNT/guest/enable.list"
  fi
}

install_growroot() {
  cat >/etc/systemd/system/saiife-growroot.service <<'UNIT'
[Unit]
Description=Grow the root partition and filesystem to the disk
After=systemd-remount-fs.service

[Service]
Type=oneshot
ExecStart=-/usr/bin/growpart /dev/vda 1
ExecStart=/usr/sbin/resize2fs /dev/vda1

[Install]
WantedBy=multi-user.target
UNIT
  systemctl enable saiife-growroot.service
}

make_agent_user() {
  if ! id agent >/dev/null 2>&1; then
    # the cloud image may carry an ubuntu user on uid 1000: free it first
    if getent passwd 1000 >/dev/null; then
      userdel -r "$(getent passwd 1000 | cut -d: -f1)" || true
    fi
    useradd -m -u 1000 -G docker,sudo -s /bin/bash agent
  fi
  printf 'agent ALL=(ALL) NOPASSWD:ALL\n' >/etc/sudoers.d/agent
  chmod 0440 /etc/sudoers.d/agent
  visudo -cf /etc/sudoers.d/agent
  mkdir -p /work
  grep -q '^LABEL=repo ' /etc/fstab ||
    printf 'LABEL=repo /work ext4 defaults,nofail,x-systemd.device-timeout=5s 0 2\n' >>/etc/fstab
}

# Codex (plan 42 D10, R7): the release tarball holds exactly one file, the
# static musl binary. The archive is only unpacked, never sourced.
install_codex() {
  local tmp n bin th
  tmp=$(mktemp -d)
  tar -xzf "$MNT/codex.tar.gz" -C "$tmp" --no-same-owner --no-same-permissions
  n=$(find "$tmp" -mindepth 1 -printf x | wc -c)
  bin="$tmp/codex-x86_64-unknown-linux-musl"
  if [ "$n" != 1 ] || [ -L "$bin" ] || [ ! -f "$bin" ]; then
    echo "codex.tar.gz: want exactly one regular file codex-x86_64-unknown-linux-musl" >&2
    return 1
  fi
  install -o root -g root -m 0755 "$bin" "/usr/local/bin/codex"
  rm -rf -- "$tmp"
  install -d -o root -g root -m 0755 "/etc/codex"
  install -o root -g root -m 0644 "$MNT/codex-requirements.toml" "/etc/codex/requirements.toml"
  # the managed config layer: the model host and /work untrusted (FU2)
  install -o root -g root -m 0644 "$MNT/codex-managed-config.toml" "/etc/codex/managed_config.toml"
  # a throwaway HOME: the probe must not leave /root/.codex behind
  th=$(mktemp -d)
  HOME="$th" "/usr/local/bin/codex" --version
  rm -rf -- "$th"
}

# Gemini CLI (plan 42 D10, R9, R11, R14) on its own Node.js. The zip is
# unpacked with Python's zipfile (members are kept under the target dir),
# never run by the shell; one gemini.js at its root or in bundle/.
install_gemini() {
  local js c n tmp th
  if [ ! -f "$MNT/gemini.zip" ] || [ ! -f "$MNT/node.tar.xz" ]; then
    echo "gemini needs both gemini.zip and node.tar.xz" >&2
    return 1
  fi
  install -d -o root -g root -m 0755 "/opt/saiife-node"
  tar -xJf "$MNT/node.tar.xz" -C "/opt/saiife-node" --strip-components=1 --no-same-owner --no-same-permissions
  install -d -o root -g root -m 0755 "/opt/gemini-cli"
  python3 -I -m zipfile -e "$MNT/gemini.zip" "/opt/gemini-cli"
  n=0
  js=
  for c in "/opt/gemini-cli/gemini.js" "/opt/gemini-cli/bundle/gemini.js"; do
    if [ -f "$c" ] && [ ! -L "$c" ]; then
      js=$c
      n=$((n + 1))
    fi
  done
  if [ "$n" != 1 ]; then
    echo "gemini.zip: want exactly one gemini.js at its root or in bundle/" >&2
    return 1
  fi
  tmp=$(mktemp)
  printf '#!/bin/sh\nexec /opt/saiife-node/bin/node %s "$@"\n' "$js" >"$tmp"
  install -o root -g root -m 0755 "$tmp" "/usr/local/bin/gemini"
  rm -f -- "$tmp"
  # the managed system settings: the repo's settings never reach the hooks
  install -d -o root -g root -m 0755 "/etc/gemini-cli"
  install -o root -g root -m 0644 "$MNT/gemini-system-settings.json" "/etc/gemini-cli/settings.json"
  # the baked home: the agent may add files to .gemini (sticky), never
  # replace saiife's
  install -d -o root -g root -m 0755 "/opt/saiife-gemini-home"
  install -d -o root -g agent -m 1775 "/opt/saiife-gemini-home/.gemini"
  install -o root -g root -m 0644 "$MNT/gemini-user-settings.json" "/opt/saiife-gemini-home/.gemini/settings.json"
  install -o root -g root -m 0644 /dev/null "/opt/saiife-gemini-home/.gemini/.env"
  install -d -o root -g root -m 0755 "/opt/saiife-gemini-home/.gemini/extensions"
  # a throwaway HOME: the probe must not leave /root/.gemini behind
  th=$(mktemp -d)
  HOME="$th" "/usr/local/bin/gemini" --version
  rm -rf -- "$th"
}

# Every agent's git (COORD-7): every agent's launch env names
# /etc/saiife/gitconfig as git's global config (GIT_CONFIG_NOSYSTEM=1, so no
# /etc/gitconfig is read or baked) and forces its keys, and the forced
# core.sshCommand is this ssh wrapper, which reads only saiife's ssh config.
# Always, whatever agents the payload holds: every agent depends on them.
install_saiife_git() {
  install -d -o root -g root -m 0755 "/usr/local/libexec"
  install -o root -g root -m 0755 "$MNT/saiife-ssh" "/usr/local/libexec/saiife-ssh"
  install -d -o root -g root -m 0755 "/etc/ssh"
  install -o root -g root -m 0644 "$MNT/saiife-ssh-config" "/etc/ssh/saiife_ssh_config"
  install -d -o root -g root -m 0755 "/etc/saiife"
  install -o root -g root -m 0644 "$MNT/saiife-gitconfig" "/etc/saiife/gitconfig"
}

# Claude Code (FU2): its managed settings hold saiife's hooks and win over
# every user, project and --settings value. Always: claude is always baked.
install_claude_managed() {
  install -d -o root -g root -m 0755 "/etc/claude-code"
  install -o root -g root -m 0644 "$MNT/claude-managed-settings.json" "/etc/claude-code/managed-settings.json"
}

# git's files and Claude Code always; the others only for the payload files
# present: recipe.env does not say.
install_agents() {
  install_saiife_git
  install_claude_managed
  if [ -f "$MNT/codex.tar.gz" ]; then
    install_codex
  fi
  if [ -f "$MNT/gemini.zip" ] || [ -f "$MNT/node.tar.xz" ]; then
    install_gemini
  fi
}

trim() {
  mkdir -p /etc/systemd/journald.conf.d
  printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=32M\n' \
    >/etc/systemd/journald.conf.d/saiife.conf
  # mask works on units that are not installed
  systemctl mask multipathd apport rsyslog udisks2 polkit grub-common \
    ubuntu-fan setvtrgb snapd.service snapd.socket snapd.seeded.service \
    systemd-networkd-wait-online.service apt-daily.timer \
    apt-daily-upgrade.timer unattended-upgrades.service
  systemctl set-default multi-user.target
  systemctl disable containerd.service docker.service
  systemctl enable docker.socket
}

# Before the first Docker start: the classic image store only, so pulled
# images land where the box runtime looks.
write_docker_store_config() {
  mkdir -p /etc/docker
  printf '%s\n' '{"features":{"containerd-snapshotter":false}}' >/etc/docker/daemon.json
}

# Written after the pulls (final I6 content): the bake VM pulls directly,
# and the proxy only exists in a running box.
write_docker_config() {
  mkdir -p /etc/docker
  # proxy port 3128: source of truth is saiife_boxproto::ports (plan 38)
  cat >/etc/docker/daemon.json <<'JSON'
{"features":{"containerd-snapshotter":false},"proxies":{"http-proxy":"http://127.0.0.1:3128","https-proxy":"http://127.0.0.1:3128","no-proxy":"localhost,127.0.0.0/8"}}
JSON
}

start_docker() {
  # restart: the docker.io postinst may already have started dockerd with
  # the default image store, before daemon.json was written
  systemctl restart docker.service
  for _ in $(seq 1 60); do
    docker info >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "dockerd did not come up" >&2
  return 1
}

pull_images() {
  local ref want got imgs found
  start_docker
  set -f
  read -ra imgs <<<"$PULL_IMAGES"
  set +f
  for ref in "${imgs[@]}"; do
    want=${ref#*@}
    docker pull "$ref"
    found=0
    while IFS= read -r got; do
      [ "${got#*@}" = "$want" ] && found=1
    done < <(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref")
    if [ "$found" != 1 ]; then
      echo "digest mismatch for $ref" >&2
      return 1
    fi
  done
  systemctl stop docker.service docker.socket
}

export_outputs() {
  local k
  mkdir -p "$MNT/out"
  if [ "$DIRECT_KERNEL" = 1 ]; then
    # only the direct-boot image carries the -kvm flavour: on a firmware
    # boot grub would otherwise pick it over the generic kernel
    apt-get install -y --no-install-recommends linux-image-kvm
    k=$(ls -1 /boot/vmlinuz-*-kvm | sort -V | tail -n 1)
    cp "$k" "$MNT/out/vmlinuz"
  fi
  dpkg-query -W -f '${Package} ${Version}\n' >"$MNT/out/packages.txt"
}

# Every box boots from this image: drop what identifies the bake VM.
# Runs after Docker is stopped.
generalise() {
  if command -v cloud-init >/dev/null 2>&1; then
    cloud-init clean --logs --seed
  fi
  truncate -s 0 /etc/machine-id
  rm -f /var/lib/dbus/machine-id
  mkdir -p /var/lib/dbus
  ln -s /etc/machine-id /var/lib/dbus/machine-id
  rm -f /etc/ssh/ssh_host_*
  # no inbound use for sshd in a box
  systemctl mask ssh.service ssh.socket
  rm -f /var/lib/docker/engine-id
}

main() {
  mount_payload
  read_recipe
  install_packages
  install_binaries
  install_guest_units
  install_growroot
  make_agent_user
  install_agents
  trim
  write_docker_store_config
  pull_images
  write_docker_config
  export_outputs
  generalise
  mkdir -p /etc/cloud
  touch /etc/cloud/cloud-init.disabled
  apt-get clean
  sync
  umount "$MNT"
  fstrim -av || true
  echo SAIIFE-BAKE-OK >"$TTY"
}

main
