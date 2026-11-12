#!/usr/bin/env bash
# Guest side of the box base image bake. Runs as root from cloud-init
# (runcmd) on the bake VM; ported from the spike's spike-bake.sh. The host
# attaches the payload disk (LABEL=SAIIFE) with saiife, claude, guest/,
# recipe.env and an empty out/ directory.
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
  # APT_PACKAGES is a space separated list of validated package names
  # shellcheck disable=SC2086
  apt-get install -y --no-install-recommends $APT_PACKAGES
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
      if ! [[ $u =~ ^[A-Za-z0-9@._-]+$ ]]; then
        echo "enable.list: bad unit name" >&2
        return 1
      fi
      systemctl enable "$u"
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

trim() {
  mkdir -p /etc/docker /etc/systemd/journald.conf.d
  # proxy port 3128: source of truth is saiife_boxproto::ports (plan 38)
  cat >/etc/docker/daemon.json <<'JSON'
{"features":{"containerd-snapshotter":false},"proxies":{"http-proxy":"http://127.0.0.1:3128","https-proxy":"http://127.0.0.1:3128","no-proxy":"localhost,127.0.0.0/8"}}
JSON
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

start_docker() {
  systemctl start docker.service
  for _ in $(seq 1 60); do
    docker info >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "dockerd did not come up" >&2
  return 1
}

pull_images() {
  local ref want got
  start_docker
  for ref in $PULL_IMAGES; do
    want=$ref
    docker pull "$ref"
    got=$(docker image inspect --format '{{index .RepoDigests 0}}' "$ref")
    if [ "$got" != "$want" ]; then
      echo "digest mismatch for $ref: got $got" >&2
      return 1
    fi
  done
  systemctl stop docker.service docker.socket
}

export_outputs() {
  local k
  mkdir -p "$MNT/out"
  if [ "$DIRECT_KERNEL" = 1 ]; then
    k=$(ls -1 /boot/vmlinuz-*-kvm | sort -V | tail -n 1)
    cp "$k" "$MNT/out/vmlinuz"
  fi
  dpkg-query -W -f '${Package} ${Version}\n' >"$MNT/out/packages.txt"
}

main() {
  mount_payload
  read_recipe
  install_packages
  install_binaries
  install_guest_units
  install_growroot
  make_agent_user
  trim
  pull_images
  export_outputs
  mkdir -p /etc/cloud
  touch /etc/cloud/cloud-init.disabled
  apt-get clean
  sync
  umount "$MNT"
  fstrim -av || true
  echo SAIIFE-BAKE-OK >"$TTY"
}

main
