# Egress recipe for dedicated agent accounts

Locked mode stops the agent from holding credentials for brokered services,
but it does not stop an agent from sending data to a host of its choosing.
On a dedicated agent account you can close most of that gap with a few
`nftables` rules that drop outbound traffic for the agent's uid, except to
the model provider (or a local model server) and DNS.

This page is a recipe, not a feature: saiife does not install or manage
these rules. `saiife doctor` only tells you, as an `info` line, when a
dedicated account has no rule set called `saiife_egress` (see
[Doctor](#doctor-hint)).

It fits the recommended setup: the agent runs as its own account (for
example `agent-shop`) with no login shell, and brokered traffic leaves from
the saiife daemon. See [threats](threats.md) for what this does and
does not cover.

## Why it works

- The rules match the agent account by uid (`meta skuid`). Nobody else on
  the machine is affected.
- All brokered traffic (Shopify, HubSpot, GitHub, your own APIs, forwarding)
  leaves as the daemon user `saiife`, not as the agent. Connectors keep
  working with the agent blocked.
- The agent talks to the daemon over a Unix socket (and, if you enabled it,
  a loopback TCP listener). Unix sockets are not filtered by `nftables`;
  the loopback rule below keeps the TCP listener working.
- The agent still needs its model provider, or a local model, and DNS.

What it does not stop: data sent to the addresses you allow (the model
provider can receive anything the agent puts in a prompt), data sent through
a host you allowed that relays elsewhere, and anything a root attacker does.
It is a net around the agent account, not a general firewall.

## The rule set

Save as `/etc/nftables.d/saiife-egress.nft` (or into your distribution's
nftables configuration), replacing the user name, resolver and provider
addresses with your own.

```nft
# /etc/nftables.d/saiife-egress.nft
table inet saiife_egress {
    # Addresses of the model provider. Look them up and keep them current
    # (see "Keeping the provider set current").
    set provider4 {
        type ipv4_addr
        flags interval
        elements = { 203.0.113.0/24 }
    }
    set provider6 {
        type ipv6_addr
        flags interval
        elements = { 2001:db8:100::/48 }
    }
    # Your DNS resolvers (the addresses in /etc/resolv.conf, or the local
    # stub resolver on 127.0.0.53, which the loopback rule already covers).
    set resolvers4 {
        type ipv4_addr
        elements = { 192.0.2.53 }
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Only the agent account is restricted.
        meta skuid != "agent-shop" return

        # Loopback: the local model server (for example Ollama on 11434),
        # the stub resolver, and saiife's optional TCP gateway listener.
        oifname "lo" accept

        # Replies to connections that are already allowed.
        ct state established,related accept

        # DNS.
        ip daddr @resolvers4 udp dport 53 accept
        ip daddr @resolvers4 tcp dport 53 accept

        # The model provider, HTTPS only.
        ip  daddr @provider4 tcp dport 443 accept
        ip6 daddr @provider6 tcp dport 443 accept

        # Everything else from the agent account is dropped and counted.
        counter log prefix "saiife-egress-drop " drop
    }
}
```

Notes on the rules:

- `meta skuid != "agent-shop" return` is the only place the account is named.
  A `return` in a base chain with `policy accept` lets the packet through
  for everyone else. To cover several dedicated accounts use a set:
  `meta skuid != { "agent-shop", "agent-crm" } return`.
- The daemon runs as the user `saiife` and is never matched, so you do not
  need a rule for it. If you run the daemon under another account name,
  nothing changes: only the uids you list are restricted.
- With a **local model** (Ollama, vLLM) on the same machine, the loopback
  rule is all you need and you can delete the provider sets. For a model
  server on another host, replace the provider sets with its address and
  port.
- If the agent needs package registries or git hosts in the dedicated
  account, add them as sets the same way. Each one is a hole, so keep the
  list short. Anything the agent can reach, it can send data to.
- If your resolver is on `127.0.0.53` (systemd-resolved), the loopback rule
  covers DNS and the `resolvers4` set can stay empty or be removed.

## Loading it

Check the file first, then load it as root:

```sh
nft -c -f /etc/nftables.d/saiife-egress.nft    # syntax check only
nft -f /etc/nftables.d/saiife-egress.nft
nft list tables                                # should list: table inet saiife_egress
```

To keep it across reboots, include the file from `/etc/nftables.conf` (or
your distribution's equivalent) and enable the `nftables` service. The table
must keep the name `saiife_egress`, because that is what `saiife doctor`
looks for.

Test as the agent account: a request to the provider works, a request to an
unrelated host fails, and a brokered call still works:

```sh
sudo -u agent-shop curl -sS --max-time 5 https://example.org   # should fail
sudo -u agent-shop saiife api --list                           # should work
```

The dropped packets are counted and logged with the prefix
`saiife-egress-drop `, which helps when something legitimate is blocked.

## Keeping the provider set current

Model providers publish address ranges, or sit behind a CDN whose addresses
change. A rule set with stale addresses blocks the agent, which fails
safe but stops work. Refresh the sets from the provider's published ranges
(a timer that runs `nft` with a small script, or a config management run),
and rely on `ct state established` so open connections are not cut. If the
provider offers no stable ranges, run the agent against a local model or a
gateway you control and allow only that address.

## macOS

macOS has no per-uid firewall in `pf` that we can rely on, so there is no
recipe for it, and the doctor hint is Linux only. On a Mac the exfiltration
row of the [threat table](threats.md) stays "not covered". Locked mode itself
is Linux-only in v2.0 (macOS follows in v2.1).

## Doctor hint

For each scope user that is a dedicated account, `saiife doctor` (as root)
looks for a table named `saiife_egress` with `nft list tables`. A dedicated
account is one with no login shell (`nologin` or `false`), or one listed in
the optional `[doctor] dedicated_accounts` of `/etc/saiife/config.toml`:

```toml
[doctor]
dedicated_accounts = ["agent-shop"]
```

The check is `user.<name>.egress`. A missing table is `info`, never a failure; pass
means only that the table exists, not that its rules are right. Doctor only
runs `nft` when the binary exists and is owned by root, and not at all when
run as a normal user.
