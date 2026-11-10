# Dev environments (preview)

`saiife dev` starts any Docker Compose repo behind one local HTTPS proxy, with
a name like `https://web.shop.localhost` for each service. It does not edit
the repo: saiife reads the compose file, writes its own copy under its state
directory, and runs that copy.

This is a preview. See [Limits](#limits).

## Quick start

In a folder with a compose file:

```
saiife dev up
```

It prints one URL per service that has a port, for example
`https://web.shop.localhost`. Run `saiife dev ca` once to see where the local
CA certificate is and how to trust it, so browsers accept the URLs without a
warning. When you are done, `saiife dev down shop`.

## Names

- A service is reachable at `<service>.<project>.localhost`. The apex
  `<project>.localhost` is routed too, for the project's first routed service.
- The project name is the folder name, lowercased, with anything that is not a
  letter, digit or `-` turned into `-`, and cut to 40 characters.
- A second folder with the same name becomes `shop-2`, then `shop-3`. A folder
  keeps its name between runs.
- A service with no port has no URL. `up` lists it as "Not routed". Set a port
  for it in the [quirks file](#quirks).
- Traefik route names are `<project>_<label>`, and `<project>__apex` for the
  apex host.

## HTTPS and the local CA

saiife makes its own certificate authority the first time it needs one. It
lives under `$XDG_STATE_HOME/saiife/dev` (by default
`~/.local/state/saiife/dev`), in the `ca` folder. Each project gets a leaf
certificate in `tls/<project>/` in the same state directory. saiife never
writes a trust store: you decide whether to trust the CA, and you do it
yourself. `saiife dev ca` prints the path and the steps for your OS. All three:

Linux:

```
Debian, Ubuntu:   sudo cp <cert> /usr/local/share/ca-certificates/saiife-dev.crt && sudo update-ca-certificates
Fedora, Arch:     sudo trust anchor --store <cert>
Chrome, Chromium: certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n saiife-dev -i <cert>
Firefox:          Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
```

macOS:

```
System:           sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <cert>
Firefox:          Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
```

Windows:

```
Current user:     certutil -user -addstore Root <cert>
Firefox:          Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
```

Node and Python keep their own lists: set `NODE_EXTRA_CA_CERTS`,
`SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` to the certificate path.

Keep the CA key (`ca-key.pem`) private: anyone who has it can make
certificates that this machine trusts. To stop trusting the CA, remove it the
same way you added it and delete the `ca` folder.

What the CA can sign is limited, as a second line of defence:

- DNS names only under `localhost` (so `*.localhost`);
- no IPv4 or IPv6 addresses at all;
- email names only under `.invalid`.

The honest limit: the certificate library cannot constrain URI names, so the
CA has no limit there. Browsers do not match a site against a URI name, but a
client that does is not held back by the CA. The key's file mode (`0600`) and
keeping it out of reach are the real protection.

The proxy reads only `proxy/dynamic` and `tls` from the state directory, both
read-only. It never gets the Docker socket or the CA.

## Quirks

When saiife guesses wrong, say so in
`~/.config/saiife/dev/<project>.toml` (under `$XDG_CONFIG_HOME` if set). The
file lives in your config, never in the repo, and saiife never writes it.

Under `[services.<name>]` there are four keys:

- `port`: the port the service listens on inside its container;
- `scheme`: `http` or `https` (the service speaks TLS itself);
- `skip`: `true` leaves the service unrouted;
- `host`: the label to use instead of the service name.

```toml
[services.web]
port = 3000

[services.admin]
scheme = "https"
host = "console"

[services.cache]
skip = true
```

An unknown key, a bad port or a bad scheme is an error that names the service.

## Commands

### `saiife dev up [DIR]`

Starts the compose project in `DIR` (default: the current folder) behind the
proxy, and prints the URLs. It starts the shared proxy and network if they are
not running, issues the CA and project certificate if needed, strips every
host port from the compose model (so a stack cannot collide with another one),
and brings the stack up. The first run also prints a line about trusting the
CA.

### `saiife dev ls [--json]`

Lists every project with its state, last start, folder and URLs, then the
proxy. `--json` prints the same as JSON. It exits 1 when Docker did not answer.

| Containers of the project | Folder exists | State |
|---|---|---|
| all running (at least 1) | any | `running` |
| some running | any | `partial` |
| none running, or none at all | yes | `stopped` |
| none running, or none at all | no, or no saved state | `missing` |
| `docker ps` failed | any | `unknown` |

Paused, restarting and created containers count as not running.

### `saiife dev down <PROJECT> [--volumes] [--yes]`

Stops and removes the project's containers and networks, removes its routes,
and stops the proxy if no project is left running. It keeps the project's
saved state, so `ls` shows it as `stopped` and a later `up` keeps the name.

- `--volumes`: also delete the project's volumes (the ones saiife labelled).
  It asks first. Anonymous volumes are not touched.
- `--yes`: answer yes to that question. Needed in a script, which has no
  terminal.

`down` refuses, and touches nothing, if the compose project holds containers
that saiife did not create.

### `saiife dev gc [--volumes] [--yes]`

Cleans up what is left over: containers of stopped projects, route files with
no project, and unused saiife networks.

- A stopped project keeps its saved state while its folder exists, so its name
  and URLs stay the same. A project whose folder is gone loses its state too.
- Running and partial projects are kept and named.
- `--volumes`: also delete saiife's unused (dangling) labelled volumes, after a
  yes. Without it, `gc` says how many volumes it kept.
- `--yes`: answer yes. Without a terminal, `--volumes` with no `--yes` is an
  error and nothing is removed.

`gc` always ends with this line: "Dangling images are not touched: saiife
removes only what it labelled saiife.managed=true. docker image prune removes
them."

### `saiife dev ca`

Creates the CA if it is missing, prints where the certificate is, and prints
the steps to trust it on this OS. It works without Docker.

## Cleanup and labels

Everything saiife creates carries `saiife.managed=true`, and everything that
belongs to a project also carries `saiife.dev.project=<project>`. The shared
network and the proxy carry `saiife.managed=true` and a role label, and no
project label.

Cleanup selects only by those labels, and always from a listing it has just
made. It never removes a container, network or volume that saiife did not
label. Volumes are deleted only after a yes, or with `--yes`.

saiife does not touch dangling images or anonymous volumes. If you want them
gone, that is `docker image prune` and `docker volume prune`.

## Limits

- Preview. Linux comes first. The macOS and Windows builds compile, but they
  are untested against Docker.
- Docker Compose v2, version 2.0.0 or later.
- Only compose files in the folder itself are read: `compose.yaml`,
  `compose.yml`, `docker-compose.yml` or `docker-compose.yaml`, plus one
  `compose.override.*` or `docker-compose.override.*`. There is no search in
  parent folders. `COMPOSE_FILE`, from the environment or from `.env`, is
  ignored.
- Every host port in the compose file is stripped. The stack is reached
  through the proxy only.
- Ports 80 and 443 on 127.0.0.1 must be free. The proxy listens on 127.0.0.1
  only; LAN access (for a phone) is a later opt-in. It restarts with Docker
  (`--restart unless-stopped`) and is removed with the last project. Rootless
  Docker needs `net.ipv4.ip_unprivileged_port_start` set to 80 or lower.
- The CA's limits are listed under [HTTPS and the local CA](#https-and-the-local-ca):
  URI names cannot be constrained.
- This is not a security boundary. The stack runs with your own Docker, and
  membership of the `docker` group is root on the host.
- `ls` shows no disk use, because measuring it is slow.
- `compose.json` under the state directory holds the compose model with
  values from `.env`. saiife keeps it at mode `0600` in a `0700` folder, and
  the proxy never sees it.
