# own-tunnel

Self-hosted SSH tunnel server: expose local HTTP and TCP services through a regular SSH client.

SSH is the primary protocol. When SSH is blocked, the same server can carry SSH over an HTTPS WebSocket on the existing HTTPS port — see [Tunnel over HTTPS/WebSocket](#tunnel-over-httpswebsocket-ot-http).

Listens on three ports:

| Port | Default | Role |
|------|---------|------|
| SSH | 22 | Auth, create tunnels (`-R`), consume TCP (`-L`), interactive menu |
| HTTP | 80 | Public HTTP by subdomain |
| HTTPS | 443 | Public HTTPS by subdomain; optional SSH-over-WebSocket endpoint |

## Quick start

```bash
cp config.example.yaml config.yaml
# Edit domain, users, listen addresses, TLS paths

# Generate a bcrypt password hash
go run ./scripts/hashpassword.go 'secret'

go run ./cmd/own-tunnel -config config.yaml
```

Point DNS at the server:

- `tunnel.example.com` → server A/AAAA
- `*.tunnel.example.com` → server A/AAAA

Supply a wildcard (or SAN) certificate for `*.tunnel.example.com` under `tls.cert` / `tls.key`. Optional per-host certs go under `tls.domains`.

TLS files are re-read automatically when their mtime changes (no process restart needed after a Let's Encrypt renew that overwrites the PEMs in place).

Privileged ports (`22`/`80`/`443`) need root or `CAP_NET_BIND_SERVICE`. The example config uses high ports for local testing.

## Create tunnels (`-R`)

The **bind address** is the tunnel name. Port **80** is HTTP; any other port is TCP.

```bash
# HTTP → http(s)://myapp.tunnel.example.com
ssh -R myapp:80:localhost:3000 alice@tunnel.example.com

# TCP (same name, different port) — not public; SSH-only
ssh -R myapp:5432:localhost:5432 alice@tunnel.example.com

# Several forwards in one connection
ssh -R myapp:80:localhost:3000 -R myapp:5432:localhost:5432 alice@tunnel.example.com

# Auto-generated name when bind address is omitted / localhost
ssh -R 80:localhost:3000 alice@tunnel.example.com
```

Assigned URLs / `name:port` are printed on the SSH session (when a shell/PTY is present) and always written to server logs.

Rules:

- Same name may bind many ports
- At most one HTTP (`:80`) per name
- One SSH connection may register many `-R` forwards
- Disconnecting unregisters that connection’s tunnels

## Consume TCP tunnels (`-L`)

TCP tunnels are **not** exposed as public ports. Any authenticated user who knows `name` and `port` can reach them:

```bash
ssh -L 5432:myapp:5432 bob@tunnel.example.com
# then: psql -h 127.0.0.1 -p 5432 ...
```

`direct-tcpip` only resolves registered tunnel names — the server is not an open TCP proxy.

## Forward SSH (port 22)

Publish a remote SSH server the same way as any other TCP port:

```bash
# Publisher — expose local sshd
ssh -R homelab:22:localhost:22 alice@tunnel.example.com -N
```

Consumers reach it through own-tunnel with OpenSSH **`-W`** (opens a `direct-tcpip` channel). No server changes are required; port 22 uses the same TCP bridge as other non-HTTP ports.

### ProxyCommand (stock OpenSSH)

```bash
ssh -o ProxyCommand='ssh -W homelab:22 bob@tunnel.example.com' admin@homelab
```

Or in `~/.ssh/config`:

```
Host homelab
  ProxyCommand ssh -W homelab:22 bob@tunnel.example.com
  User admin
  HostName homelab
```

Then: `ssh homelab`

Authentication is **two layers**:

| Layer | Server | Typical auth |
|-------|--------|--------------|
| Outer (ProxyCommand) | own-tunnel | your tunnel account (`bob`) |
| Inner (main `ssh`) | forwarded sshd | target account (`admin`) |

The inner session (password or public key) is forwarded unchanged. own-tunnel only authenticates the outer hop.

**Password caveat:** the nested `ssh` inside `ProxyCommand` usually has no TTY, so it often **cannot** prompt for your own-tunnel password. Practical options:

- Use an **SSH key** for the own-tunnel login (recommended).
- Open a **ControlMaster** first on a real TTY, then reuse it (see wrapper below).
- Prompt once yourself: `ssh -M -N -f bob@tunnel.example.com`, then run the ProxyCommand command.

### Helper script (`scripts/ot-ssh`)

Single bash file, **ssh only** as a dependency. Wraps the common `ssh -R` / `-L` / `-W` invocations:

```bash
chmod +x scripts/ot-ssh

# Host only — ssh uses your local username ($USER), same as plain ssh
export OT_HOST=tunnel.example.com

# Or user@host when the tunnel account differs from your local user
export OT_HOST=alice@tunnel.example.com

# Publish
ot-ssh publish http  myapp 3000
ot-ssh publish tcp   myapp 5432 5432
ot-ssh publish ssh   homelab

# Consume TCP (local listener)
ot-ssh forward tcp myapp 5432

# Consume SSH (-W + control socket; password-friendly own-tunnel login)
ot-ssh ssh homelab admin
ot-ssh ssh homelab admin -- ls -la

# Interactive menu
ot-ssh open
```

Per-invocation: `ot-ssh -h alice@tunnel.example.com …` or `-u alice` to override the user from `OT_HOST`.

Global options / environment: `OT_HOST` (hostname or `user@host`), `OT_USER` (optional override), `OT_PORT`, `OT_CONTROL_DIR`, `OT_CONTROL_PERSIST`.

For `ot-ssh ssh`, the script opens (or reuses) a **ControlMaster** to own-tunnel so your tunnel password can be entered on a real TTY once; the proxied session then prompts for the target host separately.

For non-interactive use (cron/CI), use SSH keys for the own-tunnel account. Optional extra dependency: [`sshpass`](https://linux.die.net/man/1/sshpass) if you must script password login — not built in; keys are safer.

## Tunnel over HTTPS/WebSocket (`ot-http`)

Some networks block the SSH protocol or port 22. The server can carry the same SSH protocol over an HTTPS WebSocket on the **existing HTTPS listener** — no extra public port, and no change to accounts, permissions, lockout, or tunnel semantics.

The endpoint is enabled by default:

```yaml
websocket:
  enabled: true
  host: ""            # default: domain (apex), e.g. tunnel.example.com
  path: /ws           # wss://tunnel.example.com/ws
  allow_http: false   # HTTPS only; see the warning below
```

`allow_http: true` makes the endpoint reachable on the plain HTTP listener as well. Use it only for local testing or when a trusted reverse proxy terminates TLS. SSH still encrypts its own authentication and tunnel payload, so this does not expose your password or tunnel data in plaintext; however, TLS protects the WebSocket handshake and metadata and should be kept in production.

The default `host` is the apex domain, so only the `/ws` path on that host is reserved and tunnel names cannot collide with it. If you set `host` to a subdomain (for example `connect.tunnel.example.com`), that name is reserved for the endpoint and a tunnel cannot use it while the endpoint is enabled.

Build the client:

```bash
go build -o ot-http ./cmd/ot-http
```

### Publish and forward

```bash
# Server selection (or use --url / OT_URL)
export OT_HOST=tunnel.example.com
export OT_USER=alice

# HTTP publish → https://myapp.tunnel.example.com
ot-http publish http myapp 3000

# TCP publish, then consume it locally through the WebSocket transport
ot-http publish tcp myapp 5432 5432
ot-http forward tcp myapp 5432

# Publish a local sshd as name:22
ot-http publish ssh homelab

# Consume a published sshd with stock ssh via ProxyCommand
ssh -o ProxyCommand='ot-http proxy homelab' admin@homelab
```

Use `-` as the name (or `auto`) to request an automatically assigned name. The server prints the assigned name and public URL to stderr through a status session; `--quiet` does not suppress that server output:

```bash
ot-http publish http - 3000
```

`ot-http` runs in the foreground and handles one command per process; there is no automatic reconnect yet. Use your service manager or a shell loop to keep a publisher running.

### Full SSH over WebSocket

`connect` is a raw WebSocket byte pipe. Stock OpenSSH runs on top of it, so the interactive menu, `-R`, and `-L` all work exactly as they do over TCP:

```bash
# Interactive menu / stock -R / stock -L
ssh -o ProxyCommand='ot-http connect' alice@tunnel.example.com

# Publish with stock ssh over WebSocket
ssh -o ProxyCommand='ot-http connect' -N \
  -R myapp:80:localhost:3000 alice@tunnel.example.com

# Consume another user's TCP tunnel with stock ssh over WebSocket
ssh -o ProxyCommand='ot-http connect' -N \
  -L 5432:myapp:5432 alice@tunnel.example.com
```

In this mode `ot-http` performs no SSH authentication itself; OpenSSH authenticates directly with the own-tunnel server, so the usual SSH keys, agent, and password prompts apply.

### Client options

| Option | Environment | Meaning |
|--------|-------------|---------|
| `-H`, `--host` | `OT_HOST` | Server host or `user@host` |
| `-u`, `--user` | `OT_USER` | Tunnel login user (default: local `$USER`) |
| `-p`, `--port` | `OT_WS_PORT` (`OT_HTTP_PORT` alias) | HTTPS port (default 443) |
| `--url` | `OT_URL` | Full `http(s)://` or `ws(s)://` URL; takes precedence over host/port |
| `--scheme` | `OT_SCHEME` | `https` (default), `http`, `wss`, or `ws` |
| `--path` | `OT_WS_PATH` | WebSocket path (default `/ws`); used when `--url` has no path (or only `/`) |
| `--key` | — | SSH private key file, repeatable |
| `--no-agent` | — | Do not use `$SSH_AUTH_SOCK` |
| `--no-default-keys` | — | Do not load default `~/.ssh/id_*` keys |
| `--known-hosts` | — | known_hosts file, repeatable (default `~/.ssh/known_hosts`) |
| `--ssh-port` | `OT_SSH_PORT` | SSH port used for nonstandard known_hosts entries (default 22) |
| `--host-key` | `OT_HOST_KEY` | Pin the server host key (`SHA256:...`); mutually exclusive with `--insecure-host-key` |
| `--insecure-host-key` | `OT_INSECURE_HOST_KEY` | Skip SSH host-key verification (testing only) |
| `--insecure-tls` | `OT_INSECURE_TLS` | Skip TLS certificate verification (testing only) |
| `--local-host` | `OT_LOCAL_HOST` | Local target host for `publish` (default `localhost`) |
| `--timeout` | — | WebSocket connect/handshake timeout (default 20s); SSH login has a 2m grace for password prompts |
| `--keepalive` | — | WebSocket ping interval (default 30s; `0` disables) |
| `--quiet` | — | Suppress client status messages; auto-named publishes still show the server's assigned name |
| `-v`, `--verbose` | — | Verbose diagnostics: URLs, loaded/count of auth keys, known_hosts source, channels |

`OT_PORT` belongs to the `ot-ssh` wrapper and is not used by `ot-http`.

### Authentication and host keys

- Login is regular SSH auth against the same `users` list: default keys, `--key`, ssh-agent, then password. Duplicate keys are offered once. Set `OT_PASSWORD` for non-interactive password use; otherwise the prompt is read from `/dev/tty`, so it also works inside `ProxyCommand`.
- If your default `~/.ssh` keys are passphrase-protected and are not useful for own-tunnel, use `--no-default-keys` and/or `--no-agent`. The server defaults to 6 SSH auth attempts (OpenSSH's default), so a few extra agent keys are fine, but a large agent can exhaust the attempts.
- `ot-http` verifies the server's SSH host key against `~/.ssh/known_hosts` using port-22 semantics by default. The WebSocket/HTTPS port is **not** the SSH port, so if your known_hosts entry uses a nonstandard SSH port (for example `[tunnel.example.com]:2222`), pass `--ssh-port 2222`. You can also pin with `--host-key SHA256:...`.
- A host-key mismatch is a hard failure with a possible man-in-the-middle warning; a revoked key is also refused. Neither is treated as an unknown host.
- Host keys are shared by the SSH and WebSocket transports. Get the fingerprint with `ssh-keyscan -p <ssh-port> tunnel.example.com | ssh-keygen -lf -`.
- `connect` delegates authentication and host-key verification to OpenSSH, which checks the host in the `ssh` command line as usual. Its own `--key`, `--known-hosts`, `--ssh-port`, `--host-key`, `--insecure-host-key`, and `--no-agent` flags do not apply.
- On Windows, ssh-agent uses a named pipe and `ot-http` cannot connect to it; use `--no-agent` with an explicit `--key` or password. `ot-http` does not read `~/.ssh/config`.

### Reverse proxy

If own-tunnel sits behind nginx/Caddy/Traefik:

- Forward WebSocket upgrades (`Connection: upgrade`, `Upgrade: websocket`) to the HTTPS listener.
- Preserve the `Host` header: the control host must match `websocket.host` (default: the apex domain).
- Disable response buffering for the endpoint, and use a read timeout long enough for idle tunnels. Keepalive pings default to 30s.
- Terminate TLS at the proxy only if traffic between the proxy and own-tunnel is on a trusted network; `allow_http: true` can then serve the endpoint on the internal HTTP listener.
- Auth lockout is per source IP. Behind a reverse proxy every client appears to come from the proxy, so failures can lock out all WebSocket clients together. Terminate TLS at own-tunnel directly if per-client throttling matters.
- There is no built-in concurrent WebSocket connection cap; apply limits at the reverse proxy or OS if needed.

Close the WebSocket with a normal close frame or let the keepalive detect a dead peer. The server logs the transport as `network=ws`.

## Interactive menu

```bash
ssh alice@tunnel.example.com
```

Commands: `help`, `list`, `blocked` (needs `blocks`), `whoami`, `quit`. `list` shows your tunnels, or everyone's with `peers`.

## Config

See [config.example.yaml](config.example.yaml).

- Users: `password_hash` (bcrypt) and/or `authorized_keys`
- Plaintext passwords are rejected at config load
- Permissions per user (`permissions`): `admin`, `publish` (`-R`), `dial` (`-L`), `peers` (other users' tunnels), `blocks` (view lockouts). Default if omitted: `publish` + `dial` (own tunnels only)
- Auth throttling (`auth.*`): per-IP lockout after repeated failures (defaults: 5 in 15m → 15m ban), and `max_auth_tries: 6` per SSH connection
- The example config contains a bcrypt hash for `password`; replace it before exposing the server
- WebSocket (`websocket.*`): SSH-over-WebSocket endpoint on the existing HTTPS listener, on by default; HTTPS-only unless `allow_http` is set
- Host keys are auto-generated under `host_keys_dir` (default `./host_keys`)

## Logs

Structured logs (`json` or `text`) cover auth, tunnel register/unregister, HTTP requests, and TCP consume connect/disconnect. Secrets are never logged.

## Build

```bash
go build -o own-tunnel ./cmd/own-tunnel
go build -o ot-http ./cmd/ot-http
```
