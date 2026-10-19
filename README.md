# own-tunnel

Self-hosted SSH tunnel server: expose local HTTP and TCP services through a regular SSH client.

Listens on three ports:

| Port | Default | Role |
|------|---------|------|
| SSH | 22 | Auth, create tunnels (`-R`), consume TCP (`-L`), interactive menu |
| HTTP | 80 | Public HTTP by subdomain |
| HTTPS | 443 | Public HTTPS by subdomain |

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
- Auth throttling (`auth.*`): per-IP lockout after repeated failures (defaults: 5 in 15m → 15m ban)
- Host keys are auto-generated under `host_keys_dir` (default `./host_keys`)

## Logs

Structured logs (`json` or `text`) cover auth, tunnel register/unregister, HTTP requests, and TCP consume connect/disconnect. Secrets are never logged.

## Build

```bash
go build -o own-tunnel ./cmd/own-tunnel
```
