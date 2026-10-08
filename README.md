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
