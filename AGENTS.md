# AGENTS.md — own-tunnel

Notes for agents working on this repo.

## Purpose

Single-process Go SSH tunnel server (ngrok-like) using stock OpenSSH clients:

- **Create** tunnels with `ssh -R [name:]port:localhost:localport`
- **Consume** TCP tunnels with `ssh -L localport:name:port` only (no public TCP ports)
- **HTTP** when remote port is `80` → `{name}.{domain}` on shared `:80` / `:443`
- **TCP** for any other remote port → registry only, reached via `-L`
- Interactive shell menu only when the client opens a session **without** `-R` (`help`, `list`, `quit`)
- With `-R`: print tunnel info (including auto-assigned names), hold the session (no menu). On bind conflict: print error and disconnect.
- With `-L`: on first use, print status; if `name:port` is missing, print error and disconnect.
- **HTTPS/WebSocket transport** for blocked-SSH networks: `ot-http` carries the SSH protocol over `{websocket.host}{websocket.path}` on the existing HTTPS listener. `publish http|tcp|ssh`, `forward tcp`, `proxy`, and raw `connect` (stock OpenSSH `ProxyCommand`) all reuse the same SSH server.

## Layout

```
cmd/own-tunnel/          # server main
cmd/ot-http/             # SSH-over-WebSocket client: publish/forward/proxy/connect
internal/auth/           # password (bcrypt) + authorized_keys + per-IP lockout + perms lookup
internal/otclient/       # WS URL/dial, SSH auth, host-key callbacks, bidirectional piping
internal/perms/          # permission names / parsing
internal/config/         # YAML load + validate
internal/hostkeys/       # Ed25519 host key load/generate
internal/httpproxy/      # HTTP/HTTPS reverse proxy (Host/SNI → tunnel) + control endpoint routing
internal/logging/        # slog setup
internal/namegen/        # DNS labels + random names
internal/registry/       # in-memory name:port → owner ssh.Conn
internal/sshserver/      # SSH accept (TCP or injected net.Conn), -R/-L, menu
internal/tlsutil/        # wildcard + per-domain certs (mtime-based hot reload)
internal/wsconn/         # WebSocket ↔ net.Conn adapter (binary data, half-close, keepalive)
internal/wsgateway/      # WebSocket upgrade → sshserver.ServeConn
scripts/hashpassword.go  # bcrypt helper for config
config.example.yaml
```

## Locked design rules

- Language: **Go**. Prefer stdlib + `golang.org/x/crypto/ssh` + `gopkg.in/yaml.v3`.
- SSH-over-WebSocket is a **transport**, not a second protocol: `wsgateway` upgrades and hands the `wsconn` byte pipe to `sshserver.ServeConn`. Keep auth, permissions, lockout, and the registry unchanged. Do not add an HTTP token/auth layer to `/ws`.
- The WS endpoint uses the existing HTTP/HTTPS listener; no extra public port. `websocket.enabled` defaults true, `host` defaults to the apex domain, `path` to `/ws`, and `allow_http` to false (plain HTTP returns 404).
- Do **not** bind a real socket per `-R`. Shared HTTP/HTTPS listeners route by subdomain; TCP exists only in the registry.
- Tunnel **name** = `-R` bind address. Ephemeral binds (`""`, `localhost`, `0.0.0.0`, …) get a random name for public routing.
- `forwarded-tcpip` must use the client’s original **ClientBind** address (not the generated public name), or OpenSSH rejects the channel.
- Same name may have many ports; at most one HTTP (`:80`) per name; one SSH connection may own many forwards.
- `direct-tcpip` must **only** resolve registered tunnel names — never dial arbitrary hosts (no open relay).
- Passwords in config are **bcrypt hashes only**; reject plaintext at load.
- Auth: per-IP fail2ban-style lockout (defaults 5 failures / 15m → 15m ban); trim domain/usernames at load; dummy bcrypt for unknown users.
- Permissions (`admin`|`publish`|`dial`|`peers`|`blocks`): default `publish`+`dial`; `peers` for cross-user list/`-L`; `blocks` for `blocked` command; `admin` implies all.
- v1: single process, YAML users, in-memory registry. No ACME inside the process, no multi-node, no UDP, no custom domains beyond `{name}.{domain}`.

## Commands

```bash
go test ./...
go build -o own-tunnel ./cmd/own-tunnel
go build -o ot-http ./cmd/ot-http
go run ./scripts/hashpassword.go 'secret'
go run ./cmd/own-tunnel -config config.yaml
```

Copy `config.example.yaml` → `config.yaml` for local runs (gitignored).

## Logging

Use `log/slog`. Log auth, tunnel register/unregister, HTTP summaries, TCP consume connect/disconnect, and WebSocket SSH open/close. Never log passwords or key material.

## Do not

- Edit plan files under `.cursor/plans/` unless asked.
- Commit `config.yaml`, host keys, or certs.
- Commit or push unless the user explicitly asks.
- Add a custom tunnel protocol or a non-SSH client; stay OpenSSH-compatible. `ot-http` only transports SSH over WebSocket.
