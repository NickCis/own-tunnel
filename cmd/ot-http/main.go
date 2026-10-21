package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type globals struct {
	url           string
	host          string
	port          string
	scheme        string
	path          string
	user          string
	keys          stringList
	noAgent       bool
	noDefaultKeys bool
	known         stringList
	hostKey       string
	insecure      bool
	insecTLS      bool
	sshPort       int
	localHost     string
	timeout       time.Duration
	keep          time.Duration
	quiet         bool
	verbose       bool
	version       bool
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	g := &globals{}
	fs := flag.NewFlagSet("ot-http", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(fs.Output()) }

	fs.StringVar(&g.url, "url", env("OT_URL", ""), "server URL (http(s):// or ws(s)://)")
	fs.StringVar(&g.host, "H", env("OT_HOST", ""), "server host (or user@host)")
	fs.StringVar(&g.host, "host", env("OT_HOST", ""), "server host (or user@host)")
	fs.StringVar(&g.port, "p", wsPortEnv(), "server HTTPS port (default 443)")
	fs.StringVar(&g.port, "port", wsPortEnv(), "server HTTPS port (default 443)")
	fs.StringVar(&g.scheme, "scheme", env("OT_SCHEME", "https"), "https or http")
	fs.StringVar(&g.path, "path", env("OT_WS_PATH", "/ws"), "WebSocket path")
	fs.StringVar(&g.user, "u", env("OT_USER", ""), "own-tunnel login user")
	fs.StringVar(&g.user, "user", env("OT_USER", ""), "own-tunnel login user")
	fs.Var(&g.keys, "key", "SSH private key file (repeatable)")
	fs.BoolVar(&g.noAgent, "no-agent", false, "do not use ssh-agent")
	fs.BoolVar(&g.noDefaultKeys, "no-default-keys", false, "do not load default ~/.ssh/id_* keys")
	fs.Var(&g.known, "known-hosts", "known_hosts file (repeatable; default ~/.ssh/known_hosts)")
	fs.StringVar(&g.hostKey, "host-key", env("OT_HOST_KEY", ""), "pin server host key (SHA256:...)")
	fs.BoolVar(&g.insecure, "insecure-host-key", envBool("OT_INSECURE_HOST_KEY"), "skip SSH host key verification")
	fs.BoolVar(&g.insecTLS, "insecure-tls", envBool("OT_INSECURE_TLS"), "skip TLS certificate verification")
	fs.IntVar(&g.sshPort, "ssh-port", envInt("OT_SSH_PORT", 22), "SSH port for known_hosts lookup (default 22)")
	fs.StringVar(&g.localHost, "local-host", env("OT_LOCAL_HOST", "localhost"), "local target host for publish")
	fs.DurationVar(&g.timeout, "timeout", 20*time.Second, "WebSocket connect/handshake timeout")
	fs.DurationVar(&g.keep, "keepalive", 30*time.Second, "WebSocket keepalive interval (0 disables)")
	fs.BoolVar(&g.quiet, "quiet", false, "suppress client status messages")
	fs.BoolVar(&g.verbose, "v", false, "verbose diagnostics (URL, keys, channels)")
	fs.BoolVar(&g.verbose, "verbose", false, "verbose diagnostics (URL, keys, channels)")
	fs.BoolVar(&g.version, "version", false, "print version")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	if g.version {
		fmt.Println("ot-http (own-tunnel)")
		return
	}

	args := fs.Args()
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}

	g.resolveHostUser()
	if g.user == "" {
		g.user = defaultUser()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &app{globals: g, ctx: ctx}
	if err := a.run(args); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintf(os.Stderr, "ot-http: %v\n", err)
		os.Exit(1)
	}
}

func (g *globals) resolveHostUser() {
	if g.user != "" {
		return
	}
	for _, raw := range []string{g.url, g.host} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(withDefaultScheme(raw))
		if err != nil || u.User == nil {
			continue
		}
		if name := u.User.Username(); name != "" {
			g.user = name
			return
		}
	}
}

func (g *globals) serverURL() string {
	raw := strings.TrimSpace(g.url)
	if raw == "" {
		host := strings.TrimSpace(g.host)
		if host == "" {
			return ""
		}
		if !strings.Contains(host, "://") {
			// Accept user@host in --host even when --user overrides the user.
			if i := strings.LastIndex(host, "@"); i >= 0 {
				host = host[i+1:]
			}
			scheme := strings.ToLower(strings.TrimSpace(g.scheme))
			if scheme == "" {
				scheme = "https"
			}
			port := strings.TrimSpace(g.port)
			if port == "" {
				switch scheme {
				case "http", "ws":
					port = "80"
				default:
					port = "443"
				}
			}
			raw = scheme + "://" + hostWithPort(host, port)
		} else {
			raw = host
		}
	}

	u, err := url.Parse(withDefaultScheme(raw))
	if err != nil {
		return raw
	}
	// User info is used for the SSH login, not HTTP basic auth.
	u.User = nil
	path := strings.TrimSpace(g.path)
	if path != "" && (u.Path == "" || u.Path == "/") {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u.Path = path
	}
	return u.String()
}

func withDefaultScheme(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "://") {
		return raw
	}
	return "https://" + raw
}

func hostWithPort(host, port string) string {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p != "" {
			return host
		}
		host = strings.Trim(h, "[]")
		return net.JoinHostPort(host, port)
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return net.JoinHostPort(host, port)
}

func parsePort(s string) (uint32, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint32(n), nil
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// wsPortEnv returns the WebSocket/HTTPS port from the environment. OT_PORT is
// deliberately not used: ot-ssh already uses it for the SSH port.
func wsPortEnv() string {
	if v := strings.TrimSpace(os.Getenv("OT_WS_PORT")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("OT_HTTP_PORT"))
}

func envInt(key string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil {
		return fallback
	}
	return v
}

func defaultUser() string {
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return os.Getenv("USERNAME")
}

func usage(out io.Writer) {
	fmt.Fprintln(out, `Usage: ot-http [global options] <command> [args...]

SSH-over-WebSocket client for own-tunnel. Authentication is regular SSH
(password or key/agent), carried over an HTTPS WebSocket.

Global options:
  --url URL             server URL (http(s):// or ws(s)://); its path
                        is used when present, otherwise --path         OT_URL
  -H, --host HOST       server host (or user@host)                    OT_HOST
  -p, --port PORT       server HTTPS port (default 443)               OT_WS_PORT
                        (OT_HTTP_PORT is accepted as an alias)
  --scheme SCHEME       https (default), http, wss, or ws             OT_SCHEME
  --path PATH           WebSocket path (default /ws)                  OT_WS_PATH
  -u, --user USER       own-tunnel login user                         OT_USER
  --key PATH            SSH private key (repeatable)
  --no-agent            do not use ssh-agent
  --no-default-keys     do not load default ~/.ssh/id_* keys
  --known-hosts PATH    known_hosts file (repeatable)
  --ssh-port PORT       SSH port for known_hosts lookup (default 22)  OT_SSH_PORT
  --host-key FP         pin server host key (SHA256:...)              OT_HOST_KEY
  --insecure-host-key   skip SSH host key verification                OT_INSECURE_HOST_KEY
  --insecure-tls        skip TLS certificate verification             OT_INSECURE_TLS
  --local-host HOST     local target host for publish (default localhost)
                                                                      OT_LOCAL_HOST
  --timeout DUR         WebSocket connect/handshake timeout (default 20s)
  --keepalive DUR       WebSocket keepalive (default 30s; 0 disables)
  --quiet               suppress client status messages
  -v, --verbose         verbose diagnostics (URL, keys, channels)

Commands:
  publish http  <name|-> <local-port>
  publish tcp   <name|-> <remote-port> <local-port>
  publish ssh   <name|-> [local-port=22]
  forward tcp   <name> <remote-port> [local-port]
  proxy         <name> [remote-port=22]
  connect
  help

Use "-" as the name to request an automatically assigned tunnel name.

"connect" is a raw transport only: stock OpenSSH handles its own keys, agent,
password, and host-key checks, so --key/--known-hosts/--ssh-port/--host-key/
--insecure-host-key/--no-agent are ignored for that command.

--quiet suppresses client status messages; an auto-named publish still keeps
the server status session open so the assigned name is shown.

Examples:
  ot-http -H tunnel.example.com -u alice publish http myapp 3000
  ot-http -H tunnel.example.com -u alice publish tcp myapp 5432 5432
  ot-http -H tunnel.example.com -u alice publish ssh homelab
  ot-http -H tunnel.example.com -u alice forward tcp myapp 5432
  ssh -o ProxyCommand='ot-http -H tunnel.example.com -u alice proxy homelab' admin@homelab
  ssh -o ProxyCommand='ot-http -H tunnel.example.com connect' alice@tunnel.example.com`)
}
