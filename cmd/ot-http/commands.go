package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nickcis/own-tunnel/internal/otclient"
	"golang.org/x/crypto/ssh"
)

type app struct {
	*globals
	ctx context.Context

	auth            []ssh.AuthMethod
	hostKeyCallback ssh.HostKeyCallback
	cleanup         func() error
	authReady       bool
}

func (a *app) run(args []string) error {
	defer a.closeAuth()

	switch args[0] {
	case "publish":
		return a.cmdPublish(args[1:])
	case "forward":
		return a.cmdForward(args[1:])
	case "proxy":
		return a.cmdProxy(args[1:])
	case "connect":
		return a.cmdConnect(args[1:])
	case "help", "-h", "--help":
		usage(os.Stderr)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try help)", args[0])
	}
}

func (a *app) ensureAuth() error {
	if a.authReady {
		return nil
	}
	if a.user == "" {
		return fmt.Errorf("set --user or OT_USER")
	}
	if a.sshPort < 1 || a.sshPort > 65535 {
		return fmt.Errorf("--ssh-port must be between 1 and 65535")
	}
	a.debugf("auth: user=%s keys=%d no_agent=%v no_default_keys=%v password_from_env=%v known_hosts=%v ssh_port=%d pinned_key=%v insecure_host_key=%v",
		a.user, len(a.keys), a.noAgent, a.noDefaultKeys, os.Getenv("OT_PASSWORD") != "", a.known, a.sshPort, a.hostKey != "", a.insecure)
	opts := otclient.AuthOptions{
		User:                a.user,
		UseAgent:            !a.noAgent,
		NoDefaultKeys:       a.noDefaultKeys,
		Password:            os.Getenv("OT_PASSWORD"),
		AllowPasswordPrompt: true,
		KnownHosts:          a.known,
		KnownHostsPort:      a.sshPort,
		InsecureHostKey:     a.insecure,
		HostKeyFingerprint:  a.hostKey,
		Debugf:              a.debugf,
	}
	if len(a.keys) > 0 {
		opts.KeyFiles = a.keys
	}
	auth, cleanup, err := otclient.BuildAuth(opts)
	if err != nil {
		return err
	}
	hostKey, err := otclient.BuildHostKeyCallback(opts)
	if err != nil {
		_ = cleanup()
		return err
	}
	a.auth = auth
	a.cleanup = cleanup
	a.hostKeyCallback = hostKey
	a.authReady = true
	if a.insecure {
		fmt.Fprintln(os.Stderr, "ot-http: warning: SSH host key verification is disabled")
	}
	if a.insecTLS {
		fmt.Fprintln(os.Stderr, "ot-http: warning: TLS certificate verification is disabled")
	}
	return nil
}

func (a *app) closeAuth() {
	if a.cleanup != nil {
		_ = a.cleanup()
	}
}

func (a *app) dial() (*otclient.Client, error) {
	if err := a.ensureAuth(); err != nil {
		return nil, err
	}
	url := a.serverURL()
	if url == "" {
		return nil, fmt.Errorf("set --url/--host or OT_URL")
	}
	a.debugf("dial: url=%s user=%s timeout=%s keepalive=%s", url, a.user, a.timeout, a.keep)
	client, err := otclient.Dial(a.ctx, otclient.Config{
		URL:             url,
		User:            a.user,
		Auth:            a.auth,
		HostKeyCallback: a.hostKeyCallback,
		InsecureTLS:     a.insecTLS,
		Timeout:         a.timeout,
		Keepalive:       a.keep,
	})
	if err != nil {
		return nil, err
	}
	a.debugf("dial: SSH transport established")
	return client, nil
}

func (a *app) cmdPublish(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: publish <http|tcp|ssh> ...")
	}
	kind := args[0]
	args = args[1:]
	switch kind {
	case "http":
		if len(args) != 2 {
			return fmt.Errorf("usage: publish http <name|-> <local-port>")
		}
		return a.publish(args[0], 80, args[1])
	case "tcp":
		if len(args) != 3 {
			return fmt.Errorf("usage: publish tcp <name|-> <remote-port> <local-port>")
		}
		port, err := parsePort(args[1])
		if err != nil {
			return err
		}
		if port == 80 {
			return fmt.Errorf("remote port 80 is reserved for HTTP tunnels; use publish http <name|-> <local-port>")
		}
		return a.publish(args[0], port, args[2])
	case "ssh":
		if len(args) < 1 || len(args) > 2 {
			return fmt.Errorf("usage: publish ssh <name|-> [local-port=22]")
		}
		local := "22"
		if len(args) == 2 {
			local = args[1]
		}
		return a.publish(args[0], 22, local)
	default:
		return fmt.Errorf("unknown publish kind %q (want http, tcp, or ssh)", kind)
	}
}

func (a *app) publish(name string, remotePort uint32, localPort string) error {
	local, err := parsePort(localPort)
	if err != nil {
		return fmt.Errorf("local port: %w", err)
	}
	localPort = strconv.FormatUint(uint64(local), 10)
	auto := isAutoName(name)
	name = normalizeName(name)

	remoteAddr := fmt.Sprintf(":%d", remotePort)
	if name != "" {
		remoteAddr = fmt.Sprintf("%s:%d", name, remotePort)
	}

	client, err := a.dial()
	if err != nil {
		return err
	}
	defer client.Close()

	a.debugf("publish: bind=%s auto=%v local=%s", remoteAddr, auto, net.JoinHostPort(a.localHost, localPort))
	ln, err := client.SSH.Listen("tcp", remoteAddr)
	if err != nil {
		if strings.Contains(err.Error(), "tcpip-forward request denied") {
			a.reportPublishRejection(client)
		}
		return fmt.Errorf("publish %s: %w (server refused the forward; check for a name conflict, invalid name, or missing publish permission; see the server log)", remoteAddr, err)
	}
	defer ln.Close()

	// The server sends the assigned name and public URL through a session.
	// Open one for auto-named tunnels and for normal status output.
	if auto || !a.quiet {
		stop := a.startSessionOutput(client)
		defer stop()
	}

	if auto {
		a.logf("publishing auto-named port %d -> %s:%s", remotePort, a.localHost, localPort)
	} else {
		a.logf("publishing %s:%d -> %s:%s", name, remotePort, a.localHost, localPort)
	}

	go func() {
		<-a.ctx.Done()
		_ = client.Close()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if a.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept forwarded connection: %w", err)
		}
		go a.serveLocal(conn, localPort)
	}
}

func (a *app) serveLocal(conn net.Conn, localPort string) {
	defer conn.Close()

	target := net.JoinHostPort(a.localHost, localPort)
	local, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		a.logf("local dial %s failed: %v", target, err)
		return
	}
	defer local.Close()
	otclient.Pipe(conn, local)
}

func (a *app) startSessionOutput(client *otclient.Client) func() {
	sess, err := client.SSH.NewSession()
	if err != nil {
		a.debugf("open status session: %v", err)
		return func() {}
	}
	pr, pw := io.Pipe()
	sess.Stdin = pr
	sess.Stdout = os.Stderr
	sess.Stderr = os.Stderr
	if err := sess.Shell(); err != nil {
		a.debugf("start status session: %v", err)
		_ = pr.Close()
		_ = sess.Close()
		return func() {}
	}
	return func() {
		_ = pw.Close()
		_ = sess.Close()
	}
}

// reportPublishRejection attaches a short-lived session so the server can
// print the detailed reason for a rejected tcpip-forward request. The SSH
// protocol itself does not carry that reason in the request reply.
func (a *app) reportPublishRejection(client *otclient.Client) {
	sess, err := client.SSH.NewSession()
	if err != nil {
		a.debugf("publish: status session unavailable: %v", err)
		return
	}
	sess.Stdout = os.Stderr
	sess.Stderr = os.Stderr
	if err := sess.Shell(); err != nil {
		a.debugf("publish: status session failed: %v", err)
		_ = sess.Close()
		return
	}
	done := make(chan struct{})
	go func() {
		_ = sess.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = sess.Close()
	}
}

func (a *app) cmdForward(args []string) error {
	if len(args) == 0 || args[0] != "tcp" {
		return fmt.Errorf("usage: forward tcp <name> <remote-port> [local-port]")
	}
	args = args[1:]
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("usage: forward tcp <name> <remote-port> [local-port]")
	}
	name := args[0]
	remotePort, err := parsePort(args[1])
	if err != nil {
		return err
	}
	localPort := args[1]
	if len(args) == 3 {
		localPort = args[2]
	}
	local, err := parsePort(localPort)
	if err != nil {
		return fmt.Errorf("local port: %w", err)
	}
	localPort = strconv.FormatUint(uint64(local), 10)
	if remotePort == 80 {
		return fmt.Errorf("remote port 80 is an HTTP tunnel; open its public URL instead of using TCP forwarding")
	}

	client, err := a.dial()
	if err != nil {
		return err
	}
	defer client.Close()

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", localPort))
	if err != nil {
		return fmt.Errorf("listen 127.0.0.1:%s: %w", localPort, err)
	}
	defer ln.Close()

	a.logf("forwarding 127.0.0.1:%s -> %s:%d", localPort, name, remotePort)
	a.debugf("forward: local listener established")

	go func() {
		<-a.ctx.Done()
		_ = client.Close()
		_ = ln.Close()
	}()
	waitErr := make(chan error, 1)
	go func() {
		err := client.SSH.Wait()
		waitErr <- err
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// The listener is closed by the signal handler or when the SSH
			// connection drops.
			if a.ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				if werr := <-waitErr; werr != nil {
					return fmt.Errorf("own-tunnel connection closed: %w", werr)
				}
				return fmt.Errorf("own-tunnel connection closed")
			}
			return fmt.Errorf("accept local connection: %w", err)
		}
		go func(local net.Conn) {
			defer local.Close()
			remote, err := client.SSH.Dial("tcp", fmt.Sprintf("%s:%d", name, remotePort))
			if err != nil {
				a.logf("dial %s:%d: %v", name, remotePort, err)
				return
			}
			defer remote.Close()
			otclient.Pipe(local, remote)
		}(conn)
	}
}

func (a *app) cmdProxy(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: proxy <name> [remote-port=22]")
	}
	name := args[0]
	port := uint32(22)
	if len(args) == 2 {
		var err error
		port, err = parsePort(args[1])
		if err != nil {
			return err
		}
	}
	if port == 80 {
		return fmt.Errorf("remote port 80 is an HTTP tunnel; open its public URL instead of using proxy")
	}

	client, err := a.dial()
	if err != nil {
		return err
	}
	defer client.Close()

	a.debugf("proxy: opening channel to %s:%d", name, port)
	remote, err := client.SSH.Dial("tcp", fmt.Sprintf("%s:%d", name, port))
	if err != nil {
		return fmt.Errorf("dial %s:%d: %w", name, port, err)
	}
	defer remote.Close()

	go func() {
		<-a.ctx.Done()
		_ = remote.Close()
		_ = client.Close()
	}()
	go func() {
		_, _ = io.Copy(remote, os.Stdin)
		otclient.CloseWrite(remote)
	}()

	_, err = io.Copy(os.Stdout, remote)
	if err != nil && a.ctx.Err() == nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (a *app) cmdConnect(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: connect")
	}
	url := a.serverURL()
	if url == "" {
		return fmt.Errorf("set --url/--host or OT_URL")
	}
	if a.insecTLS {
		fmt.Fprintln(os.Stderr, "ot-http: warning: TLS certificate verification is disabled")
	}
	a.debugf("connect: raw WebSocket to %s", url)
	raw, _, err := otclient.DialRaw(a.ctx, otclient.Config{
		URL:         url,
		InsecureTLS: a.insecTLS,
		Timeout:     a.timeout,
		Keepalive:   a.keep,
	})
	if err != nil {
		return err
	}
	defer raw.Close()

	go func() {
		<-a.ctx.Done()
		_ = raw.Close()
	}()
	go func() {
		_, _ = io.Copy(raw, os.Stdin)
		_ = raw.CloseWrite()
	}()

	_, err = io.Copy(os.Stdout, raw)
	if err != nil && a.ctx.Err() == nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (a *app) logf(format string, args ...any) {
	if !a.quiet {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func (a *app) debugf(format string, args ...any) {
	if a.verbose {
		fmt.Fprintf(os.Stderr, "ot-http: "+format+"\n", args...)
	}
}

func isAutoName(name string) bool {
	return name == "" || name == "-" || strings.EqualFold(name, "auto")
}

func normalizeName(name string) string {
	if isAutoName(name) {
		return ""
	}
	return name
}
