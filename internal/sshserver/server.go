package sshserver

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nickcis/own-tunnel/internal/auth"
	"github.com/nickcis/own-tunnel/internal/namegen"
	"github.com/nickcis/own-tunnel/internal/registry"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Config        *ssh.ServerConfig
	Registry      *registry.Registry
	Domain        string
	Authenticator *auth.Authenticator
	Logger        *slog.Logger
	listener      net.Listener
	connSeq       atomic.Uint64
}

func New(signers []ssh.Signer, authenticator *auth.Authenticator, reg *registry.Registry, domain string, maxAuthTries int, logger *slog.Logger) *Server {
	s := &Server{
		Registry:      reg,
		Domain:        domain,
		Authenticator: authenticator,
		Logger:        logger,
	}

	if maxAuthTries < 1 {
		maxAuthTries = 3
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback:  authenticator.Password,
		PublicKeyCallback: authenticator.PublicKey,
		ServerVersion:     "SSH-2.0-OwnTunnel",
		MaxAuthTries:      maxAuthTries,
	}
	for _, signer := range signers {
		cfg.AddHostKey(signer)
	}
	s.Config = cfg
	return s
}

func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.Logger.Info("ssh listening", "addr", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

type sessionState struct {
	user   string
	connID string
	conn   *ssh.ServerConn

	mu             sync.Mutex
	notifiers      []chan string
	pending        []string // messages before a session attaches
	remoteForwards atomic.Bool
	localForwards  atomic.Bool
	exiting        atomic.Bool
}

func (st *sessionState) addNotifier(ch chan string) {
	st.mu.Lock()
	st.notifiers = append(st.notifiers, ch)
	pending := st.pending
	st.pending = nil
	st.mu.Unlock()
	for _, msg := range pending {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (st *sessionState) removeNotifier(ch chan string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := st.notifiers[:0]
	for _, n := range st.notifiers {
		if n != ch {
			out = append(out, n)
		}
	}
	st.notifiers = out
}

func (st *sessionState) notify(msg string) {
	st.mu.Lock()
	if len(st.notifiers) == 0 {
		st.pending = append(st.pending, msg)
		st.mu.Unlock()
		return
	}
	ns := append([]chan string(nil), st.notifiers...)
	st.mu.Unlock()
	for _, n := range ns {
		select {
		case n <- msg:
		default:
		}
	}
}

// failAndExit prints msg to any session and closes the SSH connection.
func (st *sessionState) failAndExit(msg string) {
	if !st.exiting.CompareAndSwap(false, true) {
		return
	}
	st.notify(msg)
	go func() {
		time.Sleep(150 * time.Millisecond) // let session flush
		_ = st.conn.Close()
	}()
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nc, s.Config)
	if err != nil {
		s.Logger.Debug("ssh handshake failed", "peer", nc.RemoteAddr().String(), "err", err)
		return
	}
	defer sshConn.Close()

	connID := fmt.Sprintf("%d", s.connSeq.Add(1))
	user := sshConn.User()
	if sshConn.Permissions != nil && sshConn.Permissions.Extensions["user"] != "" {
		user = sshConn.Permissions.Extensions["user"]
	}

	st := &sessionState{
		user:   user,
		connID: connID,
		conn:   sshConn,
	}

	s.Logger.Info("ssh connected", "user", user, "peer", sshConn.RemoteAddr().String(), "conn_id", connID)

	go s.handleGlobalReqs(st, reqs)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			go s.handleSession(st, newChannel)
		case "direct-tcpip":
			go s.handleDirectTCPIP(st, newChannel)
		default:
			s.Logger.Debug("reject channel", "type", newChannel.ChannelType(), "user", user)
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}

	removed := s.Registry.UnregisterConn(connID)
	for _, t := range removed {
		s.Logger.Info("tunnel unregistered", "user", t.User, "name", t.Name, "port", t.Port, "kind", t.Kind, "reason", "disconnect")
	}
	s.Logger.Info("ssh disconnected", "user", user, "conn_id", connID)
}

func (s *Server) handleGlobalReqs(st *sessionState, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			s.handleTCPIPForward(st, req)
		case "cancel-tcpip-forward":
			s.handleCancelTCPIPForward(st, req)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

type remoteForwardRequest struct {
	Addr string
	Port uint32
}

func (s *Server) handleTCPIPForward(st *sessionState, req *ssh.Request) {
	var rf remoteForwardRequest
	if err := ssh.Unmarshal(req.Payload, &rf); err != nil {
		s.Logger.Warn("bad tcpip-forward payload", "user", st.user, "err", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		st.failAndExit("error: invalid remote forward request\n")
		return
	}

	autoNamed := namegen.IsEphemeralBind(rf.Addr)
	opts := registry.RegisterOpts{
		Port:       rf.Port,
		ClientBind: rf.Addr,
		User:       st.user,
		ConnID:     st.connID,
		Conn:       st.conn,
	}

	var (
		t   *registry.Tunnel
		err error
	)
	if autoNamed {
		// Allocate name + insert under one lock to avoid races.
		t, err = s.Registry.RegisterAllocated(opts, func() (string, error) {
			return namegen.Random(8)
		}, 16)
	} else {
		opts.Name, err = namegen.Sanitize(rf.Addr)
		if err != nil {
			s.Logger.Warn("tunnel reject", "user", st.user, "bind", rf.Addr, "port", rf.Port, "reason", err.Error())
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			st.failAndExit(fmt.Sprintf("error: %v\n", err))
			return
		}
		t, err = s.Registry.Register(opts)
	}
	if err != nil {
		s.Logger.Warn("tunnel reject", "user", st.user, "name", opts.Name, "port", rf.Port, "kind", registry.KindForPort(rf.Port), "reason", err.Error())
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		if autoNamed {
			st.failAndExit(fmt.Sprintf("error: %v\n", err))
		} else {
			st.failAndExit(fmt.Sprintf("error: cannot bind %s:%d: %v\n", opts.Name, rf.Port, err))
		}
		return
	}

	st.remoteForwards.Store(true)
	s.Logger.Info("tunnel registered", "user", st.user, "name", t.Name, "port", t.Port, "kind", t.Kind, "auto_named", autoNamed, "conn_id", st.connID)

	st.notify(s.formatTunnelMessage(t, autoNamed))

	if req.WantReply {
		_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{Port: rf.Port}))
	}
}

func (s *Server) handleCancelTCPIPForward(st *sessionState, req *ssh.Request) {
	var rf remoteForwardRequest
	if err := ssh.Unmarshal(req.Payload, &rf); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	t, ok := s.Registry.UnregisterByClientBind(st.connID, rf.Addr, rf.Port)
	if !ok {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	s.Logger.Info("tunnel unregistered", "user", t.User, "name", t.Name, "port", t.Port, "kind", t.Kind, "reason", "cancel")
	st.notify(fmt.Sprintf("unregistered %s:%d\n", t.Name, t.Port))
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

func (s *Server) formatTunnelMessage(t *registry.Tunnel, autoNamed bool) string {
	var b strings.Builder
	if autoNamed {
		b.WriteString(fmt.Sprintf("assigned name: %s (automatic)\n", t.Name))
	}
	if t.Kind == registry.KindHTTP {
		b.WriteString(fmt.Sprintf("http tunnel:  http://%s.%s\n", t.Name, s.Domain))
		b.WriteString(fmt.Sprintf("https tunnel: https://%s.%s\n", t.Name, s.Domain))
	} else {
		b.WriteString(fmt.Sprintf("tcp tunnel: %s:%d\n", t.Name, t.Port))
		b.WriteString(fmt.Sprintf("consume with: ssh -L <local>:%s:%d <user>@<server>\n", t.Name, t.Port))
	}
	return b.String()
}

type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *Server) handleDirectTCPIP(st *sessionState, newChannel ssh.NewChannel) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "bad payload")
		st.failAndExit("error: invalid local forward request\n")
		return
	}

	dest := strings.ToLower(strings.TrimSpace(payload.DestAddr))
	if namegen.IsEphemeralBind(dest) || net.ParseIP(dest) != nil || strings.Contains(dest, ".") {
		s.Logger.Warn("tcp consume rejected", "user", st.user, "dest", payload.DestAddr, "port", payload.DestPort, "reason", "not_a_tunnel_name")
		_ = newChannel.Reject(ssh.ConnectionFailed, "unknown tunnel")
		st.failAndExit(fmt.Sprintf("error: local forward target %q is not a tunnel name\n", payload.DestAddr))
		return
	}
	name, err := namegen.Sanitize(dest)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid tunnel name")
		st.failAndExit(fmt.Sprintf("error: invalid tunnel name %q\n", payload.DestAddr))
		return
	}

	t, ok := s.Registry.Get(name, payload.DestPort)
	if !ok || t.Kind != registry.KindTCP {
		s.Logger.Warn("tcp consume rejected", "user", st.user, "name", name, "port", payload.DestPort, "reason", "not_found")
		_ = newChannel.Reject(ssh.ConnectionFailed, "tunnel not found")
		st.failAndExit(fmt.Sprintf("error: tunnel %s:%d not found\n", name, payload.DestPort))
		return
	}

	ch, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	first := !st.localForwards.Swap(true)
	if first {
		st.notify(fmt.Sprintf("local forward connected: %s:%d (owner %s)\n", t.Name, t.Port, t.User))
	}

	s.Logger.Info("tcp consume connect", "consumer", st.user, "name", t.Name, "port", t.Port, "owner", t.User)

	upstream, err := t.Dial(payload.OriginAddr, payload.OriginPort)
	if err != nil {
		s.Logger.Error("tcp consume dial failed", "consumer", st.user, "name", t.Name, "port", t.Port, "err", err)
		st.failAndExit(fmt.Sprintf("error: could not reach tunnel %s:%d: %v\n", t.Name, t.Port, err))
		return
	}
	defer upstream.Close()

	registry.Pipe(ch, upstream)
	s.Logger.Info("tcp consume disconnect", "consumer", st.user, "name", t.Name, "port", t.Port)
}

func (s *Server) handleSession(st *sessionState, newChannel ssh.NewChannel) {
	ch, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	notifyCh := make(chan string, 32)
	st.addNotifier(notifyCh)
	stopNotify := make(chan struct{})
	defer func() {
		st.removeNotifier(notifyCh)
		close(stopNotify)
	}()

	go func() {
		for {
			select {
			case msg := <-notifyCh:
				writePty(ch, msg)
			case <-stopNotify:
				return
			}
		}
	}()

	startSession := make(chan struct{}, 1)
	reqsDone := make(chan struct{})
	go func() {
		defer close(reqsDone)
		for req := range reqs {
			switch req.Type {
			case "pty-req", "env", "window-change", "signal":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			case "shell", "exec":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				select {
				case startSession <- struct{}{}:
				default:
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	select {
	case <-startSession:
		s.runSession(st, ch)
	case <-reqsDone:
	}
}

func (s *Server) runSession(st *sessionState, ch ssh.Channel) {
	writePty(ch, fmt.Sprintf("own-tunnel (%s) — authenticated as %s\n", s.Domain, st.user))

	// Remote forwards often arrive just before/around shell; wait briefly.
	// Pending notify messages (including errors) are flushed when the notifier was added.
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if st.exiting.Load() {
			time.Sleep(250 * time.Millisecond)
			return
		}
		if st.remoteForwards.Load() || len(s.Registry.ListByConn(st.connID)) > 0 {
			s.runForwardHold(st, ch)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	if st.exiting.Load() {
		time.Sleep(250 * time.Millisecond)
		return
	}
	if st.remoteForwards.Load() || len(s.Registry.ListByConn(st.connID)) > 0 {
		s.runForwardHold(st, ch)
		return
	}

	// No -R: interactive menu. -L status/errors still arrive via notify / failAndExit.
	s.runMenu(st, ch)
}

func (s *Server) runForwardHold(st *sessionState, ch ssh.Channel) {
	writePty(ch, "\nforwarding session active — keep this connection open (Ctrl-C to stop)\n")

	// Hold the session open; discard input (no interactive menu).
	buf := make([]byte, 256)
	for {
		if st.exiting.Load() {
			time.Sleep(200 * time.Millisecond)
			return
		}
		_, err := ch.Read(buf)
		if err != nil {
			return
		}
	}
}

// writePty writes text to an SSH session, normalizing newlines to CRLF so
// terminal clients don't show the classic staircase effect.
func writePty(w io.Writer, s string) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	_, _ = io.WriteString(w, s)
}

func (s *Server) runMenu(st *sessionState, ch ssh.Channel) {
	writePty(ch, "\n")
	s.printHelp(ch)
	writePty(ch, "> ")

	buf := make([]byte, 256)
	line := strings.Builder{}
	lastWasCR := false
	for {
		if st.exiting.Load() {
			time.Sleep(200 * time.Millisecond)
			return
		}
		n, err := ch.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				c := buf[i]
				switch c {
				case '\n':
					if lastWasCR {
						lastWasCR = false
						continue
					}
					fallthrough
				case '\r':
					lastWasCR = c == '\r'
					cmd := strings.TrimSpace(line.String())
					line.Reset()
					writePty(ch, "\n")
					if cmd == "" {
						writePty(ch, "> ")
						continue
					}
					if !s.handleMenuCommand(st, ch, cmd) {
						return
					}
					writePty(ch, "> ")
				case 0x03, 0x04:
					writePty(ch, "\nbye\n")
					return
				case 0x7f, 0x08:
					lastWasCR = false
					if line.Len() > 0 {
						s := line.String()
						line.Reset()
						line.WriteString(s[:len(s)-1])
						_, _ = io.WriteString(ch, "\b \b")
					}
				default:
					lastWasCR = false
					if c >= 32 && c < 127 {
						line.WriteByte(c)
						_, _ = ch.Write([]byte{c})
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) printHelp(ch ssh.Channel) {
	writePty(ch, `Commands:
  help     Show this help
  list     List all active tunnels
  quit     Disconnect

Create HTTP tunnel:
  ssh -R <name>:80:localhost:<localport> <user>@<server>

Create TCP tunnel:
  ssh -R <name>:<port>:localhost:<localport> <user>@<server>

Consume TCP tunnel:
  ssh -L <localport>:<name>:<port> <user>@<server>

`)
}

func (s *Server) handleMenuCommand(st *sessionState, ch ssh.Channel, cmd string) bool {
	switch strings.ToLower(strings.Fields(cmd)[0]) {
	case "help", "h", "?":
		s.printHelp(ch)
		return true
	case "list", "ls", "l":
		tunnels := s.Registry.ListAll()
		if len(tunnels) == 0 {
			writePty(ch, "(no active tunnels)\n")
			return true
		}
		for _, t := range tunnels {
			if t.Kind == registry.KindHTTP {
				writePty(ch, fmt.Sprintf("  [http] %s.%s  port %d  owner %s\n", t.Name, s.Domain, t.Port, t.User))
			} else {
				writePty(ch, fmt.Sprintf("  [tcp]  %s:%d  owner %s\n", t.Name, t.Port, t.User))
			}
		}
		return true
	case "quit", "exit", "q":
		writePty(ch, "bye\n")
		return false
	default:
		writePty(ch, fmt.Sprintf("unknown command %q (try help)\n", cmd))
		return true
	}
}
