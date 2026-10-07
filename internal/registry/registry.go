package registry

import (
	"fmt"
	"io"
	"net"
	"sort"
	"sync"

	"golang.org/x/crypto/ssh"
)

type Kind string

const (
	KindHTTP Kind = "http"
	KindTCP  Kind = "tcp"
)

// Tunnel is a registered remote forward.
type Tunnel struct {
	Name       string // public name (subdomain / -L destination)
	Port       uint32
	ClientBind string // exact bind addr from tcpip-forward (for forwarded-tcpip)
	Kind       Kind
	User       string
	ConnID string
	Conn   ssh.Conn
}

// Dial opens a forwarded-tcpip channel to the tunnel owner.
// Addr/Port must match the client's tcpip-forward request or OpenSSH rejects the channel.
func (t *Tunnel) Dial(originAddr string, originPort uint32) (ssh.Channel, error) {
	bind := t.ClientBind
	payload := ssh.Marshal(struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{
		Addr:       bind,
		Port:       t.Port,
		OriginAddr: originAddr,
		OriginPort: originPort,
	})
	ch, reqs, err := t.Conn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return ch, nil
}

type Registry struct {
	mu      sync.RWMutex
	byKey   map[string]*Tunnel            // name:port
	byConn  map[string]map[string]*Tunnel // connID -> key -> tunnel
	byUser  map[string]map[string]*Tunnel // user -> key -> tunnel
}

func New() *Registry {
	return &Registry{
		byKey:  make(map[string]*Tunnel),
		byConn: make(map[string]map[string]*Tunnel),
		byUser: make(map[string]map[string]*Tunnel),
	}
}

func key(name string, port uint32) string {
	return fmt.Sprintf("%s:%d", name, port)
}

func KindForPort(port uint32) Kind {
	if port == 80 {
		return KindHTTP
	}
	return KindTCP
}

type RegisterOpts struct {
	Name       string
	Port       uint32
	ClientBind string
	User       string
	ConnID     string
	Conn       ssh.Conn
}

func (r *Registry) Register(opts RegisterOpts) (*Tunnel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registerLocked(opts)
}

// RegisterAllocated picks a unique name under the registry lock (nameGen + insert
// are atomic), then registers the tunnel on opts.Port.
func (r *Registry) RegisterAllocated(opts RegisterOpts, nameGen func() (string, error), maxAttempts int) (*Tunnel, error) {
	if maxAttempts <= 0 {
		maxAttempts = 16
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < maxAttempts; i++ {
		n, err := nameGen()
		if err != nil {
			return nil, err
		}
		if r.nameExistsLocked(n) {
			continue
		}
		opts.Name = n
		return r.registerLocked(opts)
	}
	return nil, fmt.Errorf("could not allocate tunnel name")
}

func (r *Registry) registerLocked(opts RegisterOpts) (*Tunnel, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("empty tunnel name")
	}
	if opts.Port == 0 {
		return nil, fmt.Errorf("port must be non-zero")
	}

	k := key(opts.Name, opts.Port)
	kind := KindForPort(opts.Port)

	if existing, ok := r.byKey[k]; ok {
		return nil, fmt.Errorf("tunnel %s already registered by %s", k, existing.User)
	}

	t := &Tunnel{
		Name:       opts.Name,
		Port:       opts.Port,
		ClientBind: opts.ClientBind,
		Kind:       kind,
		User:       opts.User,
		ConnID:     opts.ConnID,
		Conn:       opts.Conn,
	}
	r.byKey[k] = t
	if r.byConn[opts.ConnID] == nil {
		r.byConn[opts.ConnID] = make(map[string]*Tunnel)
	}
	r.byConn[opts.ConnID][k] = t
	if r.byUser[opts.User] == nil {
		r.byUser[opts.User] = make(map[string]*Tunnel)
	}
	r.byUser[opts.User][k] = t
	return t, nil
}

func (r *Registry) Unregister(name string, port uint32) (*Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.removeLocked(key(name, port))
}

// UnregisterByClientBind removes a tunnel owned by connID matching the original tcpip-forward bind.
func (r *Registry) UnregisterByClientBind(connID, clientBind string, port uint32) (*Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.byConn[connID]
	if m == nil {
		return nil, false
	}
	for k, t := range m {
		if t.Port == port && t.ClientBind == clientBind {
			return r.removeLocked(k)
		}
	}
	return nil, false
}

func (r *Registry) UnregisterConn(connID string) []*Tunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.byConn[connID]
	if m == nil {
		return nil
	}
	out := make([]*Tunnel, 0, len(m))
	for k := range m {
		if t, ok := r.removeLocked(k); ok {
			out = append(out, t)
		}
	}
	return out
}

func (r *Registry) removeLocked(k string) (*Tunnel, bool) {
	t, ok := r.byKey[k]
	if !ok {
		return nil, false
	}
	delete(r.byKey, k)
	if m := r.byConn[t.ConnID]; m != nil {
		delete(m, k)
		if len(m) == 0 {
			delete(r.byConn, t.ConnID)
		}
	}
	if m := r.byUser[t.User]; m != nil {
		delete(m, k)
		if len(m) == 0 {
			delete(r.byUser, t.User)
		}
	}
	return t, true
}

func (r *Registry) Get(name string, port uint32) (*Tunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byKey[key(name, port)]
	return t, ok
}

func (r *Registry) GetHTTP(name string) (*Tunnel, bool) {
	return r.Get(name, 80)
}

func (r *Registry) NameExists(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.nameExistsLocked(name)
}

func (r *Registry) nameExistsLocked(name string) bool {
	for _, t := range r.byKey {
		if t.Name == name {
			return true
		}
	}
	return false
}

func (r *Registry) ListByUser(user string) []*Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m := r.byUser[user]
	out := make([]*Tunnel, 0, len(m))
	for _, t := range m {
		out = append(out, t)
	}
	sortTunnels(out)
	return out
}

func (r *Registry) ListByConn(connID string) []*Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m := r.byConn[connID]
	out := make([]*Tunnel, 0, len(m))
	for _, t := range m {
		out = append(out, t)
	}
	sortTunnels(out)
	return out
}

// ListAll returns every active tunnel, sorted by name then port ascending.
func (r *Registry) ListAll() []*Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Tunnel, 0, len(r.byKey))
	for _, t := range r.byKey {
		out = append(out, t)
	}
	sortTunnels(out)
	return out
}

func sortTunnels(tunnels []*Tunnel) {
	sort.Slice(tunnels, func(i, j int) bool {
		if tunnels[i].Name != tunnels[j].Name {
			return tunnels[i].Name < tunnels[j].Name
		}
		return tunnels[i].Port < tunnels[j].Port
	})
}

// Pipe copies bidirectionally between two ends until both finish.
func Pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	copy := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}
	go copy(a, b)
	go copy(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// SplitHostPort helpers for origin addresses.
func OriginFromAddr(addr net.Addr) (string, uint32) {
	if addr == nil {
		return "0.0.0.0", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	var port uint32
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}
