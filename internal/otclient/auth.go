package otclient

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type AuthOptions struct {
	User                string
	KeyFiles            []string
	NoDefaultKeys       bool
	UseAgent            bool
	Password            string // e.g. OT_PASSWORD; avoids prompting
	AllowPasswordPrompt bool

	KnownHosts         []string
	KnownHostsPort     int // SSH port used for known_hosts names; default 22
	InsecureHostKey    bool
	HostKeyFingerprint string

	Debugf func(format string, args ...any)
}

func (o AuthOptions) debugf(format string, args ...any) {
	if o.Debugf != nil {
		o.Debugf(format, args...)
	}
}

// BuildAuth assembles SSH auth methods in preference order: key files, agent,
// then password. Duplicate keys are offered once. The returned cleanup closes
// any ssh-agent connection.
func BuildAuth(opts AuthOptions) ([]ssh.AuthMethod, func() error, error) {
	cleanup := func() error { return nil }

	var signers []ssh.Signer
	seen := make(map[string]struct{})
	addSigner := func(signer ssh.Signer, source string) {
		fp := ssh.FingerprintSHA256(signer.PublicKey())
		if _, ok := seen[fp]; ok {
			opts.debugf("auth: ignoring duplicate key %s from %s", fp, source)
			return
		}
		seen[fp] = struct{}{}
		signers = append(signers, signer)
		opts.debugf("auth: loaded key %s from %s", fp, source)
	}

	explicitKeys := len(opts.KeyFiles) > 0
	keyFiles := opts.KeyFiles
	switch {
	case explicitKeys:
		opts.debugf("auth: using %d explicit key file(s)", len(keyFiles))
	case opts.NoDefaultKeys:
		opts.debugf("auth: default key files disabled")
	default:
		keyFiles = defaultKeyFiles()
		opts.debugf("auth: checking %d default key file(s)", len(keyFiles))
	}
	for _, path := range keyFiles {
		signer, err := loadSigner(path)
		if err != nil {
			if !explicitKeys {
				opts.debugf("auth: skipping %s: %v", path, err)
				continue
			}
			_ = cleanup()
			return nil, nil, fmt.Errorf("load key %s: %w", path, err)
		}
		addSigner(signer, path)
	}

	if opts.UseAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			opts.debugf("auth: connecting to ssh-agent at %s", sock)
			conn, err := net.Dial("unix", sock)
			if err == nil {
				ag := agent.NewClient(conn)
				agentSigners, err := ag.Signers()
				if err == nil {
					opts.debugf("auth: ssh-agent returned %d key(s)", len(agentSigners))
					for i, signer := range agentSigners {
						addSigner(signer, fmt.Sprintf("ssh-agent[%d]", i))
					}
					cleanup = conn.Close
				} else {
					opts.debugf("auth: ssh-agent signers failed: %v", err)
					_ = conn.Close()
				}
			} else {
				opts.debugf("auth: ssh-agent unavailable: %v", err)
			}
		} else {
			opts.debugf("auth: SSH_AUTH_SOCK is not set")
		}
	}

	var methods []ssh.AuthMethod
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if opts.Password != "" {
		methods = append(methods, ssh.Password(opts.Password))
		opts.debugf("auth: password method enabled from environment")
	} else if opts.AllowPasswordPrompt {
		methods = append(methods, ssh.PasswordCallback(func() (string, error) {
			return PromptPassword("own-tunnel password: ")
		}))
		opts.debugf("auth: interactive password prompt enabled")
	}
	if len(methods) == 0 {
		_ = cleanup()
		return nil, nil, fmt.Errorf("no authentication methods available (use --key, ssh-agent, OT_PASSWORD, or a terminal password prompt)")
	}
	opts.debugf("auth: offering %d unique key(s) in %d method(s)", len(signers), len(methods))
	return methods, cleanup, nil
}

// BuildHostKeyCallback verifies the server's SSH host key. KnownHostsPort is
// the SSH port used for known_hosts naming (the WebSocket port is unrelated).
func BuildHostKeyCallback(opts AuthOptions) (ssh.HostKeyCallback, error) {
	if opts.InsecureHostKey {
		if strings.TrimSpace(opts.HostKeyFingerprint) != "" {
			return nil, fmt.Errorf("--insecure-host-key and --host-key cannot be used together")
		}
		opts.debugf("host key: verification disabled by --insecure-host-key")
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if fp := strings.TrimSpace(opts.HostKeyFingerprint); fp != "" {
		want := fp
		if len(want) >= len("SHA256:") && strings.EqualFold(want[:len("SHA256:")], "SHA256:") {
			want = "SHA256:" + want[len("SHA256:"):]
		} else {
			want = "SHA256:" + want
		}
		opts.debugf("host key: pinned fingerprint %s", want)
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				return fmt.Errorf("SSH HOST KEY MISMATCH for %s: got %s, want %s; possible man-in-the-middle, refusing to connect", hostname, got, want)
			}
			return nil
		}, nil
	}

	files := opts.KnownHosts
	if len(files) == 0 {
		if home, err := os.UserHomeDir(); err == nil {
			files = []string{filepath.Join(home, ".ssh", "known_hosts")}
		}
	}
	port := opts.KnownHostsPort
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("known_hosts SSH port must be between 1 and 65535")
	}
	cb, err := knownhosts.New(files...)
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w (check --known-hosts or pin with --host-key SHA256:...)", err)
	}
	opts.debugf("host key: known_hosts=%v ssh_port=%d", files, port)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// The SSH client is always given port 22 semantics by Dial. If the
		// user configured a different SSH port, also try that known_hosts
		// name, e.g. [tunnel.example.com]:2222.
		names := []string{hostname}
		if port != 22 {
			if host, _, err := net.SplitHostPort(hostname); err == nil {
				if alt := net.JoinHostPort(host, strconv.Itoa(port)); alt != hostname {
					names = append(names, alt)
				}
			}
		}

		var firstErr, hardErr error
		for _, name := range names {
			err := cb(name, remote, key)
			if err == nil {
				return nil
			}
			if firstErr == nil {
				firstErr = err
			}
			var keyErr *knownhosts.KeyError
			var revoked *knownhosts.RevokedError
			if errors.As(err, &revoked) || (errors.As(err, &keyErr) && len(keyErr.Want) > 0) {
				hardErr = err
			}
		}
		if hardErr != nil {
			return formatHostKeyError(hardErr, hostname, key)
		}
		return formatHostKeyError(firstErr, hostname, key)
	}, nil
}

func formatHostKeyError(err error, hostname string, key ssh.PublicKey) error {
	host := hostname
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}
	var revoked *knownhosts.RevokedError
	if errors.As(err, &revoked) {
		return fmt.Errorf("SSH host key for %s is revoked: %w; refusing to connect", host, err)
	}
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) {
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("SSH HOST KEY MISMATCH for %s: server presented %s; possible man-in-the-middle, refusing to connect: %w",
				host, ssh.FingerprintSHA256(key), err)
		}
		return fmt.Errorf("SSH host key for %s is not in known_hosts: %w; verify and add it, or pin it with --host-key %s",
			host, err, ssh.FingerprintSHA256(key))
	}
	return fmt.Errorf("SSH host key verification for %s failed: %w", host, err)
}

func defaultKeyFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	sshDir := filepath.Join(home, ".ssh")
	return []string{
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_ecdsa"),
		filepath.Join(sshDir, "id_rsa"),
	}
}

func loadSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, err
	}
	pass, err := PromptPassword(fmt.Sprintf("Enter passphrase for %s: ", path))
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKeyWithPassphrase(data, []byte(pass))
}

// PromptPassword reads a password without echo from /dev/tty when available,
// falling back to stdin only if stdin is a terminal. ProxyCommand stdin is the
// tunnel itself, so it must not be used for prompts.
func PromptPassword(prompt string) (string, error) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		fmt.Fprint(tty, prompt)
		pass, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			return "", err
		}
		return string(pass), nil
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(pass), nil
	}

	return "", fmt.Errorf("no terminal available for password prompt (use an SSH key/agent or set OT_PASSWORD)")
}
