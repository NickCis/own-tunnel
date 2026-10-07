package hostkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// LoadOrGenerate returns SSH host signers from dir, creating an Ed25519 key if missing.
func LoadOrGenerate(dir string) ([]ssh.Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("host keys dir: %w", err)
	}

	path := filepath.Join(dir, "ssh_host_ed25519_key")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := generateEd25519(path); err != nil {
			return nil, err
		}
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	return []ssh.Signer{signer}, nil
}

func generateEd25519(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal host key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write host key: %w", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("encode host key: %w", err)
	}

	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return fmt.Errorf("public host key: %w", err)
	}
	pubPath := path + ".pub"
	line := ssh.MarshalAuthorizedKey(pub)
	if err := os.WriteFile(pubPath, line, 0o644); err != nil {
		return fmt.Errorf("write host pub key: %w", err)
	}
	return nil
}
