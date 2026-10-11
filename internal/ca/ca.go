// Package ca is the certificate authority the proxy uses to decrypt traffic
// to inspected hosts. The sandbox trusts the CA's public certificate; the
// private key lives only in this process's memory, unless the operator asks
// for a persistent CA on a machine they control (see Persistent).
//
// Leaf details (P-256, DNS vs IP SAN, lifetime capped at the issuer's
// expiry, bounded cache) follow Infisical CLI packages/agentproxy/ca.go
// (MIT, Copyright (c) 2025 Infisical Inc.); see NOTICE.
//
// Leaf certificates are minted per hostname on first use and cached. ECDSA
// P-256 throughout: fast to generate, and accepted by every TLS stack we care
// about including rustls-based tools like uv.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	rootLifetime       = 7 * 24 * time.Hour   // ephemeral root: one run
	persistentLifetime = 365 * 24 * time.Hour // on-disk root: trusted once, kept a while
	leafLifetime       = 24 * time.Hour
	leafReuseMin       = time.Hour // re-mint when less than this remains
	maxCachedLeaf      = 4096
)

// CA holds the root and a bounded cache of leaves.
type CA struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	certPEM []byte

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// NewEphemeral generates a fresh root in memory.
func NewEphemeral() (*CA, error) {
	return newRoot("secproxy ephemeral CA", rootLifetime)
}

func newRoot(commonName string, lifetime time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"secproxy"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newCA(cert, key), nil
}

// FromPEM loads a root supplied by an orchestrator, for setups where the
// orchestrator wants to hand the certificate to the sandbox before the proxy
// starts.
func FromPEM(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("ca: cert PEM does not contain a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca: key PEM does not contain a block")
	}
	var key *ecdsa.PrivateKey
	switch kb.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	case "PRIVATE KEY":
		var k any
		k, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err == nil {
			var ok bool
			if key, ok = k.(*ecdsa.PrivateKey); !ok {
				err = errors.New("not an ECDSA key")
			}
		}
	default:
		err = fmt.Errorf("unsupported key type %q", kb.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("ca: parse key: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("ca: certificate is not a CA")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("ca: key does not match certificate")
	}
	if time.Now().After(cert.NotAfter) {
		return nil, errors.New("ca: certificate has expired")
	}
	return newCA(cert, key), nil
}

// Persistent loads the root stored in dir (ca.pem and ca.key), or mints one
// and stores it there when the directory is empty. This is for a proxy that
// runs on the same machine as the programs it serves: the user trusts the
// certificate once and it stays valid across restarts. created reports
// whether a new root was written, so the caller can say so.
//
// A sidecar or per-run proxy should not use this; an ephemeral root that
// dies with the process is the safer default.
func Persistent(dir string) (authority *CA, created bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("ca: create %s: %w", dir, err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, false, fmt.Errorf("ca: inspect %s: %w", dir, err)
	}
	if !dirInfo.IsDir() {
		return nil, false, fmt.Errorf("ca: %s is not a directory", dir)
	}
	if dirInfo.Mode().Perm()&0o022 != 0 {
		return nil, false, fmt.Errorf("ca: %s is writable by another user (mode %o)", dir, dirInfo.Mode().Perm())
	}

	// The lock file is permanent; the kernel lock on its open descriptor is
	// the lock. The OS releases it if the process exits or crashes, so there is
	// no timestamp-based stale-lock decision that can steal a live lock.
	unlock, err := acquireFileLock(filepath.Join(dir, "ca.lock"))
	if err != nil {
		return nil, false, err
	}
	defer unlock()

	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	certInfo, certErr := os.Lstat(certPath)
	keyInfo, keyErr := os.Lstat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		if !certInfo.Mode().IsRegular() || !keyInfo.Mode().IsRegular() {
			return nil, false, fmt.Errorf("ca: %s must contain regular ca.pem and ca.key files", dir)
		}
		if keyInfo.Mode().Perm()&0o077 != 0 {
			return nil, false, fmt.Errorf("ca: %s has insecure mode %o; want 600", keyPath, keyInfo.Mode().Perm())
		}
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, false, fmt.Errorf("ca: read %s: %w", certPath, err)
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, false, fmt.Errorf("ca: read %s: %w", keyPath, err)
		}
		authority, err = FromPEM(certPEM, keyPEM)
		if err != nil {
			return nil, false, fmt.Errorf("%w (in %s; delete the directory to mint a new CA, then trust the new certificate)", err, dir)
		}
		return authority, false, nil
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		// fall through to mint
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, false, fmt.Errorf("ca: inspect %s: %w", certPath, certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, false, fmt.Errorf("ca: inspect %s: %w", keyPath, keyErr)
	default:
		// We hold the process lock, so a half-written pair can only be debris
		// from a crashed writer. Remove the surviving path and mint a complete
		// pair. created=true tells the caller that the new certificate must be
		// trusted.
		for _, path := range []string{certPath, keyPath} {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return nil, false, fmt.Errorf("ca: remove incomplete %s: %w", path, removeErr)
			}
		}
	}

	authority, err = newRoot("secproxy CA", persistentLifetime)
	if err != nil {
		return nil, false, err
	}
	keyDER, err := x509.MarshalECPrivateKey(authority.rootKey)
	if err != nil {
		return nil, false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// Create-exclusive so a symlink planted at the path is not followed.
	if err := writeNew(keyPath, keyPEM, 0o600); err != nil {
		return nil, false, fmt.Errorf("ca: write %s: %w", keyPath, err)
	}
	if err := writeNew(certPath, authority.CertPEM(), 0o644); err != nil {
		_ = os.Remove(keyPath)
		return nil, false, fmt.Errorf("ca: write %s: %w", certPath, err)
	}
	return authority, true, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func newCA(cert *x509.Certificate, key *ecdsa.PrivateKey) *CA {
	return &CA{
		root:    cert,
		rootKey: key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		leafs:   map[string]*tls.Certificate{},
	}
}

// CertPEM is the public certificate to give to the sandbox.
func (c *CA) CertPEM() []byte { return c.certPEM }

// Leaf returns a certificate for host, minting one if needed. host must be
// canonical (see policy.CanonicalHost).
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leafs[host]; ok && time.Until(leaf.Leaf.NotAfter) > leafReuseMin {
		return leaf, nil
	}
	leaf, err := c.mint(host)
	if err != nil {
		return nil, err
	}
	if len(c.leafs) >= maxCachedLeaf {
		// Simple bound: drop everything rather than track LRU. A proxy that
		// has seen 4096 distinct hosts in one run is not in a normal state.
		c.leafs = map[string]*tls.Certificate{}
	}
	c.leafs[host] = leaf
	return leaf, nil
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(leafLifetime)
	if notAfter.After(c.root.NotAfter) {
		notAfter = c.root.NotAfter // a leaf must never outlive its issuer
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.root, &key.PublicKey, c.rootKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.root.Raw},
		PrivateKey:  key,
		Leaf:        parsed,
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
