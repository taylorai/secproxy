package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewEphemeralProducesCA(t *testing.T) {
	t.Parallel()
	authority, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(authority.CertPEM())
	if block == nil {
		t.Fatal("CertPEM did not contain a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("certificate is not a signing CA: IsCA=%v KeyUsage=%v", cert.IsCA, cert.KeyUsage)
	}
}

func TestLeafVerifiesForRequestedDNSNameOnly(t *testing.T) {
	t.Parallel()
	authority, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := authority.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.root)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "api.example.test"}); err != nil {
		t.Fatalf("leaf did not verify: %v", err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example.test"}); err == nil {
		t.Fatal("leaf verified for a different DNS name")
	}
}

func TestLeafForIPHasIPSAN(t *testing.T) {
	t.Parallel()
	authority, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := authority.Leaf("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("IP SANs = %v", leaf.Leaf.IPAddresses)
	}
}

func TestLeafCacheReturnsSamePointer(t *testing.T) {
	t.Parallel()
	authority, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("Leaf minted a second certificate for a cached host")
	}
}

func TestLeafNeverOutlivesRoot(t *testing.T) {
	t.Parallel()
	now := time.Now()
	certPEM, keyPEM := makeCertificate(t, true, now.Add(-time.Hour), now.Add(time.Hour))
	authority, err := FromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := authority.Leaf("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf.NotAfter.After(authority.root.NotAfter) {
		t.Fatalf("leaf expires %v after root %v", leaf.Leaf.NotAfter, authority.root.NotAfter)
	}
}

func TestFromPEMRejectsInvalidAuthorities(t *testing.T) {
	t.Parallel()
	now := time.Now()
	validCert, _ := makeCertificate(t, true, now.Add(-time.Hour), now.Add(time.Hour))
	_, otherKey := makeCertificate(t, true, now.Add(-time.Hour), now.Add(time.Hour))
	nonCACert, nonCAKey := makeCertificate(t, false, now.Add(-time.Hour), now.Add(time.Hour))
	expiredCert, expiredKey := makeCertificate(t, true, now.Add(-2*time.Hour), now.Add(-time.Hour))
	tests := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{"mismatched key", validCert, otherKey},
		{"non CA", nonCACert, nonCAKey},
		{"expired", expiredCert, expiredKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FromPEM(tt.cert, tt.key); err == nil {
				t.Fatal("FromPEM returned no error")
			}
		})
	}
}

func makeCertificate(t *testing.T, isCA bool, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test authority"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestPersistentMintsOnceThenReloads(t *testing.T) {
	t.Parallel()
	dir := t.TempDir() + "/ca"
	first, created, err := Persistent(dir)
	if err != nil || !created {
		t.Fatalf("first Persistent() = created %v, err %v", created, err)
	}
	info, err := os.Stat(dir + "/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ca.key mode = %o, want 600", perm)
	}
	if first.root.NotAfter.Before(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("persistent root expires too soon: %v", first.root.NotAfter)
	}

	second, created, err := Persistent(dir)
	if err != nil || created {
		t.Fatalf("second Persistent() = created %v, err %v", created, err)
	}
	if !bytes.Equal(first.CertPEM(), second.CertPEM()) {
		t.Fatal("reloaded CA differs from the one written")
	}
	if _, err := second.Leaf("api.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentRepairsHalfDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/ca.pem", []byte("not really"), 0o644); err != nil {
		t.Fatal(err)
	}
	authority, created, err := Persistent(dir)
	if err != nil || !created {
		t.Fatalf("Persistent() = created %v, err %v", created, err)
	}
	if _, err := authority.Leaf("api.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentExplainsExpiredRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now()
	cert, key := makeCertificate(t, true, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err := os.WriteFile(dir+"/ca.pem", cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/ca.key", key, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Persistent(dir); err == nil || !strings.Contains(err.Error(), "delete the directory") {
		t.Fatalf("Persistent() error = %v", err)
	}
}

func TestPersistentDoesNotFollowSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := dir + "/victim"
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	caDir := dir + "/ca"
	if err := os.Mkdir(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, caDir+"/ca.key"); err != nil {
		t.Fatal(err)
	}
	if _, created, err := Persistent(caDir); err != nil || !created {
		t.Fatalf("Persistent() = created %v, err %v", created, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "keep me" {
		t.Fatalf("symlink target was overwritten: %q", got)
	}
	if info, err := os.Lstat(caDir + "/ca.key"); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("ca.key was not replaced with a regular file: info=%v err=%v", info, err)
	}
}

func TestPersistentRejectsExistingSymlinkPair(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	if _, _, err := Persistent(source); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(source+"/ca.pem", dir+"/ca.pem"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source+"/ca.key", dir+"/ca.key"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Persistent(dir); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("Persistent() error = %v", err)
	}
}

func TestPersistentRecoversUnlockedCrashDebris(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/ca.lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/ca.key", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, created, err := Persistent(dir); err != nil || !created {
		t.Fatalf("Persistent() = created %v, err %v", created, err)
	}
}

func TestPersistentRecoversAfterLockHolderExits(t *testing.T) {
	const helper = "SECPROXY_CA_CRASH_HELPER"
	const helperDir = "SECPROXY_CA_CRASH_DIR"
	if os.Getenv(helper) == "1" {
		dir := os.Getenv(helperDir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			os.Exit(2)
		}
		unlock, err := acquireFileLock(dir + "/ca.lock")
		if err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(dir+"/ca.key", []byte("partial"), 0o600); err != nil {
			os.Exit(4)
		}
		runtime.KeepAlive(unlock)
		os.Exit(0) // simulate a crash: do not call unlock
	}

	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPersistentRecoversAfterLockHolderExits$")
	cmd.Env = append(os.Environ(), helper+"=1", helperDir+"="+dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crash helper failed: %v\n%s", err, output)
	}
	if _, created, err := Persistent(dir); err != nil || !created {
		t.Fatalf("Persistent() after crash = created %v, err %v", created, err)
	}
}

func TestPersistentConcurrentFirstStartsAgree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir() + "/ca"
	const n = 8
	type out struct {
		pem []byte
		err error
	}
	results := make(chan out, n)
	for i := 0; i < n; i++ {
		go func() {
			authority, _, err := Persistent(dir)
			if err != nil {
				results <- out{err: err}
				return
			}
			results <- out{pem: authority.CertPEM()}
		}()
	}
	var first []byte
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("concurrent Persistent() failed: %v", r.err)
		}
		if first == nil {
			first = r.pem
		} else if !bytes.Equal(first, r.pem) {
			t.Fatal("concurrent first starts produced different CAs")
		}
	}
	info, err := os.Stat(dir + "/ca.lock")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("lock file = info %v, err %v", info, err)
	}
}
