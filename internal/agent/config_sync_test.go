package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validWireGuardYAML = `apiVersion: s5m.wireguard/v1alpha1
interface:
  name: wg0
  role: server
  backend: linux-kernel
  privateKeyFile: secrets/server.key
  addresses:
    - 10.77.0.1/24
  listenPort: 51820
peers: []
`

func TestStoreSyncedConfigValidatesHashAndAtomicallyWrites(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "config.yaml")
	sum := sha256.Sum256([]byte(validWireGuardYAML))
	hash := hex.EncodeToString(sum[:])
	if err := storeSyncedConfig(path, dataDir, validWireGuardYAML, hash); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != validWireGuardYAML {
		t.Fatalf("stored YAML differs from controller payload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestStoreSyncedConfigRejectsHashMismatchWithoutReplacingExisting(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "config.yaml")
	original := "previous desired config\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := storeSyncedConfig(path, dataDir, validWireGuardYAML, strings.Repeat("0", 64)); err == nil {
		t.Fatal("expected hash mismatch")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("invalid remote config replaced existing config: %q", got)
	}
}

func TestStoreSyncedConfigRejectsInvalidYAMLWithoutReplacingExisting(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "config.yaml")
	original := "previous desired config\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := "apiVersion: wrong\n"
	sum := sha256.Sum256([]byte(invalid))
	if err := storeSyncedConfig(path, dataDir, invalid, hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("expected invalid config rejection")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("invalid remote config replaced existing config: %q", got)
	}
}

func TestFileSHA256MissingFileReturnsEmptyHash(t *testing.T) {
	hash, err := fileSHA256(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil || hash != "" {
		t.Fatalf("hash=%q err=%v, want empty hash without error", hash, err)
	}
}
