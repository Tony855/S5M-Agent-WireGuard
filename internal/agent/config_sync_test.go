package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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

func TestRequestConfigUsesMasterWSEnvelopeAndStoresConfig(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(dataDir, "config.yaml")
	sum := sha256.Sum256([]byte(validWireGuardYAML))
	wantHash := hex.EncodeToString(sum[:])
	serverErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil { serverErr <- err; return }
		defer conn.Close()
		var request map[string]any
		if err := conn.ReadJSON(&request); err != nil { serverErr <- err; return }
		if request["type"] != "config.request" || request["config_sha256"] != "" || request["config_hash"] != nil || request["id"] == "" {
			serverErr <- fmt.Errorf("unexpected Master config request: %#v", request)
			return
		}
		if err := conn.WriteJSON(map[string]any{"type":"config.sync","id":request["id"],"sha256":wantHash,"yaml":validWireGuardYAML}); err != nil {
			serverErr <- err; return
		}
		serverErr <- nil
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	client := &Client{ConfigPath: configPath, DataDir: dataDir}
	if err := client.requestConfig(conn); err != nil { t.Fatal(err) }
	select {
	case err := <-serverErr:
		if err != nil { t.Fatal(err) }
	case <-time.After(2*time.Second):
		t.Fatal("Master test server did not receive config request")
	}
	stored, err := os.ReadFile(configPath)
	if err != nil { t.Fatal(err) }
	if string(stored) != validWireGuardYAML { t.Fatal("WSS config payload was not stored exactly") }
}
