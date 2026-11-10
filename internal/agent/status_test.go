package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
)

type fakeRuntime struct {
	caps   wr.Capabilities
	status wr.Status
	err    error
}

func (f fakeRuntime) Probe(context.Context) wr.Capabilities { return f.caps }
func (f fakeRuntime) Apply(context.Context, config.Config) error { return nil }
func (f fakeRuntime) Status(context.Context, string) (wr.Status, error) { return f.status, f.err }
func (f fakeRuntime) Stop(context.Context, string) error { return nil }

func TestBuildWireGuardStatusReportsRuntimeWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	yaml := "apiVersion: s5m.wireguard/v1alpha1\ninterface:\n  name: wg0\n  role: server\n  backend: linux-kernel\n  privateKeyFile: secrets/server.key\n  addresses:\n    - 10.77.0.1/24\n  listenPort: 51820\npeers: []\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := fakeRuntime{
		caps: wr.Capabilities{Backend: "linux-kernel", Available: true},
		status: wr.Status{
			Interface: "wg0", Backend: "linux-kernel", Running: true, ListenPort: 51820,
			Peers: []wr.PeerStatus{
				{PublicKey: "peer-public-key", ReceiveBytes: 100, TransmitBytes: 200, LastHandshake: ptrTime(time.Now())},
			},
		},
	}
	status := BuildWireGuardStatus(context.Background(), configPath, dir, "test-version", runtime)
	if status["agent_type"] != nil {
		t.Fatal("Agent type belongs to the WebSocket envelope, not the runtime provider")
	}
	if status["interface_name"] != "wg0" || status["interface_up"] != true || status["peer_count"] != float64(1) {
		t.Fatalf("unexpected interface status: %#v", status)
	}
	if status["rx_bytes"] != float64(100) || status["tx_bytes"] != float64(200) {
		t.Fatalf("unexpected transfer counters: %#v", status)
	}
	if status["config_sha256"] == "" || status["desired_revision"] != status["applied_revision"] {
		t.Fatalf("config revision/hash not reported: %#v", status)
	}
	if _, exists := status["private_key"]; exists {
		t.Fatal("private key must never be included in telemetry")
	}
}

func TestBuildWireGuardStatusRejectsUnsupportedBackend(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	yaml := "apiVersion: s5m.wireguard/v1alpha1\ninterface:\n  name: wg0\n  role: server\n  backend: routeros-native\n  addresses: []\npeers: []\n"
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := fakeRuntime{caps: wr.Capabilities{Backend: "linux-kernel", Available: true}}
	status := BuildWireGuardStatus(context.Background(), configPath, dir, "test-version", runtime)
	if status["available"] != false || status["last_error"] == "" {
		t.Fatalf("unsupported backend should be unavailable: %#v", status)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
