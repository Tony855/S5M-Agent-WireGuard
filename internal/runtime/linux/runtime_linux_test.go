//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
)

type fakeRunner struct {
	calls  []string
	fail   string
	output []byte
}

func (f *fakeRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if call == f.fail {
		return nil, errors.New("injected failure")
	}
	if strings.Contains(call, "link show") {
		return nil, errors.New("not found")
	}
	if name == "wg" && len(args) == 3 && args[2] == "dump" {
		return f.output, nil
	}
	return nil, nil
}

func testConfig() config.Config {
	return config.Config{
		APIVersion: "s5m.wireguard/v1alpha1",
		Interface: config.Interface{
			Name: "wgtest", Role: "server", Backend: "linux-kernel", PrivateKeyFile: "private.key",
			Addresses: []string{"10.77.0.1/24"}, ListenPort: 51820, MTU: 1420,
		},
		Peers: []config.Peer{{
			Name: "peer1", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			AllowedIPs: []string{"10.77.0.2/32"},
		}},
	}
}

func setup(t *testing.T) (string, *fakeRunner, *Runtime) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "private.key"), []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRunner{}
	return dir, fake, &Runtime{DataDir: dir, Runner: fake}
}

func TestApplyConfigAndCleansTemporarySecret(t *testing.T) {
	dir, fake, runtime := setup(t)
	if err := runtime.Apply(context.Background(), testConfig()); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(fake.calls, "\n")
	for _, want := range []string{
		"ip link add dev wgtest type wireguard",
		"wg setconf wgtest",
		"ip address replace 10.77.0.1/24 dev wgtest",
		"ip link set dev wgtest up",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %q in %s", want, calls)
		}
	}
	files, err := os.ReadDir(filepath.Join(dir, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("temporary config remains: %v", files)
	}
}

func TestApplyRollsBackCreatedInterface(t *testing.T) {
	_, fake, runtime := setup(t)
	fake.fail = "ip link set dev wgtest up"
	if err := runtime.Apply(context.Background(), testConfig()); err == nil {
		t.Fatal("expected failure")
	}
	if fake.calls[len(fake.calls)-1] != "ip link delete dev wgtest" {
		t.Fatalf("rollback missing: %v", fake.calls)
	}
}

func TestApplyBlocksDefaultRoute(t *testing.T) {
	_, fake, runtime := setup(t)
	cfg := testConfig()
	cfg.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}
	if err := runtime.Apply(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "default-route") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("commands ran before route rejection: %v", fake.calls)
	}
}

func TestStatusRejectsUnsafeName(t *testing.T) {
	_, _, runtime := setup(t)
	if _, err := runtime.Status(context.Background(), "wg0;reboot"); err == nil {
		t.Fatal("expected invalid name")
	}
}

func TestParseDumpReturnsPeerTelemetry(t *testing.T) {
	status := wr.Status{}
	dump := "private\tpublic\t51820\toff\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t198.51.100.10:51820\t10.77.0.2/32,fd77::2/128\t1700000000\t1234\t5678\t25\n"
	if err := parseDump(dump, &status); err != nil {
		t.Fatal(err)
	}
	if status.ListenPort != 51820 || len(status.Peers) != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	peer := status.Peers[0]
	if peer.Endpoint != "198.51.100.10:51820" || peer.ReceiveBytes != 1234 || peer.TransmitBytes != 5678 || peer.PersistentKeepalive != 25 {
		t.Fatalf("unexpected peer telemetry: %+v", peer)
	}
	if peer.LastHandshake == nil || !peer.LastHandshake.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("unexpected handshake time: %+v", peer.LastHandshake)
	}
	if strings.Join(peer.AllowedIPs, ",") != "10.77.0.2/32,fd77::2/128" {
		t.Fatalf("unexpected AllowedIPs: %v", peer.AllowedIPs)
	}
}

func TestParseDumpRejectsMalformedPeerRow(t *testing.T) {
	status := wr.Status{}
	if err := parseDump("private\tpublic\t51820\toff\nshort\trow\n", &status); err == nil {
		t.Fatal("expected malformed dump error")
	}
}

func TestParseDumpLeavesNeverConnectedHandshakeUnset(t *testing.T) {
	status := wr.Status{}
	dump := "private\tpublic\t0\toff\n" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t(none)\t10.77.0.2/32\t0\t0\t0\t0\n"
	if err := parseDump(dump, &status); err != nil {
		t.Fatal(err)
	}
	if status.Peers[0].LastHandshake != nil {
		t.Fatalf("expected no handshake, got %v", status.Peers[0].LastHandshake)
	}
}

func TestLinkIsUpUsesInterfaceFlags(t *testing.T) {
	if !linkIsUp("7: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420") {
		t.Fatal("expected interface with UP flag to be running")
	}
	if linkIsUp("7: wg0: <POINTOPOINT,NOARP> mtu 1420") {
		t.Fatal("interface without UP flag must not be running")
	}
	if linkIsUp("malformed output") {
		t.Fatal("malformed link output must not be treated as running")
	}
}
