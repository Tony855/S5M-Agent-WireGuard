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
	calls           []string
	fail            string
	failRollback    bool
	outputs         map[string][]byte
	linkOutput      string
	rollbackBounded bool
	cancelOn        string
	cancel          context.CancelFunc
}

func (f *fakeRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if call == "ip link delete dev wgtest" {
		deadline, ok := ctx.Deadline()
		f.rollbackBounded = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 5*time.Second
	}
	if call == f.fail || (f.failRollback && call == "ip link delete dev wgtest") {
		return nil, errors.New("injected failure")
	}
	if strings.Contains(call, "link show") {
		if f.linkOutput != "" {
			return []byte(f.linkOutput), nil
		}
		return nil, errors.New("not found")
	}
	if name == "wg" {
		if output, ok := f.outputs[call]; ok {
			return output, nil
		}
	}
	if f.cancelOn != "" && strings.HasPrefix(call, f.cancelOn) && f.cancel != nil {
		f.cancel()
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

func markManaged(t *testing.T, runtime *Runtime, name string) {
	t.Helper()
	if err := runtime.writeManagedMarker(name); err != nil {
		t.Fatal(err)
	}
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
	if _, err := os.Stat(filepath.Join(dir, "runtime", "wgtest.managed")); err != nil {
		t.Fatalf("managed interface marker missing: %v", err)
	}
	files, err := os.ReadDir(filepath.Join(dir, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "wgtest.managed" {
		t.Fatalf("expected only ownership marker after apply; found: %v", files)
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

func TestApplyReportsRollbackFailure(t *testing.T) {
	_, fake, runtime := setup(t)
	fake.fail = "ip link set dev wgtest up"
	fake.failRollback = true
	err := runtime.Apply(context.Background(), testConfig())
	if err == nil || !strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("expected explicit rollback failure, got %v", err)
	}
	if !fake.rollbackBounded {
		t.Fatalf("rollback did not receive a bounded cleanup context: %v", fake.calls)
	}
}

func TestApplyRollbackUsesBoundedIndependentContext(t *testing.T) {
	_, fake, runtime := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.cancelOn = "wg setconf wgtest"
	fake.cancel = cancel
	// Cancellation after interface creation must not suppress cleanup, and
	// cleanup must have its own short deadline rather than an unbounded context.
	if err := runtime.Apply(ctx, testConfig()); err == nil {
		t.Fatal("expected canceled apply to fail")
	}
	if !fake.rollbackBounded {
		t.Fatalf("rollback did not receive a bounded cleanup context: %v", fake.calls)
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

func telemetryOutputs(name string) map[string][]byte {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	return map[string][]byte{
		"wg show " + name + " listen-port":          []byte("51820\n"),
		"wg show " + name + " peers":                []byte(key + "\n"),
		"wg show " + name + " endpoints":            []byte(key + "\t198.51.100.10:51820\n"),
		"wg show " + name + " allowed-ips":          []byte(key + "\t10.77.0.2/32,fd77::2/128\n"),
		"wg show " + name + " latest-handshakes":    []byte(key + "\t1700000000\n"),
		"wg show " + name + " transfer":             []byte(key + "\t1234\t5678\n"),
		"wg show " + name + " persistent-keepalive": []byte(key + "\t25\n"),
	}
}

func TestParseTelemetryReturnsPeerStatsWithoutPrivateKeyDump(t *testing.T) {
	status := wr.Status{}
	values := map[string]string{
		"listen-port":          "51820",
		"peers":                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"endpoints":            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t198.51.100.10:51820",
		"allowed-ips":          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t10.77.0.2/32,fd77::2/128",
		"latest-handshakes":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t1700000000",
		"transfer":             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t1234\t5678",
		"persistent-keepalive": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t25",
	}
	if err := parseTelemetry(values, &status); err != nil {
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

func TestParseTelemetryRejectsMalformedCounters(t *testing.T) {
	status := wr.Status{}
	values := map[string]string{
		"listen-port": "51820",
		"peers":       "peer-key",
		"transfer":    "peer-key\t123",
	}
	if err := parseTelemetry(values, &status); err == nil {
		t.Fatal("expected malformed transfer counter error")
	}
}

func TestParseTelemetryLeavesNeverConnectedHandshakeUnset(t *testing.T) {
	status := wr.Status{}
	values := map[string]string{
		"listen-port":       "0",
		"peers":             "peer-key",
		"latest-handshakes": "peer-key\t0",
	}
	if err := parseTelemetry(values, &status); err != nil {
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

func TestStatusReadsLinkStateAndPeerCounters(t *testing.T) {
	_, fake, runtime := setup(t)
	markManaged(t, runtime, "wgtest")
	fake.linkOutput = "7: wgtest: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420"
	fake.outputs = telemetryOutputs("wgtest")

	status, err := runtime.Status(context.Background(), "wgtest")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Running || status.ListenPort != 51820 || len(status.Peers) != 1 {
		t.Fatalf("unexpected interface status: %+v", status)
	}
	if status.Peers[0].ReceiveBytes != 1234 || status.Peers[0].TransmitBytes != 5678 {
		t.Fatalf("unexpected peer counters: %+v", status.Peers[0])
	}
}

func TestStatusDoesNotTreatDownInterfaceAsRunning(t *testing.T) {
	_, fake, runtime := setup(t)
	markManaged(t, runtime, "wgtest")
	fake.linkOutput = "7: wgtest: <POINTOPOINT,NOARP> mtu 1420"
	fake.outputs = telemetryOutputs("wgtest")
	status, err := runtime.Status(context.Background(), "wgtest")
	if err != nil {
		t.Fatal(err)
	}
	if status.Running {
		t.Fatalf("down interface reported running: %+v", status)
	}
}

func TestStopRefusesNonWireGuardInterface(t *testing.T) {
	_, fake, runtime := setup(t)
	markManaged(t, runtime, "eth0")
	fake.fail = "wg show eth0"
	if err := runtime.Stop(context.Background(), "eth0"); err == nil {
		t.Fatal("expected refusal for non-WireGuard interface")
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "ip link delete") {
			t.Fatalf("non-WireGuard interface was deleted: %v", fake.calls)
		}
	}
}

func TestStatusDoesNotMarkNonWireGuardInterfaceRunning(t *testing.T) {
	_, fake, runtime := setup(t)
	markManaged(t, runtime, "eth0")
	fake.linkOutput = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
	fake.fail = "wg show eth0 peers"
	status, err := runtime.Status(context.Background(), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if status.Running || status.LastError == "" {
		t.Fatalf("unverified interface reported as WireGuard: %+v", status)
	}
}

func TestStopRequiresManagedMarker(t *testing.T) {
	_, fake, runtime := setup(t)
	if err := runtime.Stop(context.Background(), "wg0"); err == nil {
		t.Fatal("expected unmanaged interface refusal")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("commands ran for unmanaged interface: %v", fake.calls)
	}
}

func TestStopRemovesManagedMarkerAfterDeletingInterface(t *testing.T) {
	dir, fake, runtime := setup(t)
	markManaged(t, runtime, "wgtest")
	if err := runtime.Stop(context.Background(), "wgtest"); err != nil {
		t.Fatal(err)
	}
	if fake.calls[len(fake.calls)-1] != "ip link delete dev wgtest" {
		t.Fatalf("unexpected stop commands: %v", fake.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "runtime", "wgtest.managed")); !os.IsNotExist(err) {
		t.Fatalf("managed marker should be removed after stop, stat error: %v", err)
	}
}

func TestProbeRejectsMissingKernelWireGuardSupport(t *testing.T) {
	_, fake, runtime := setup(t)
	fake.fail = "wg show interfaces"

	caps := runtime.Probe(context.Background())
	if caps.Available {
		t.Fatalf("kernel without WireGuard support reported available: %+v", caps)
	}
	if !strings.Contains(caps.Reason, "generic-netlink API") {
		t.Fatalf("unexpected capability reason: %q", caps.Reason)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "wg show interfaces" {
		t.Fatalf("unexpected probe commands: %v", fake.calls)
	}
}

func TestProbeConfirmsKernelWireGuardSupport(t *testing.T) {
	_, fake, runtime := setup(t)

	caps := runtime.Probe(context.Background())
	if !caps.Available {
		t.Fatalf("expected kernel WireGuard support, got: %+v", caps)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "wg show interfaces" {
		t.Fatalf("probe did not query the kernel API: %v", fake.calls)
	}
}

func TestApplyDoesNotDeleteInterfaceWhenAtomicCreateFails(t *testing.T) {
	_, fake, runtime := setup(t)
	fake.fail = "ip link add dev wgtest type wireguard"

	if err := runtime.Apply(context.Background(), testConfig()); err == nil {
		t.Fatal("expected atomic interface creation failure")
	}
	if len(fake.calls) != 2 || fake.calls[0] != "wg show interfaces" || fake.calls[1] != fake.fail {
		t.Fatalf("unexpected commands after failed atomic create: %v", fake.calls)
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "ip link delete") {
			t.Fatalf("failed create must never trigger interface deletion: %v", fake.calls)
		}
	}
}
