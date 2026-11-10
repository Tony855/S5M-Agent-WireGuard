package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func validConfig() Config {
	return Config{
		APIVersion: "s5m.wireguard/v1alpha1",
		Interface:  Interface{Name: "wg0", Role: "server", Backend: "linux-kernel", PrivateKeyFile: "secrets/server.key", Addresses: []string{"10.77.0.1/24"}},
		Peers:      []Peer{{Name: "router", PublicKey: testKey(), AllowedIPs: []string{"10.77.0.2/32"}}},
	}
}

func TestValidConfig(t *testing.T) {
	if err := validConfig().Validate(t.TempDir()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestRejectsPathTraversal(t *testing.T) {
	cfg := validConfig()
	cfg.Interface.PrivateKeyFile = "../../etc/shadow"
	if err := cfg.Validate(t.TempDir()); err == nil || !strings.Contains(err.Error(), "relative file") {
		t.Fatalf("expected path traversal rejection, got %v", err)
	}
}

func TestRejectsDuplicatePeerKey(t *testing.T) {
	cfg := validConfig()
	cfg.Peers = append(cfg.Peers, Peer{Name: "duplicate", PublicKey: testKey(), AllowedIPs: []string{"10.77.0.3/32"}})
	if err := cfg.Validate(t.TempDir()); err == nil || !strings.Contains(err.Error(), "duplicate peer") {
		t.Fatalf("expected duplicate key rejection, got %v", err)
	}
}

func TestRejectsOverlappingAllowedIPs(t *testing.T) {
	cfg := validConfig()
	cfg.Peers = append(cfg.Peers, Peer{Name: "overlap", PublicKey: base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")), AllowedIPs: []string{"10.77.0.0/24"}})
	if err := cfg.Validate(t.TempDir()); err == nil || !strings.Contains(err.Error(), "overlapping AllowedIPs") {
		t.Fatalf("expected overlap rejection, got %v", err)
	}
}

func TestRejectsClientWithoutEndpoint(t *testing.T) {
	cfg := validConfig()
	cfg.Interface.Role = "client"
	if err := cfg.Validate(t.TempDir()); err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Fatalf("expected endpoint rejection, got %v", err)
	}
}

func TestRejectsUnknownBackend(t *testing.T) {
	cfg := validConfig()
	cfg.Interface.Backend = "shell"
	if err := cfg.Validate(t.TempDir()); err == nil {
		t.Fatal("expected unknown backend rejection")
	}
}

func TestRejectsSymlinkEscape(t *testing.T) {
	dataDir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dataDir, "secrets")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if safeDataFile(dataDir, "secrets/private.key") {
		t.Fatal("accepted secret path escaping through symlink")
	}
}

func TestRejectsInvalidEndpointPort(t *testing.T) {
	cfg := validConfig()
	cfg.Interface.Role = "client"
	cfg.Peers[0].Endpoint = "vpn.example.com:70000"
	if err := cfg.Validate(t.TempDir()); err == nil || !strings.Contains(err.Error(), "port must be between") {
		t.Fatalf("expected invalid endpoint port rejection, got %v", err)
	}
}

func TestRouterOSNativeDoesNotRequireContainerPrivateKey(t *testing.T) {
	cfg := validConfig()
	cfg.Interface.Backend = "routeros-native"
	cfg.Interface.PrivateKeyFile = ""
	if err := cfg.Validate(t.TempDir()); err != nil {
		t.Fatalf("RouterOS-native config should keep private key on RouterOS: %v", err)
	}
}
