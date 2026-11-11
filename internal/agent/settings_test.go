package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveSettingsUsesPrivatePermissionsAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "agent.yaml")
	want := Settings{
		ControllerURL: "https://bind.example.test",
		MachineCode:   "a1b2c3d4",
		AgentType:     "wireguard",
		InstanceID:    "wg.routeros-01",
		Secret:        "dedicated-token",
	}
	if err := SaveSettings(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("settings mode = %o, want 600", info.Mode().Perm())
	}
	got, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("settings round trip = %#v, want %#v", got, want)
	}
}

func TestLoadSettingsRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("controllerURL: https://bind.example.test\nmachineCode: abc123\ntoken: abcdefghijklmnop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(path); err == nil {
		t.Fatal("expected group/world-readable settings to be rejected")
	}
}

func TestSettingsRejectPublicPlainHTTP(t *testing.T) {
	settings := Settings{
		ControllerURL: "http://controller.example.test",
		MachineCode:   "abc123",
		Secret:        "dedicated-token",
	}
	if err := settings.Validate(); err == nil {
		t.Fatal("expected public plain HTTP controller URL to be rejected")
	}
}

func TestSettingsRejectPartialOrInvalidInstanceIdentity(t *testing.T) {
	base := Settings{ControllerURL: "https://bind.example.test", MachineCode: "abc123", Secret: "dedicated-token"}
	cases := []struct {
		name string
		edit func(*Settings)
	}{
		{name: "missing instance id", edit: func(s *Settings) { s.AgentType = "wireguard" }},
		{name: "missing agent type", edit: func(s *Settings) { s.InstanceID = "wg.routeros-01" }},
		{name: "wrong agent type", edit: func(s *Settings) { s.AgentType = "mihomo"; s.InstanceID = "wg-01" }},
		{name: "invalid instance id", edit: func(s *Settings) { s.AgentType = "wireguard"; s.InstanceID = "bad/id" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := base
			tc.edit(&settings)
			if err := settings.Validate(); err == nil {
				t.Fatal("expected invalid instance identity to be rejected")
			}
		})
	}
}

func TestSettingsKeepLegacyMachineScopedCompatibility(t *testing.T) {
	settings := Settings{ControllerURL: "https://bind.example.test", MachineCode: "abc123", Secret: "dedicated-token"}
	if err := settings.Validate(); err != nil {
		t.Fatalf("legacy settings must remain valid: %v", err)
	}
}
