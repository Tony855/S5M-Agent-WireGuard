package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRegisterPersistsDedicatedTokenAndClearsSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agent/register" {
			t.Fatalf("registration request = %s %s", r.Method, r.URL.Path)
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request["machine_code"] != "node_01" || request["secret"] != "one-time-dedicated-secret" || request["agent_type"] != "wireguard" || request["instance_id"] != "wg.routeros-01" {
			t.Fatalf("unexpected registration body: %#v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "注册成功", "token": "signed-agent-jwt-token"})
	}))
	defer server.Close()

	settingsPath := filepath.Join(t.TempDir(), "agent.yaml")
	client := &Client{
		Settings: Settings{
			ControllerURL: server.URL,
			MachineCode:   "node_01",
			AgentType:     "wireguard",
			InstanceID:    "wg.routeros-01",
			Secret:        "one-time-dedicated-secret",
		},
		SettingsPath: settingsPath,
	}
	if err := client.register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.Settings.Token != "signed-agent-jwt-token" || client.Settings.Secret != "" {
		t.Fatalf("registration credentials after success: token-set=%t secret-empty=%t", client.Settings.Token != "", client.Settings.Secret == "")
	}
	saved, err := LoadSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Token != "signed-agent-jwt-token" || saved.Secret != "" || saved.AgentType != "wireguard" || saved.InstanceID != "wg.routeros-01" {
		t.Fatalf("persisted credentials = %#v", saved)
	}
}

func TestRunSessionSendsTypedWireGuardHeartbeat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/ws" {
			serverErr <- context.Canceled
			return
		}
		if r.Header.Get("Authorization") != "Bearer signed-agent-jwt-token" {
			serverErr <- context.DeadlineExceeded
			return
		}
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(map[string]any{
			"type": "welcome", "protocol": 1, "heartbeat_interval_sec": 30,
		}); err != nil {
			serverErr <- err
			return
		}
		var heartbeat struct {
			Type      string         `json:"type"`
			AgentType string         `json:"agent_type"`
			ID        string         `json:"id"`
			Status    map[string]any `json:"status"`
		}
		if err := conn.ReadJSON(&heartbeat); err != nil {
			serverErr <- err
			return
		}
		if heartbeat.Type != "heartbeat" || heartbeat.AgentType != "wireguard" || heartbeat.ID == "" {
			serverErr <- context.Canceled
			return
		}
		if heartbeat.Status["interface_name"] != "wg0" || heartbeat.Status["backend"] != "linux-kernel" {
			serverErr <- context.Canceled
			return
		}
		if err := conn.WriteJSON(map[string]any{
			"type": "heartbeat.ack", "id": heartbeat.ID, "ok": true,
		}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
		cancel()
	}))
	defer server.Close()

	client := &Client{
		Settings: Settings{
			ControllerURL: server.URL,
			MachineCode:   "node_01",
			Token:         "signed-agent-jwt-token",
		},
		Status: func(context.Context) (map[string]any, error) {
			return map[string]any{
				"backend": "linux-kernel", "available": true, "interface_name": "wg0",
				"interface_up": true, "role": "server", "listen_port": float64(51820),
				"peer_count": float64(1), "rx_bytes": float64(10), "tx_bytes": float64(20),
				"config_sha256": "", "desired_revision": "", "applied_revision": "",
				"last_error": "",
			}, nil
		},
	}
	err := client.runSession(ctx)
	if err != context.Canceled {
		t.Fatalf("runSession error = %v, want context.Canceled after ACK", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("WebSocket test server: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket server did not receive heartbeat")
	}
}
