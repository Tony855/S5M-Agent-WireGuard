package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRunReconnectsAfterWebSocketDisconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var connections atomic.Int32
	serverErr := make(chan error, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := connections.Add(1)
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(map[string]any{"type": "welcome", "protocol": 1, "heartbeat_interval_sec": 5}); err != nil {
			serverErr <- err
			return
		}
		var heartbeat map[string]any
		if err := conn.ReadJSON(&heartbeat); err != nil {
			serverErr <- err
			return
		}
		if heartbeat["type"] != "heartbeat" {
			serverErr <- context.Canceled
			return
		}
		if count == 1 {
			// Simulate controller restart/network loss before the heartbeat ACK.
			serverErr <- nil
			return
		}
		if err := conn.WriteJSON(map[string]any{"type": "heartbeat.ack", "id": heartbeat["id"], "ok": true}); err != nil {
			serverErr <- err
			return
		}
		var request map[string]any
		if err := conn.ReadJSON(&request); err != nil {
			serverErr <- err
			return
		}
		if request["type"] != "command.request" {
			serverErr <- context.Canceled
			return
		}
		if err := conn.WriteJSON(map[string]any{"type": "command.none", "id": request["id"]}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
		cancel()
	}))
	defer server.Close()

	client := &Client{
		Settings: Settings{ControllerURL: server.URL, MachineCode: "node_01", Token: "signed-agent-jwt-token"},
		Status: func(context.Context) (map[string]any, error) {
			return map[string]any{"backend": "linux-kernel", "interface_name": "wg0"}, nil
		},
		Command: func(context.Context, json.RawMessage) (string, string) {
			t.Fatal("empty queue must not execute a command")
			return "failed", "unexpected"
		},
	}
	if err := client.Run(ctx); err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if got := connections.Load(); got < 2 {
		t.Fatalf("Agent reconnected %d times, want at least 2 WebSocket sessions", got)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second WebSocket session did not complete")
	}
}
