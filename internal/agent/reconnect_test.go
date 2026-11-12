package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestWebSocketAcceptsConcurrentAgentSessions(t *testing.T) {
	const clients = 100
	var accepted atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		accepted.Add(1)
		_ = conn.WriteJSON(map[string]any{"type": "welcome", "protocol": 1, "heartbeat_interval_sec": 30})
		_ = conn.Close()
	}))
	defer server.Close()

	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			var welcome map[string]any
			if err := conn.ReadJSON(&welcome); err != nil {
				errs <- err
				return
			}
			if welcome["type"] != "welcome" {
				errs <- errors.New("unexpected WebSocket welcome envelope")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent WebSocket session failed: %v", err)
	}
	if got := accepted.Load(); got != clients {
		t.Fatalf("accepted concurrent WebSocket sessions = %d, want %d", got, clients)
	}
}

func TestReconnectDelayIsStableAndBoundedPerMachine(t *testing.T) {
	const base = 20 * time.Second
	first := reconnectDelay("machine-a", base)
	second := reconnectDelay("machine-a", base)
	if first != second {
		t.Fatalf("same machine reconnect jitter changed: %v != %v", first, second)
	}
	if first < base || first > base+base/4 {
		t.Fatalf("reconnect delay outside bounded jitter window: %v", first)
	}
	other := reconnectDelay("machine-b", base)
	if other == first {
		t.Fatalf("different machine IDs unexpectedly share the same delay: %v", first)
	}
	if got := reconnectDelay("machine-a", 0); got != 0 {
		t.Fatalf("non-positive backoff should remain zero, got %v", got)
	}
}
