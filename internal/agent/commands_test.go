package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRequestCommandExecutesTypedDeliveryAndPersistsACKProtocol(t *testing.T) {
	serverErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		var request map[string]any
		if err := conn.ReadJSON(&request); err != nil {
			serverErr <- err
			return
		}
		if request["type"] != "command.request" || request["id"] == "" {
			serverErr <- context.Canceled
			return
		}
		command := map[string]any{"id": "cmd-123", "type": "status"}
		if err := conn.WriteJSON(map[string]any{"type": "command.deliver", "id": request["id"], "command": command}); err != nil {
			serverErr <- err
			return
		}
		var ack map[string]any
		if err := conn.ReadJSON(&ack); err != nil {
			serverErr <- err
			return
		}
		if ack["type"] != "command.ack" || ack["id"] != "cmd-123" || ack["command_status"] != "success" {
			serverErr <- context.Canceled
			return
		}
		if err := conn.WriteJSON(map[string]any{"type": "command.acknowledged", "id": "cmd-123", "ok": true}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	called := false
	client := &Client{Command: func(_ context.Context, raw json.RawMessage) (string, string) {
		called = true
		var command map[string]any
		if err := json.Unmarshal(raw, &command); err != nil || command["id"] != "cmd-123" {
			t.Errorf("command payload = %s, err=%v", raw, err)
		}
		return "success", "status collected"
	}}
	if err := client.requestCommand(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("typed command handler was not invoked")
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("controller did not receive command ACK")
	}
}

func TestRequestCommandIgnoresEmptyQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var request map[string]any
		if conn.ReadJSON(&request) != nil {
			return
		}
		_ = conn.WriteJSON(map[string]any{"type": "command.none", "id": request["id"]})
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &Client{Command: func(context.Context, json.RawMessage) (string, string) {
		t.Fatal("handler called when queue is empty")
		return "failed", "unexpected"
	}}
	if err := client.requestCommand(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
}
