package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
)

type commandWireConn interface {
	WriteJSON(any) error
	ReadJSON(any) error
}

func (c *Client) requestCommand(ctx context.Context, conn commandWireConn) error {
	if c.Command == nil {
		return nil
	}
	requestID := fmt.Sprintf("wg-command-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": requestID}); err != nil {
		return fmt.Errorf("request WireGuard command: %w", err)
	}
	var response struct {
		Type    string          `json:"type"`
		ID      string          `json:"id"`
		Command json.RawMessage `json:"command"`
		Message string          `json:"message"`
	}
	if err := conn.ReadJSON(&response); err != nil {
		return fmt.Errorf("read WireGuard command response: %w", err)
	}
	if response.ID != requestID {
		return errors.New("WireGuard command response ID mismatch")
	}
	switch response.Type {
	case "command.none":
		return nil
	case "error":
		return fmt.Errorf("controller rejected command poll: %s", safeError(errors.New(response.Message)))
	case "command.deliver":
		if len(response.Command) == 0 || !json.Valid(response.Command) || len(response.Command) > maxAgentWSMessage {
			return errors.New("controller delivered an invalid or oversized WireGuard command")
		}
	default:
		return fmt.Errorf("unsupported WireGuard command response %q", response.Type)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	status, message := c.Command(ctx, response.Command)
	if status != "success" && status != "failed" {
		status = "failed"
		message = "WireGuard command handler returned an invalid result"
	}
	if len(message) > 512 {
		message = message[:512]
	}
	var delivered struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Command, &delivered); err != nil || delivered.ID == "" {
		return errors.New("delivered WireGuard command has no valid ID")
	}
	if err := conn.WriteJSON(map[string]any{
		"type": "command.ack", "id": delivered.ID,
		"command_status": status, "message": message,
	}); err != nil {
		return fmt.Errorf("send WireGuard command ACK: %w", err)
	}
	var ack struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		OK   bool   `json:"ok"`
	}
	if err := conn.ReadJSON(&ack); err != nil {
		return fmt.Errorf("read WireGuard command ACK confirmation: %w", err)
	}
	if ack.Type != "command.acknowledged" || ack.ID != delivered.ID || !ack.OK {
		return errors.New("controller did not confirm WireGuard command ACK")
	}
	return nil
}

var _ commandWireConn = (*websocket.Conn)(nil)
