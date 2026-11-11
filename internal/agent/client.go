package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxControllerResponse = 16 << 10
	maxAgentWSMessage     = 16 << 10
)

type StatusProvider func(context.Context) (map[string]any, error)

type Client struct {
	Settings     Settings
	SettingsPath string
	HTTPClient   *http.Client
	Dialer       *websocket.Dialer
	Status       StatusProvider
	Logger       *log.Logger
}

func (c *Client) Run(ctx context.Context) error {
	if c.Status == nil {
		return errors.New("WireGuard status provider is required")
	}
	if err := c.Settings.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Settings.Token) == "" {
		if err := c.register(ctx); err != nil {
			return err
		}
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		sessionStarted := time.Now()
		err := c.runSession(ctx)
		if time.Since(sessionStarted) >= 5*time.Minute {
			backoff = time.Second
		}
		if ctx.Err() != nil {
			return nil
		}
		c.logf("control connection ended; retrying: %v", safeError(err))
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

func (c *Client) register(ctx context.Context) error {
	if strings.TrimSpace(c.Settings.Secret) == "" {
		return errors.New("first registration requires a dedicated machine token")
	}
	endpoint, err := c.controllerEndpoint("/api/v1/agent/register")
	if err != nil {
		return err
	}
	registration := map[string]string{
		"machine_code": strings.TrimSpace(c.Settings.MachineCode),
		"secret":       c.Settings.Secret,
	}
	if strings.TrimSpace(c.Settings.InstanceID) != "" {
		registration["agent_type"] = strings.TrimSpace(c.Settings.AgentType)
		registration["instance_id"] = strings.TrimSpace(c.Settings.InstanceID)
	}
	body, err := json.Marshal(registration)
	if err != nil {
		return errors.New("encode Agent registration request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("create Agent registration request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Agent registration request failed: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxControllerResponse+1))
	if err != nil || len(responseBody) > maxControllerResponse {
		return errors.New("Agent registration response is unreadable or too large")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Agent registration rejected (HTTP %d)", resp.StatusCode)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil || len(result.Token) < 16 || len(result.Token) > 4096 || strings.ContainsAny(result.Token, "\r\n") {
		return errors.New("Agent registration returned an invalid token")
	}
	c.Settings.Token = result.Token
	c.Settings.Secret = ""
	if c.SettingsPath != "" {
		if err := SaveSettings(c.SettingsPath, c.Settings); err != nil {
			c.Settings.Token = ""
			return fmt.Errorf("persist Agent registration token: %w", err)
		}
	}
	c.logf("Agent registration completed")
	return nil
}

func (c *Client) runSession(ctx context.Context) error {
	wsURL, err := c.websocketURL()
	if err != nil {
		return err
	}
	dialer := c.Dialer
	if dialer == nil {
		dialer = &websocket.Dialer{HandshakeTimeout: 8 * time.Second}
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+strings.TrimSpace(c.Settings.Token))
	conn, response, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		if response != nil {
			return fmt.Errorf("Agent WebSocket handshake rejected (HTTP %d)", response.StatusCode)
		}
		return fmt.Errorf("Agent WebSocket connection failed: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(maxAgentWSMessage)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var welcome struct {
		Type                 string `json:"type"`
		Protocol             int    `json:"protocol"`
		HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("read Agent WebSocket welcome: %w", err)
	}
	if welcome.Type != "welcome" || welcome.Protocol != 1 {
		return errors.New("unsupported Agent WebSocket protocol")
	}
	interval := time.Duration(welcome.HeartbeatIntervalSec) * time.Second
	if interval < 5*time.Second || interval > 60*time.Second {
		interval = 30 * time.Second
	}
	sendHeartbeat := func() error {
		status, err := c.Status(ctx)
		if err != nil {
			return fmt.Errorf("collect WireGuard status: %w", err)
		}
		heartbeatID := fmt.Sprintf("wg-hb-%d", time.Now().UnixNano())
		payload, err := json.Marshal(map[string]any{
			"type": "heartbeat", "agent_type": "wireguard",
			"id": heartbeatID, "status": status,
		})
		if err != nil || len(payload) > maxAgentWSMessage {
			return errors.New("WireGuard heartbeat is invalid or exceeds the 16 KiB limit")
		}
		_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			return fmt.Errorf("send WireGuard heartbeat: %w", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		var ack struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			OK      bool   `json:"ok"`
			Message string `json:"message"`
		}
		if err := conn.ReadJSON(&ack); err != nil {
			return fmt.Errorf("read WireGuard heartbeat ACK: %w", err)
		}
		if ack.Type != "heartbeat.ack" || ack.ID != heartbeatID || !ack.OK {
			return fmt.Errorf("controller rejected WireGuard heartbeat: %s", ack.Message)
		}
		return nil
	}
	if err := sendHeartbeat(); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := sendHeartbeat(); err != nil {
				return err
			}
		}
	}
}

func (c *Client) controllerEndpoint(path string) (string, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.Settings.ControllerURL), "/"))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return "", errors.New("controllerURL is invalid")
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawPath = ""
	return base.String(), nil
}

func (c *Client) websocketURL() (string, error) {
	endpoint, err := c.controllerEndpoint("/api/v1/agent/ws")
	if err != nil {
		return "", err
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("controller WebSocket URL is invalid")
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	return u.String(), nil
}

func (c *Client) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	} else {
		log.New(os.Stderr, "wg-agent: ", log.LstdFlags).Printf(format, args...)
	}
}

func safeError(err error) string {
	if err == nil {
		return "unknown error"
	}
	message := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}
