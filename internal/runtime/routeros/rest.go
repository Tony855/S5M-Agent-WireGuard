package routeros

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxRESTResponseBytes = 1 << 20

// RESTClient is a read-only, HTTPS-only RouterOS REST transport. It exposes
// fixed resources rather than arbitrary CLI/REST paths or write operations.
type RESTClient struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

func NewRESTClient(endpoint, username, password string, client *http.Client) (*RESTClient, error) {
	endpoint = strings.TrimSpace(endpoint)
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 || password == "" || len(password) > 256 ||
		strings.ContainsAny(username+password, "\r\n") {
		return nil, errors.New("RouterOS REST credentials are invalid")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("RouterOS REST endpoint must be an HTTPS URL without userinfo, query or fragment")
	}
	if u.Path != "" && u.Path != "/rest" && u.Path != "/rest/" {
		return nil, errors.New("RouterOS REST endpoint path must be empty or /rest")
	}
	u.Path = "/rest"
	u.RawPath = ""
	httpClient := &http.Client{Timeout: 8 * time.Second}
	if client != nil {
		copy := *client
		httpClient = &copy
		if httpClient.Timeout <= 0 {
			httpClient.Timeout = 8 * time.Second
		}
	}
	// Never forward Basic credentials to a redirect target.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &RESTClient{baseURL: strings.TrimRight(u.String(), "/"), username: username, password: password, http: httpClient}, nil
}

func (c *RESTClient) SystemResource(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	if err := c.get(ctx, "/system/resource", &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *RESTClient) WireGuardInterfaces(ctx context.Context) ([]map[string]any, error) {
	var result []map[string]any
	if err := c.get(ctx, "/interface/wireguard", &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *RESTClient) WireGuardPeers(ctx context.Context) ([]map[string]any, error) {
	var result []map[string]any
	if err := c.get(ctx, "/interface/wireguard/peers", &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *RESTClient) IPAddresses(ctx context.Context) ([]map[string]any, error) {
	var result []map[string]any
	if err := c.get(ctx, "/ip/address", &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *RESTClient) get(ctx context.Context, resource string, target any) error {
	switch resource {
	case "/system/resource", "/interface/wireguard", "/interface/wireguard/peers", "/ip/address":
	default:
		return errors.New("RouterOS REST resource is not allowlisted")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+resource, nil)
	if err != nil {
		return errors.New("create RouterOS REST request")
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("RouterOS REST request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRESTResponseBytes+1))
	if err != nil || len(body) > maxRESTResponseBytes {
		return errors.New("RouterOS REST response is unreadable or exceeds 1 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not persist or echo RouterOS response details; they may contain
		// configuration values or other sensitive device information.
		return fmt.Errorf("RouterOS REST request rejected (HTTP %d)", resp.StatusCode)
	}
	if len(body) == 0 {
		return errors.New("RouterOS REST returned an empty response")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return errors.New("RouterOS REST returned invalid JSON")
	}
	return nil
}
