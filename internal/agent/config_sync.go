package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
)

const maxSyncedConfigBytes = 2 << 20

func fileSHA256(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read local WireGuard config: %w", err)
	}
	if len(data) > maxSyncedConfigBytes {
		return "", errors.New("local WireGuard config exceeds 2 MiB")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// storeSyncedConfig verifies the exact server digest and validates the complete
// YAML (including local secret-file paths) before atomically replacing desired
// config. Private key and PSK contents are never downloaded from the controller.
func storeSyncedConfig(path, dataDir, yamlText, expectedSHA256 string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(dataDir) == "" {
		return errors.New("WireGuard config path and data directory are required")
	}
	if len(yamlText) == 0 || len(yamlText) > maxSyncedConfigBytes {
		return errors.New("WireGuard config is empty or exceeds 2 MiB")
	}
	sum := sha256.Sum256([]byte(yamlText))
	if hex.EncodeToString(sum[:]) != strings.ToLower(strings.TrimSpace(expectedSHA256)) {
		return errors.New("controller WireGuard config SHA-256 mismatch")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("prepare WireGuard config directory: %w", err)
	}
	file, err := os.CreateTemp(dir, ".wireguard-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary WireGuard config: %w", err)
	}
	tmpPath := file.Name()
	defer os.Remove(tmpPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := io.WriteString(file, yamlText); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary WireGuard config: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary WireGuard config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary WireGuard config: %w", err)
	}
	if _, err := config.LoadWithDataDir(tmpPath, dataDir); err != nil {
		return fmt.Errorf("controller WireGuard config rejected: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit WireGuard config: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (c *Client) requestConfig(conn interface {
	WriteJSON(any) error
	ReadJSON(any) error
}) error {
	if strings.TrimSpace(c.ConfigPath) == "" || strings.TrimSpace(c.DataDir) == "" {
		return nil
	}
	localHash, err := fileSHA256(c.ConfigPath)
	if err != nil {
		return err
	}
	requestID := fmt.Sprintf("wg-config-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]any{"type": "config.request", "id": requestID, "config_sha256": localHash}); err != nil {
		return fmt.Errorf("request WireGuard config: %w", err)
	}
	var response struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		SHA256  string `json:"sha256"`
		YAML    string `json:"yaml"`
		Message string `json:"message"`
	}
	if err := conn.ReadJSON(&response); err != nil {
		return fmt.Errorf("read WireGuard config response: %w", err)
	}
	if response.ID != requestID {
		return errors.New("WireGuard config response ID mismatch")
	}
	switch response.Type {
	case "config.unchanged":
		if response.SHA256 == "" || response.SHA256 != localHash {
			return errors.New("controller confirmed an unexpected WireGuard config hash")
		}
		return nil
	case "config.sync":
		return storeSyncedConfig(c.ConfigPath, c.DataDir, response.YAML, response.SHA256)
	case "error":
		if response.Message == "该 Agent 实例尚未分配配置" {
			return nil
		}
		return fmt.Errorf("controller rejected WireGuard config request: %s", safeError(errors.New(response.Message)))
	default:
		return fmt.Errorf("unsupported WireGuard config response %q", response.Type)
	}
}
