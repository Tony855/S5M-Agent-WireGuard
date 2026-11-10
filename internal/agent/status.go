package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strings"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
	"gopkg.in/yaml.v3"
)

func BuildWireGuardStatus(ctx context.Context, configPath, dataDir, agentVersion string, runtime wr.Runtime) map[string]any {
	status := map[string]any{
		"backend": "linux-kernel", "available": false, "interface_name": "wg0",
		"interface_up": false, "role": "server", "listen_port": float64(0),
		"peer_count": float64(0), "rx_bytes": float64(0), "tx_bytes": float64(0),
		"config_sha256": "", "desired_revision": "", "applied_revision": "",
		"last_error": "", "os": goruntime.GOOS, "arch": goruntime.GOARCH,
		"agent_version": agentVersion,
	}
	if hostname, err := os.Hostname(); err == nil {
		status["hostname"] = safeStatusText(hostname, 128)
	}
	cfg, err := config.LoadWithDataDir(configPath, dataDir)
	if err != nil {
		status["last_error"] = "WireGuard configuration is missing or invalid"
		return status
	}
	revision, err := ConfigRevision(cfg)
	if err != nil {
		status["last_error"] = "WireGuard configuration revision could not be calculated"
		return status
	}
	status["config_sha256"] = revision
	status["desired_revision"] = revision
	status["interface_name"] = cfg.Interface.Name
	status["role"] = cfg.Interface.Role
	status["backend"] = cfg.Interface.Backend
	status["listen_port"] = float64(cfg.Interface.ListenPort)
	if runtime == nil {
		status["last_error"] = "WireGuard runtime is unavailable in this build"
		return status
	}
	caps := runtime.Probe(ctx)
	backendAvailable := caps.Available && caps.Backend == cfg.Interface.Backend
	status["available"] = backendAvailable
	if !backendAvailable {
		if strings.TrimSpace(caps.Reason) != "" && caps.Backend == cfg.Interface.Backend {
			status["last_error"] = safeStatusText(caps.Reason, 2048)
		} else {
			status["last_error"] = "configured WireGuard backend is not available in this build"
		}
		return status
	}
	result, statusErr := runtime.Status(ctx, cfg.Interface.Name)
	if statusErr != nil {
		status["last_error"] = "WireGuard runtime status is unavailable"
		return status
	}
	status["interface_up"] = result.Running
	status["listen_port"] = float64(result.ListenPort)
	status["peer_count"] = float64(len(result.Peers))
	var rx, tx uint64
	for _, peer := range result.Peers {
		rx = saturatingAdd(rx, peer.ReceiveBytes)
		tx = saturatingAdd(tx, peer.TransmitBytes)
	}
	status["rx_bytes"] = boundedCounter(rx)
	status["tx_bytes"] = boundedCounter(tx)
	if result.Running {
		if applied, err := ReadAppliedRevision(dataDir, cfg.Interface.Name); err == nil && applied == revision {
			status["applied_revision"] = applied
		}
	}
	if strings.TrimSpace(result.LastError) != "" {
		status["last_error"] = safeStatusText(result.LastError, 2048)
	}
	return status
}

// ConfigRevision hashes the validated, canonical WireGuard configuration model.
// It does not include private key or PSK file contents.
func ConfigRevision(cfg config.Config) (string, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("encode WireGuard config revision: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func RecordAppliedRevision(dataDir, interfaceName, revision string) error {
	if !validRevisionInterface(interfaceName) || !validSHA256(revision) {
		return fmt.Errorf("invalid interface name or config revision")
	}
	dir, err := safeRevisionDirectory(dataDir, true)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".applied-revision-*.tmp")
	if err != nil {
		return fmt.Errorf("create applied revision journal: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.WriteString(tmp, revision+"\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, interfaceName+".applied")); err != nil {
		return fmt.Errorf("commit applied revision journal: %w", err)
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func ReadAppliedRevision(dataDir, interfaceName string) (string, error) {
	if !validRevisionInterface(interfaceName) {
		return "", fmt.Errorf("invalid interface name")
	}
	dir, err := safeRevisionDirectory(dataDir, false)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, interfaceName+".applied")
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 65 {
		return "", fmt.Errorf("applied revision journal is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	revision := strings.TrimSpace(string(data))
	if !validSHA256(revision) {
		return "", fmt.Errorf("applied revision journal is invalid")
	}
	return revision, nil
}

func ClearAppliedRevision(dataDir, interfaceName string) error {
	if !validRevisionInterface(interfaceName) {
		return fmt.Errorf("invalid interface name")
	}
	dir, err := safeRevisionDirectory(dataDir, false)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, interfaceName+".applied")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("applied revision journal is unsafe")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func safeRevisionDirectory(dataDir string, create bool) (string, error) {
	dir := filepath.Join(dataDir, "runtime")
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("create runtime journal directory: %w", err)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("runtime journal directory is unsafe")
	}
	return dir, nil
}

func validRevisionInterface(name string) bool {
	return name != "." && name != ".." && regexp.MustCompile("^[A-Za-z0-9_.-]{1,15}$").MatchString(name)
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func boundedCounter(value uint64) float64 {
	const maxExactInteger = uint64(9_000_000_000_000_000)
	if value > maxExactInteger {
		value = maxExactInteger
	}
	return float64(value)
}

func saturatingAdd(a, b uint64) uint64 {
	if b > ^uint64(0)-a {
		return ^uint64(0)
	}
	return a + b
}

func safeStatusText(value string, max int) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 {
			return -1
		}
		return r
	}, value)
	if len(value) > max {
		value = value[:max]
	}
	return value
}
