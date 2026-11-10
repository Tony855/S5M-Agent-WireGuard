package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	goruntime "runtime"
	"strings"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
)

const maxWireGuardConfigBytes = 1 << 20

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
	data, readErr := readWireGuardConfig(configPath)
	if readErr != nil {
		status["last_error"] = "WireGuard configuration is missing or unreadable"
		return status
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	status["config_sha256"] = hash
	status["desired_revision"] = hash
	cfg, err := config.LoadWithDataDir(configPath, dataDir)
	if err != nil {
		status["last_error"] = "WireGuard configuration is invalid"
		return status
	}
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
	if strings.TrimSpace(result.LastError) != "" {
		status["last_error"] = safeStatusText(result.LastError, 2048)
	}
	return status
}

func readWireGuardConfig(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxWireGuardConfigBytes {
		return nil, fmt.Errorf("invalid WireGuard config file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxWireGuardConfigBytes {
		return nil, fmt.Errorf("WireGuard config exceeds size limit")
	}
	return data, nil
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
