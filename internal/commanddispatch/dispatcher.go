package commanddispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/agent"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/commandjournal"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/keyedlock"
	wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
)

type Dispatcher struct {
	DataDir    string
	ConfigPath string
	Journal    *commandjournal.Journal
	Runtime    wr.Runtime

	locks keyedlock.Locks
}

type command struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	Deadline      time.Time       `json:"deadline"`
	Revision      string          `json:"revision"`
	PayloadSHA256 string          `json:"payload_sha256"`
	ConfigSHA256  string          `json:"config_sha256,omitempty"`
	Payload       json.RawMessage `json:"payload"`
}

type commandPayload struct {
	Interface string `json:"interface"`
}

func New(dataDir, configPath string, runtime wr.Runtime) (*Dispatcher, error) {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(configPath) == "" || runtime == nil {
		return nil, errors.New("command dispatcher requires data directory, config path, and runtime")
	}
	if err := validateConfigPath(dataDir, configPath); err != nil {
		return nil, err
	}
	journal, err := commandjournal.Open(dataDir)
	if err != nil {
		return nil, fmt.Errorf("open command journal: %w", err)
	}
	return &Dispatcher{DataDir: dataDir, ConfigPath: configPath, Journal: journal, Runtime: runtime}, nil
}

func validateConfigPath(dataDir, configPath string) error {
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return errors.New("Agent data directory is invalid")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("Agent data directory is unavailable")
	}
	target, err := filepath.Abs(configPath)
	if err != nil {
		return errors.New("WireGuard config path is invalid")
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("WireGuard config path must remain inside Agent data directory")
	}
	current := root
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) && i == len(parts)-1 {
			return nil
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("WireGuard config path contains an unavailable or symlinked component")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return errors.New("WireGuard config parent is not a directory")
		}
	}
	return nil
}


// Handle accepts only the versioned typed command envelope. It never invokes a
// shell, parses command strings, or accepts backend-specific free-form options.
func (d *Dispatcher) Handle(ctx context.Context, raw json.RawMessage) (string, string) {
	var cmd command
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cmd); err != nil {
		return "failed", "invalid WireGuard command envelope"
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "failed", "WireGuard command contains trailing JSON"
	}
	if len(cmd.Payload) == 0 || !json.Valid(cmd.Payload) {
		return "failed", "WireGuard command payload is missing or invalid"
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "failed", "invalid WireGuard command envelope"
	}
	allowed := map[string]bool{"id": true, "type": true, "deadline": true, "revision": true, "payload_sha256": true, "config_sha256": true, "payload": true}
	for key := range fields {
		if !allowed[key] {
			return "failed", "WireGuard command contains an unsupported field"
		}
	}
	if !validCommandID(cmd.ID) {
		return "failed", "invalid WireGuard command ID"
	}
	if cmd.Type != "apply" && cmd.Type != "stop" && cmd.Type != "status" {
		return "failed", "unsupported WireGuard command type"
	}
	var payloadFields map[string]json.RawMessage
	if err := json.Unmarshal(cmd.Payload, &payloadFields); err != nil || len(payloadFields) != 1 || payloadFields["interface"] == nil {
		return "failed", "WireGuard command payload must contain only interface"
	}
	var payload commandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil || !validInterface(payload.Interface) {
		return "failed", "invalid WireGuard interface"
	}
	if commandjournal.PayloadHash(cmd.Payload) != strings.ToLower(cmd.PayloadSHA256) {
		return "failed", "WireGuard command payload SHA-256 mismatch"
	}
	if cmd.Type == "apply" && (!validHash(cmd.ConfigSHA256) || !validHash(cmd.Revision)) {
		return "failed", "apply command requires config SHA-256 and revision"
	}
	if cmd.Type != "apply" && !validHash(cmd.Revision) {
		return "failed", "command revision is invalid"
	}

	executionCtx, cancel := context.WithDeadline(ctx, cmd.Deadline)
	defer cancel()
	unlockCommand, err := d.locks.Acquire(executionCtx, "command:"+cmd.ID)
	if err != nil {
		return "failed", "command deadline expired or context canceled while waiting for command lock"
	}
	defer unlockCommand()

	record, execute, err := d.Journal.Begin(commandjournal.Record{
		ID: cmd.ID, Type: cmd.Type, PayloadSHA256: cmd.PayloadSHA256,
		Deadline: cmd.Deadline, Revision: cmd.Revision, ConfigSHA256: cmd.ConfigSHA256,
	})
	if err != nil {
		return "failed", safeResult(err.Error())
	}
	if !execute {
		switch record.State {
		case commandjournal.StateSucceeded:
			return "success", safeResult(record.Result)
		case commandjournal.StateFailed, commandjournal.StateInterrupted:
			return "failed", safeResult(record.Result)
		default:
			return "failed", "command is already recorded as running; reconciliation required"
		}
	}

	unlockInterface, lockErr := d.locks.Acquire(executionCtx, "interface:"+payload.Interface)
	if lockErr != nil {
		result := safeResult("command deadline expired or context canceled while waiting for interface lock")
		if _, completeErr := d.Journal.Complete(cmd.ID, cmd.PayloadSHA256, false, result); completeErr != nil {
			return "failed", "command result could not be durably committed; manual reconciliation required"
		}
		return "failed", result
	}
	defer unlockInterface()
	result, runErr := d.execute(executionCtx, cmd, payload)
	if runErr != nil {
		result = safeResult(runErr.Error())
	}
	_, completeErr := d.Journal.Complete(cmd.ID, cmd.PayloadSHA256, runErr == nil, result)
	if completeErr != nil {
		return "failed", "command result could not be durably committed; manual reconciliation required"
	}
	if runErr != nil {
		return "failed", result
	}
	return "success", result
}

func (d *Dispatcher) execute(ctx context.Context, cmd command, payload commandPayload) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !cmd.Deadline.After(time.Now()) {
		return "", errors.New("command deadline expired before execution")
	}
	switch cmd.Type {
	case "apply":
		cfg, err := config.LoadWithDataDir(d.ConfigPath, d.DataDir)
		if err != nil {
			return "", errors.New("local WireGuard config is missing or invalid")
		}
		if cfg.Interface.Name != payload.Interface {
			return "", errors.New("command interface does not match desired config")
		}
		revision, err := agent.ConfigRevision(cfg)
		if err != nil || revision != cmd.Revision {
			return "", errors.New("desired config revision mismatch")
		}
		configHash, err := localFileHash(d.ConfigPath)
		if err != nil || configHash != strings.ToLower(cmd.ConfigSHA256) {
			return "", errors.New("desired config SHA-256 mismatch")
		}
		if err := d.Runtime.Apply(ctx, cfg); err != nil {
			return "", errors.New("WireGuard apply failed; inspect local runtime diagnostics")
		}
		if err := agent.RecordAppliedRevision(d.DataDir, cfg.Interface.Name, revision); err != nil {
			return "", errors.New("WireGuard applied but revision persistence failed; manual reconciliation required")
		}
		return "WireGuard configuration applied", nil
	case "stop":
		if err := d.Runtime.Stop(ctx, payload.Interface); err != nil {
			return "", errors.New("WireGuard stop failed; interface ownership was not changed")
		}
		if err := agent.ClearAppliedRevision(d.DataDir, payload.Interface); err != nil {
			return "", errors.New("WireGuard stopped but applied revision cleanup failed")
		}
		return "WireGuard interface stopped", nil
	case "status":
		status, err := d.Runtime.Status(ctx, payload.Interface)
		if err != nil {
			return "", errors.New("WireGuard status query failed")
		}
		data, err := json.Marshal(status)
		if err != nil {
			return "", errors.New("WireGuard status could not be encoded")
		}
		return safeResult(string(data)), nil
	default:
		return "", errors.New("unsupported WireGuard command")
	}
}

func localFileHash(path string) (string, error) {
	file, err := config.OpenRegular(path)
	if err != nil {
		return "", errors.New("config path is not a stable regular non-symlink file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > (1<<20) {
		return "", errors.New("config file is unsafe or oversized")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > (1<<20) {
		return "", errors.New("config file is unreadable or oversized")
	}
	return commandjournal.PayloadHash(data), nil
}

func validCommandID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	first := value[0]
	if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' || first >= '0' && first <= '9') {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func validInterface(value string) bool {
	if len(value) == 0 || len(value) > 15 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func safeResult(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, value)
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
