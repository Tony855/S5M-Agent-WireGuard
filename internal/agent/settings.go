package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxSettingsSize = 16 << 10

type Settings struct {
	ControllerURL string `yaml:"controllerURL"`
	MachineCode   string `yaml:"machineCode"`
	AgentType     string `yaml:"agentType,omitempty"`
	InstanceID    string `yaml:"instanceID,omitempty"`
	Secret        string `yaml:"secret,omitempty"`
	Token         string `yaml:"token,omitempty"`
}

func LoadSettings(path string) (Settings, error) {
	var settings Settings
	file, err := os.Open(path)
	if err != nil {
		return settings, fmt.Errorf("open Agent settings: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return settings, fmt.Errorf("inspect Agent settings: %w", err)
	}
	if !info.Mode().IsRegular() {
		return settings, errors.New("Agent settings must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return settings, errors.New("Agent settings permissions must not grant group or other access")
	}
	if info.Size() > maxSettingsSize {
		return settings, errors.New("Agent settings exceed size limit")
	}
	decoder := yaml.NewDecoder(io.LimitReader(file, maxSettingsSize+1))
	decoder.KnownFields(true)
	if err := decoder.Decode(&settings); err != nil {
		return settings, fmt.Errorf("parse Agent settings: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return settings, errors.New("multiple Agent settings YAML documents are not supported")
	}
	if err := settings.Validate(); err != nil {
		return settings, err
	}
	return settings, nil
}

func (s Settings) Validate() error {
	controllerURL := strings.TrimSpace(s.ControllerURL)
	if controllerURL == "" || strings.ContainsAny(controllerURL, "\r\n") {
		return errors.New("controllerURL is required")
	}
	parsed, err := url.Parse(controllerURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("controllerURL is invalid")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("controllerURL must use https (http is allowed only for loopback development)")
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("plain HTTP controllerURL is allowed only for loopback development")
		}
	}
	if !regexp.MustCompile("^[A-Za-z0-9_.-]{1,96}$").MatchString(strings.TrimSpace(s.MachineCode)) {
		return errors.New("machineCode format is invalid")
	}
	agentType := strings.TrimSpace(s.AgentType)
	instanceID := strings.TrimSpace(s.InstanceID)
	if (agentType == "") != (instanceID == "") {
		return errors.New("agentType and instanceID must be configured together")
	}
	if agentType != "" && agentType != "wireguard" {
		return errors.New("agentType must be wireguard")
	}
	if instanceID != "" && !regexp.MustCompile("^[A-Za-z0-9_-]{1,64}$").MatchString(instanceID) {
		return errors.New("instanceID format is invalid")
	}
	if len(s.Secret) > 256 || len(s.Token) > 4096 {
		return errors.New("Agent credential exceeds size limit")
	}
	if strings.TrimSpace(s.Secret) == "" && strings.TrimSpace(s.Token) == "" {
		return errors.New("either secret (first registration) or token is required")
	}
	if strings.ContainsAny(s.Secret+s.Token, "\r\n") {
		return errors.New("Agent credentials must not contain newlines")
	}
	return nil
}

func SaveSettings(path string, settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encode Agent settings: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create Agent settings directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".agent-settings-*.tmp")
	if err != nil {
		return fmt.Errorf("create Agent settings temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure Agent settings temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write Agent settings: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync Agent settings: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close Agent settings: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit Agent settings: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure Agent settings: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
