package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	APIVersion string       `yaml:"apiVersion"`
	Interface  Interface    `yaml:"interface"`
	Peers      []Peer       `yaml:"peers"`
}

type Interface struct {
	Name           string   `yaml:"name"`
	Role           string   `yaml:"role"`
	Backend        string   `yaml:"backend"`
	PrivateKeyFile string   `yaml:"privateKeyFile"`
	Addresses      []string `yaml:"addresses"`
	ListenPort     int      `yaml:"listenPort,omitempty"`
	MTU            int      `yaml:"mtu,omitempty"`
}

type Peer struct {
	Name                  string   `yaml:"name"`
	PublicKey             string   `yaml:"publicKey"`
	PresharedKeyFile      string   `yaml:"presharedKeyFile,omitempty"`
	AllowedIPs            []string `yaml:"allowedIPs"`
	Endpoint              string   `yaml:"endpoint,omitempty"`
	PersistentKeepalive   int      `yaml:"persistentKeepalive,omitempty"`
}

func Load(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil { return cfg, fmt.Errorf("read config: %w", err) }
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil { return cfg, fmt.Errorf("parse config: %w", err) }
	if err := cfg.Validate(filepath.Dir(path)); err != nil { return cfg, err }
	return cfg, nil
}

func (c Config) Validate(dataDir string) error {
	if c.APIVersion != "s5m.wireguard/v1alpha1" { return errors.New("apiVersion must be s5m.wireguard/v1alpha1") }
	if !validInterfaceName(c.Interface.Name) { return errors.New("interface.name must be a valid Linux interface name") }
	if c.Interface.Role != "client" && c.Interface.Role != "server" { return errors.New("interface.role must be client or server") }
	if c.Interface.Backend != "linux-kernel" && c.Interface.Backend != "routeros-native" && c.Interface.Backend != "wireguard-go-experimental" {
		return errors.New("interface.backend must be linux-kernel, routeros-native, or wireguard-go-experimental")
	}
	if c.Interface.Backend == "routeros-native" && c.Interface.Role != "server" && c.Interface.Role != "client" { return errors.New("invalid RouterOS role") }
	if !safeDataFile(dataDir, c.Interface.PrivateKeyFile) { return errors.New("interface.privateKeyFile must be a relative file inside the data directory") }
	if c.Interface.ListenPort < 0 || c.Interface.ListenPort > 65535 { return errors.New("interface.listenPort must be between 0 and 65535") }
	if c.Interface.MTU != 0 && (c.Interface.MTU < 576 || c.Interface.MTU > 9000) { return errors.New("interface.mtu must be between 576 and 9000") }
	for _, address := range c.Interface.Addresses {
		if _, _, err := net.ParseCIDR(address); err != nil { return fmt.Errorf("invalid interface address %q", address) }
	}
	seenKeys := map[string]bool{}
	seenRoutes := []net.IPNet{}
	for i, p := range c.Peers {
		if strings.TrimSpace(p.Name) == "" { return fmt.Errorf("peers[%d].name is required", i) }
		if err := validateKey(p.PublicKey); err != nil { return fmt.Errorf("peers[%d].publicKey: %w", i, err) }
		if seenKeys[p.PublicKey] { return fmt.Errorf("duplicate peer public key at peers[%d]", i) }
		seenKeys[p.PublicKey] = true
		if p.PresharedKeyFile != "" && !safeDataFile(dataDir, p.PresharedKeyFile) { return fmt.Errorf("peers[%d].presharedKeyFile must be a relative file inside the data directory", i) }
		if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 { return fmt.Errorf("peers[%d].persistentKeepalive is out of range", i) }
		if c.Interface.Role == "client" && strings.TrimSpace(p.Endpoint) == "" { return fmt.Errorf("peers[%d].endpoint is required for client role", i) }
		if p.Endpoint != "" { if _, _, err := net.SplitHostPort(p.Endpoint); err != nil { return fmt.Errorf("peers[%d].endpoint must be host:port", i) } }
		if len(p.AllowedIPs) == 0 { return fmt.Errorf("peers[%d].allowedIPs must not be empty", i) }
		for _, cidr := range p.AllowedIPs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil { return fmt.Errorf("peers[%d] has invalid AllowedIPs CIDR %q", i, cidr) }
			for _, previous := range seenRoutes {
				if networksOverlap(*network, previous) { return fmt.Errorf("overlapping AllowedIPs: %s conflicts with %s", network, previous.String()) }
			}
			seenRoutes = append(seenRoutes, *network)
		}
	}
	return nil
}

func safeDataFile(dataDir, name string) bool {
	if name == "" || filepath.IsAbs(name) { return false }
	root, err := filepath.Abs(dataDir); if err != nil { return false }
	target, err := filepath.Abs(filepath.Join(root, name)); if err != nil { return false }
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) { return false }

	// Lexical containment is not enough: an existing symlink (or symlinked
	// parent directory) could redirect a secret outside the persistent data
	// directory. Resolve the nearest existing ancestor before accepting it.
	probe := target
	for {
		resolved, evalErr := filepath.EvalSymlinks(probe)
		if evalErr == nil {
			resolvedRoot, rootErr := filepath.EvalSymlinks(root)
			if rootErr != nil { resolvedRoot = root }
			resolvedRel, relErr := filepath.Rel(resolvedRoot, resolved)
			return relErr == nil && resolvedRel != ".." && !strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator))
		}
		if !os.IsNotExist(evalErr) { return false }
		parent := filepath.Dir(probe)
		if parent == probe { return false }
		probe = parent
	}
}

func validInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 15 || name == "." || name == ".." { return false }
	for _, r := range name { if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') { return false } }
	return true
}

func validateKey(value string) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 { return errors.New("must be a base64-encoded 32-byte WireGuard key") }
	return nil
}

func networksOverlap(a, b net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}
