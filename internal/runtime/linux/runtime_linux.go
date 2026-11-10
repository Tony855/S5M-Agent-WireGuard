//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/secret"
)

type Runner interface {
	LookPath(string) (string, error)
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

type Runtime struct {
	DataDir string
	Runner  Runner
}

func New(dataDir string) *Runtime { return &Runtime{DataDir: dataDir, Runner: execRunner{}} }

func (r *Runtime) runner() Runner {
	if r.Runner != nil {
		return r.Runner
	}
	return execRunner{}
}

func (r *Runtime) Probe(context.Context) wr.Capabilities {
	caps := wr.Capabilities{Backend: "linux-kernel", SupportsClient: true, SupportsServer: true}
	if _, err := r.runner().LookPath("ip"); err != nil {
		caps.Reason = "iproute2 ip binary is unavailable"
		return caps
	}
	if _, err := r.runner().LookPath("wg"); err != nil {
		caps.Reason = "wireguard-tools wg binary is unavailable"
		return caps
	}
	caps.Available = true
	caps.Features = []string{"kernel-wireguard", "ipv4", "ipv6"}
	return caps
}

func (r *Runtime) Apply(ctx context.Context, cfg config.Config) error {
	if cfg.Interface.Backend != "linux-kernel" {
		return errors.New("Linux runtime only accepts linux-kernel backend")
	}
	if err := cfg.Validate(r.DataDir); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	if !r.Probe(ctx).Available {
		return errors.New("Linux WireGuard runtime prerequisites are unavailable")
	}
	for _, peer := range cfg.Peers {
		for _, cidr := range peer.AllowedIPs {
			if cidr == "0.0.0.0/0" || cidr == "::/0" {
				return errors.New("default-route AllowedIPs are blocked until explicit route policy is implemented")
			}
		}
	}

	run := r.runner()
	if _, err := run.Run(ctx, "ip", "link", "show", "dev", cfg.Interface.Name); err == nil {
		return errors.New("interface already exists; refusing non-transactional in-place update; stop before applying a replacement")
	}
	if _, err := run.Run(ctx, "ip", "link", "add", "dev", cfg.Interface.Name, "type", "wireguard"); err != nil {
		return fmt.Errorf("create WireGuard interface: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = run.Run(context.Background(), "ip", "link", "delete", "dev", cfg.Interface.Name)
		}
	}()

	conf, cleanup, err := r.buildWGConfig(cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err = run.Run(ctx, "wg", "setconf", cfg.Interface.Name, conf); err != nil {
		return fmt.Errorf("apply WireGuard configuration: %w", err)
	}
	if cfg.Interface.MTU > 0 {
		if _, err = run.Run(ctx, "ip", "link", "set", "dev", cfg.Interface.Name, "mtu", fmt.Sprint(cfg.Interface.MTU)); err != nil {
			return fmt.Errorf("set MTU: %w", err)
		}
	}
	for _, address := range cfg.Interface.Addresses {
		if _, err = run.Run(ctx, "ip", "address", "replace", address, "dev", cfg.Interface.Name); err != nil {
			return fmt.Errorf("assign interface address: %w", err)
		}
	}
	if _, err = run.Run(ctx, "ip", "link", "set", "dev", cfg.Interface.Name, "up"); err != nil {
		return fmt.Errorf("bring interface up: %w", err)
	}
	committed = true
	return nil
}

func (r *Runtime) buildWGConfig(cfg config.Config) (string, func(), error) {
	key, err := secret.ReadKey(r.DataDir, cfg.Interface.PrivateKeyFile)
	if err != nil {
		return "", func() {}, fmt.Errorf("read private key: %w", err)
	}
	defer wipe(key)

	var b strings.Builder
	b.WriteString("private_key = ")
	b.WriteString(base64.StdEncoding.EncodeToString(key))
	b.WriteByte('\n')
	if cfg.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port = %d\n", cfg.Interface.ListenPort)
	}
	for _, peer := range cfg.Peers {
		b.WriteString("\n[Peer]\npublic_key = ")
		b.WriteString(peer.PublicKey)
		b.WriteByte('\n')
		if peer.Endpoint != "" {
			b.WriteString("endpoint = ")
			b.WriteString(peer.Endpoint)
			b.WriteByte('\n')
		}
		b.WriteString("allowed_ips = ")
		b.WriteString(strings.Join(peer.AllowedIPs, ", "))
		b.WriteByte('\n')
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval = %d\n", peer.PersistentKeepalive)
		}
		if peer.PresharedKeyFile != "" {
			psk, readErr := secret.ReadKey(r.DataDir, peer.PresharedKeyFile)
			if readErr != nil {
				return "", func() {}, fmt.Errorf("read peer preshared key: %w", readErr)
			}
			b.WriteString("preshared_key = ")
			b.WriteString(base64.StdEncoding.EncodeToString(psk))
			b.WriteByte('\n')
			wipe(psk)
		}
	}

	dir := filepath.Join(r.DataDir, "runtime")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", func() {}, fmt.Errorf("create runtime directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "wg-setconf-*.conf")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temporary config: %w", err)
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := file.WriteString(b.String()); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (r *Runtime) Status(ctx context.Context, name string) (wr.Status, error) {
	if !validName(name) {
		return wr.Status{}, errors.New("invalid interface name")
	}
	status := wr.Status{Interface: name, Backend: "linux-kernel"}
	if _, err := r.runner().Run(ctx, "ip", "link", "show", "dev", name); err != nil {
		return status, nil
	}
	status.Running = true
	if _, err := r.runner().Run(ctx, "wg", "show", name); err != nil {
		status.LastError = "interface exists but WireGuard status could not be read"
	}
	return status, nil
}

func (r *Runtime) Stop(ctx context.Context, name string) error {
	if !validName(name) {
		return errors.New("invalid interface name")
	}
	if _, err := r.runner().Run(ctx, "ip", "link", "delete", "dev", name); err != nil {
		return fmt.Errorf("delete WireGuard interface: %w", err)
	}
	return nil
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if !(c == '-' || c == '_' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
