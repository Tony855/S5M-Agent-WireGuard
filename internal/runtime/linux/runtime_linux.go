//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		// stderr from wg may echo the rejected configuration line, including private keys.
		// Keep command failures useful without leaking command output into logs or RPC errors.
		return nil, fmt.Errorf("%s failed: %w", name, err)
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

func (r *Runtime) Probe(ctx context.Context) wr.Capabilities {
	caps := wr.Capabilities{Backend: "linux-kernel", SupportsClient: true, SupportsServer: true}
	if _, err := r.runner().LookPath("ip"); err != nil {
		caps.Reason = "iproute2 ip binary is unavailable"
		return caps
	}
	if _, err := r.runner().LookPath("wg"); err != nil {
		caps.Reason = "wireguard-tools wg binary is unavailable"
		return caps
	}
	// Binary presence alone does not prove that the running kernel exposes the
	// WireGuard generic-netlink API (for example, a container may lack the
	// host kernel module or the host may not support WireGuard).
	if _, err := r.runner().Run(ctx, "wg", "show", "interfaces"); err != nil {
		caps.Reason = "kernel WireGuard generic-netlink API is unavailable"
		return caps
	}
	caps.Available = true
	caps.Features = []string{"kernel-wireguard", "ipv4", "ipv6", "peer-handshake-status", "transfer-counters"}
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
	markerCreated := false
	defer func() {
		if !committed {
			if markerCreated {
				_ = os.Remove(r.markerPath(cfg.Interface.Name))
			}
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
	if err := r.writeManagedMarker(cfg.Interface.Name); err != nil {
		return fmt.Errorf("record managed interface ownership: %w", err)
	}
	markerCreated = true
	committed = true
	return nil
}

func (r *Runtime) buildWGConfig(cfg config.Config) (string, func(), error) {
	key, err := secret.ReadKey(r.DataDir, cfg.Interface.PrivateKeyFile)
	if err != nil {
		return "", func() {}, fmt.Errorf("read private key: %w", err)
	}
	defer wipe(key)

	var b bytes.Buffer
	defer func() { wipe(b.Bytes()) }()
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

	dir, err := r.runtimeDir()
	if err != nil {
		return "", func() {}, fmt.Errorf("prepare runtime directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "wg-setconf-*.conf")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temporary config: %w", err)
	}
	path := file.Name()
	cleanup := func() {
		// Best-effort overwrite before unlinking: unlink alone leaves file contents recoverable
		// on some filesystems. This is defense in depth, not a guarantee on SSD/COW storage.
		if info, statErr := os.Stat(path); statErr == nil && info.Size() > 0 {
			if wipeFile, openErr := os.OpenFile(path, os.O_WRONLY, 0); openErr == nil {
				zeroes := make([]byte, 32*1024)
				remaining := info.Size()
				for remaining > 0 {
					chunk := int64(len(zeroes))
					if remaining < chunk {
						chunk = remaining
					}
					n, writeErr := wipeFile.Write(zeroes[:chunk])
					if writeErr != nil || n == 0 {
						break
					}
					remaining -= int64(n)
				}
				_ = wipeFile.Sync()
				_ = wipeFile.Close()
				wipe(zeroes)
			}
		}
		_ = os.Remove(path)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := file.Write(b.Bytes()); err != nil {
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
	if err := r.verifyManagedMarker(name); err != nil {
		return wr.Status{}, err
	}
	status := wr.Status{Interface: name, Backend: "linux-kernel"}
	link, err := r.runner().Run(ctx, "ip", "link", "show", "dev", name)
	if err != nil {
		return status, nil
	}
	run := r.runner()
	fields := []string{"listen-port", "peers", "endpoints", "allowed-ips", "latest-handshakes", "transfer", "persistent-keepalive"}
	telemetry := make(map[string]string, len(fields))
	for _, field := range fields {
		output, showErr := run.Run(ctx, "wg", "show", name, field)
		if showErr != nil {
			status.LastError = "interface exists but is not confirmed as a WireGuard interface or telemetry is unavailable"
			return status, nil
		}
		telemetry[field] = string(output)
	}
	status.Running = linkIsUp(string(link))
	if err := parseTelemetry(telemetry, &status); err != nil {
		status.LastError = "WireGuard telemetry output was malformed"
		return status, fmt.Errorf("parse WireGuard telemetry: %w", err)
	}
	return status, nil
}

func linkIsUp(output string) bool {
	start := strings.IndexByte(output, '<')
	end := strings.IndexByte(output, '>')
	if start < 0 || end <= start {
		return false
	}
	for _, flag := range strings.Split(output[start+1:end], ",") {
		if flag == "UP" {
			return true
		}
	}
	return false
}

func parseTelemetry(values map[string]string, status *wr.Status) error {
	port, err := strconv.Atoi(strings.TrimSpace(values["listen-port"]))
	if err != nil || port < 0 || port > 65535 {
		return errors.New("invalid listen port")
	}
	status.ListenPort = port
	endpoints, err := parsePairs(values["endpoints"])
	if err != nil {
		return fmt.Errorf("parse endpoints: %w", err)
	}
	allowedIPs, err := parsePairs(values["allowed-ips"])
	if err != nil {
		return fmt.Errorf("parse allowed IPs: %w", err)
	}
	handshakes, err := parsePairs(values["latest-handshakes"])
	if err != nil {
		return fmt.Errorf("parse handshakes: %w", err)
	}
	transfers, err := parsePairs(values["transfer"])
	if err != nil {
		return fmt.Errorf("parse transfer counters: %w", err)
	}
	keepalives, err := parsePairs(values["persistent-keepalive"])
	if err != nil {
		return fmt.Errorf("parse keepalive values: %w", err)
	}
	for _, key := range strings.Fields(values["peers"]) {
		peer := wr.PeerStatus{PublicKey: key}
		if endpoint := endpoints[key]; endpoint != "" && endpoint != "(none)" {
			peer.Endpoint = endpoint
		}
		if cidrs := allowedIPs[key]; cidrs != "" && cidrs != "(none)" {
			peer.AllowedIPs = strings.Split(cidrs, ",")
		}
		if raw := handshakes[key]; raw != "" {
			seconds, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil || seconds < 0 {
				return fmt.Errorf("invalid handshake timestamp for peer %s", key)
			}
			if seconds > 0 {
				t := time.Unix(seconds, 0).UTC()
				peer.LastHandshake = &t
			}
		}
		if raw := transfers[key]; raw != "" {
			counters := strings.Fields(raw)
			if len(counters) != 2 {
				return fmt.Errorf("invalid transfer counters for peer %s", key)
			}
			peer.ReceiveBytes, err = strconv.ParseUint(counters[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid receive counter for peer %s", key)
			}
			peer.TransmitBytes, err = strconv.ParseUint(counters[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid transmit counter for peer %s", key)
			}
		}
		if raw := keepalives[key]; raw != "" && raw != "off" {
			peer.PersistentKeepalive, err = strconv.Atoi(raw)
			if err != nil || peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
				return fmt.Errorf("invalid keepalive for peer %s", key)
			}
		}
		status.Peers = append(status.Peers, peer)
	}
	return nil
}

func parsePairs(output string) (map[string]string, error) {
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.New("expected key and value")
		}
		result[fields[0]] = strings.Join(fields[1:], " ")
	}
	return result, nil
}

func (r *Runtime) Stop(ctx context.Context, name string) error {
	if !validName(name) {
		return errors.New("invalid interface name")
	}
	if err := r.verifyManagedMarker(name); err != nil {
		return err
	}
	run := r.runner()
	if _, err := run.Run(ctx, "wg", "show", name); err != nil {
		return errors.New("refusing to delete an interface that is not confirmed as WireGuard")
	}
	if _, err := run.Run(ctx, "ip", "link", "delete", "dev", name); err != nil {
		return fmt.Errorf("delete WireGuard interface: %w", err)
	}
	if err := os.Remove(r.markerPath(name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove managed interface marker: %w", err)
	}
	return nil
}

func (r *Runtime) runtimeDir() (string, error) {
	root, err := filepath.Abs(r.DataDir)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(resolvedRoot, "runtime")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("runtime path must be a real directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", err
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedDir)
	if err != nil || rel != "runtime" {
		return "", errors.New("runtime directory escapes data directory")
	}
	return dir, nil
}

func (r *Runtime) markerPath(name string) string {
	return filepath.Join(r.DataDir, "runtime", name+".managed")
}

func (r *Runtime) writeManagedMarker(name string) error {
	dir, err := r.runtimeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name+".managed")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	data := []byte("s5m-agent-wireguard/v1\n" + name + "\n")
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func (r *Runtime) verifyManagedMarker(name string) error {
	dir, err := r.runtimeDir()
	if err != nil {
		return errors.New("managed runtime directory is unavailable or unsafe")
	}
	path := filepath.Join(dir, name+".managed")
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("interface is not registered as managed by this agent")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("managed interface marker has unsafe file type or permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("managed interface marker cannot be read")
	}
	if string(data) != "s5m-agent-wireguard/v1\n"+name+"\n" {
		return errors.New("managed interface marker is invalid")
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
