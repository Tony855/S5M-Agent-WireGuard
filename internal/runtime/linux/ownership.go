//go:build linux

package linux

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
)

const managedMarkerVersion = 2

type managedMarkerV2 struct {
	Version      int       `json:"version"`
	Interface    string    `json:"interface"`
	ConfigSHA256 string    `json:"config_sha256"`
	Revision     string    `json:"revision"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// configFingerprint hashes the validated, non-secret configuration structure.
// Private key material is deliberately excluded; the config stores only its
// data-directory-relative file path.
func configFingerprint(cfg config.Config) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", errors.New("encode WireGuard config fingerprint")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func newManagedMarker(name string, cfg config.Config) ([]byte, error) {
	fingerprint, err := configFingerprint(cfg)
	if err != nil {
		return nil, err
	}
	marker := managedMarkerV2{
		Version:      managedMarkerVersion,
		Interface:    name,
		ConfigSHA256: fingerprint,
		Revision:     fingerprint,
		UpdatedAt:    time.Now().UTC(),
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return nil, errors.New("encode managed interface marker")
	}
	return append(data, '\n'), nil
}

func validateManagedMarker(data []byte, name string) error {
	// Keep existing v1 markers readable so upgrades do not orphan interfaces
	// created by earlier Agent versions. Legacy markers remain create-only.
	if bytes.Equal(data, []byte("s5m-agent-wireguard/v1\n"+name+"\n")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var marker managedMarkerV2
	if err := dec.Decode(&marker); err != nil {
		return errors.New("managed interface marker is invalid")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("managed interface marker has trailing data")
	}
	if marker.Version != managedMarkerVersion || marker.Interface != name ||
		len(marker.ConfigSHA256) != sha256.Size*2 || len(marker.Revision) != sha256.Size*2 ||
		marker.ConfigSHA256 != marker.Revision || marker.UpdatedAt.IsZero() {
		return errors.New("managed interface marker is invalid")
	}
	if _, err := hex.DecodeString(marker.ConfigSHA256); err != nil {
		return errors.New("managed interface marker fingerprint is invalid")
	}
	return nil
}

func (r *Runtime) writeManagedStateMarker(name string, cfg config.Config) error {
	dir, err := r.runtimeDir()
	if err != nil {
		return err
	}
	data, err := newManagedMarker(name, cfg)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name+".managed")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create managed interface marker: %w", err)
	}
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return errors.New("write managed interface marker")
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return errors.New("sync managed interface marker")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("close managed interface marker")
	}
	directory, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(path)
		return errors.New("open managed runtime directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		_ = os.Remove(path)
		return errors.New("sync managed runtime directory")
	}
	return nil
}
