package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var ErrUnsafePermissions = errors.New("secret file permissions must not grant group or other access")

// GeneratePrivateKey creates a WireGuard private key without printing or
// returning the key material. Existing files are never overwritten.
func GeneratePrivateKey(dataDir, relativePath string) error {
	path, err := resolveDataPath(dataDir, relativePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create secret directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("secure secret directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generate WireGuard key: %w", err)
	}
	defer wipe(key)
	encoded := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	defer wipe(encoded)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create secret file: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write secret file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync secret file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close secret file: %w", err)
	}
	return nil
}

// ReadKey returns decoded key bytes. The caller must wipe the returned slice
// as soon as the backend has consumed it.
func ReadKey(dataDir, relativePath string) ([]byte, error) {
	path, err := resolveDataPath(dataDir, relativePath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect secret file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("secret path must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnsafePermissions
	}
	if info.Size() > 128 {
		return nil, errors.New("secret file has an invalid size")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}
	trimmed := bytes.TrimSpace(encoded)
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(raw, trimmed)
	if err != nil || n != 32 {
		return nil, errors.New("secret file must contain a base64-encoded 32-byte key")
	}
	return raw[:n], nil
}

func resolveDataPath(dataDir, relativePath string) (string, error) {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return "", errors.New("secret path must be relative to the data directory")
	}
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return "", fmt.Errorf("resolve data directory: %w", err)
	}
	target, err := filepath.Abs(filepath.Join(root, relativePath))
	if err != nil {
		return "", fmt.Errorf("resolve secret path: %w", err)
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("secret path escapes the data directory")
	}
	// Resolve existing parents to reject symlink-based escapes before touching
	// the target. The target itself is opened with O_EXCL when created.
	probe := filepath.Dir(target)
	for {
		resolved, evalErr := filepath.EvalSymlinks(probe)
		if evalErr == nil {
			resolvedRoot, rootErr := filepath.EvalSymlinks(root)
			if rootErr != nil {
				resolvedRoot = root
			}
			resolvedRel, relErr := filepath.Rel(resolvedRoot, resolved)
			if relErr != nil || resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) {
				return "", errors.New("secret path resolves outside the data directory")
			}
			return target, nil
		}
		if !os.IsNotExist(evalErr) {
			return "", fmt.Errorf("inspect secret parent: %w", evalErr)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", errors.New("cannot resolve secret parent directory")
		}
		probe = parent
	}
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
