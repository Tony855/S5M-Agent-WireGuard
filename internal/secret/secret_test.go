package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAndReadPrivateKey(t *testing.T) {
	root := t.TempDir()
	if err := GeneratePrivateKey(root, "keys/server.key"); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "keys/server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}
	key, err := ReadKey(root, "keys/server.key")
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
	wipe(key)
	if err := GeneratePrivateKey(root, "keys/server.key"); err == nil {
		t.Fatal("refused to overwrite existing key")
	}
}

func TestRejectsInsecurePermissions(t *testing.T) {
	root := t.TempDir()
	if err := GeneratePrivateKey(root, "server.key"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "server.key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(root, "server.key"); err != ErrUnsafePermissions {
		t.Fatalf("expected unsafe permission error, got %v", err)
	}
}

func TestRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := GeneratePrivateKey(root, "escape/key"); err == nil {
		t.Fatal("generated key outside data directory through symlink")
	}
}

func TestRejectsAbsoluteAndTraversalPaths(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"/tmp/key", "../../etc/shadow"} {
		if err := GeneratePrivateKey(root, path); err == nil {
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
}
