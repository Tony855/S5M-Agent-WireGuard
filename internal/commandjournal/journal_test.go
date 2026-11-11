package commandjournal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func input() Record {
	return Record{
		ID:            "cmd-1",
		Type:          "apply",
		PayloadSHA256: PayloadHash([]byte(`{"interface":"wg0"}`)),
		Deadline:      time.Now().Add(time.Minute),
		Revision:      "rev-7",
	}
}

func TestBeginPersistsAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	first, execute, err := j.Begin(input())
	if err != nil || !execute || first.State != StateRunning {
		t.Fatalf("first begin: %#v %v %v", first, execute, err)
	}
	second, execute, err := j.Begin(input())
	if err != nil || execute || second.ID != first.ID {
		t.Fatalf("duplicate begin: %#v %v %v", second, execute, err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get("cmd-1")
	if !ok || got.State != StateInterrupted {
		t.Fatalf("running command must recover as interrupted: %#v", got)
	}
}

func TestBeginRejectsConflictingIDAndPayload(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.Begin(input()); err != nil {
		t.Fatal(err)
	}

	conflict := input()
	conflict.PayloadSHA256 = PayloadHash([]byte("different"))
	if _, _, err = j.Begin(conflict); err == nil {
		t.Fatal("expected conflicting command ID rejection")
	}
}

func TestCompleteRequiresMatchingHashAndRunningState(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := j.Begin(input())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Complete(rec.ID, PayloadHash([]byte("wrong")), true, "ok"); err == nil {
		t.Fatal("expected hash mismatch")
	}

	done, err := j.Complete(rec.ID, rec.PayloadSHA256, true, "applied")
	if err != nil || done.State != StateSucceeded {
		t.Fatalf("complete: %#v %v", done, err)
	}
	if _, err = j.Complete(rec.ID, rec.PayloadSHA256, true, "replay"); err == nil {
		t.Fatal("expected terminal record rejection")
	}
}

func TestJournalRejectsSymlinkedRuntimeDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "runtime")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("expected symlinked runtime directory rejection")
	}
}

func TestJournalRejectsUnsafeFilePermissions(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "runtime")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "commands.json")
	if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("expected unsafe journal rejection, got %v", err)
	}
}

func TestBeginRejectsUnsupportedCommandType(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := input()
	rec.Type = "shell"
	if _, _, err = j.Begin(rec); err == nil {
		t.Fatal("expected unsupported command rejection")
	}
}
