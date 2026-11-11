package commandjournal

import (
	"fmt"
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

func TestBeginCompactsOnlyExpiredTerminalRecords(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < maxRecords-1; i++ {
		rec := input()
		rec.ID = fmt.Sprintf("expired-%04d", i)
		rec.Deadline = now.Add(-time.Minute)
		rec.State = StateSucceeded
		rec.StartedAt = now.Add(-2 * time.Minute)
		rec.UpdatedAt = now.Add(-time.Minute)
		j.records[rec.ID] = rec
	}
	running := input()
	running.ID = "expired-running"
	running.Deadline = now.Add(-time.Minute)
	running.State = StateRunning
	running.StartedAt = now.Add(-2 * time.Minute)
	running.UpdatedAt = now.Add(-time.Minute)
	j.records[running.ID] = running
	active := input()
	active.ID = "active-terminal"
	active.Deadline = now.Add(time.Hour)
	active.State = StateFailed
	active.StartedAt = now.Add(-time.Minute)
	active.UpdatedAt = now
	j.records[active.ID] = active
	if len(j.records) != maxRecords+1 {
		t.Fatalf("fixture size = %d, want %d", len(j.records), maxRecords+1)
	}

	command := input()
	command.ID = "new-command"
	if _, execute, err := j.Begin(command); err != nil || !execute {
		t.Fatalf("Begin after compaction: execute=%v err=%v", execute, err)
	}
	if _, ok := j.records["expired-0000"]; ok {
		t.Fatal("expired terminal record was not compacted")
	}
	if _, ok := j.records["expired-running"]; !ok {
		t.Fatal("expired running record must be retained for reconciliation")
	}
	if _, ok := j.records["active-terminal"]; !ok {
		t.Fatal("unexpired terminal record must be retained for redelivery deduplication")
	}
	if _, ok := j.records["new-command"]; !ok {
		t.Fatal("new command was not persisted")
	}

	reopened, err := Open(j.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("expired-0000"); ok {
		t.Fatal("compacted record reappeared after restart")
	}
	if got, ok := reopened.Get("expired-running"); !ok || got.State != StateInterrupted {
		t.Fatalf("running record was not preserved/recovered as interrupted: %#v", got)
	}
	if _, ok := reopened.Get("active-terminal"); !ok {
		t.Fatal("unexpired terminal record was not persisted")
	}
}

func TestBeginRejectsWhenJournalHasNoExpiredTerminalRecords(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < maxRecords; i++ {
		rec := input()
		rec.ID = fmt.Sprintf("running-%04d", i)
		rec.Deadline = now.Add(time.Hour)
		rec.State = StateRunning
		rec.StartedAt = now
		rec.UpdatedAt = now
		j.records[rec.ID] = rec
	}
	if _, _, err := j.Begin(input()); err == nil || !strings.Contains(err.Error(), "cannot be discarded") {
		t.Fatalf("expected fail-closed capacity error, got %v", err)
	}
	if len(j.records) != maxRecords {
		t.Fatalf("running records were discarded: got %d records", len(j.records))
	}
}
