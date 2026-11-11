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

func TestBeginPreservesExpiredTerminalRecordsToPreventIDReplay(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < maxRecords; i++ {
		rec := input()
		rec.ID = fmt.Sprintf("expired-%04d", i)
		rec.Deadline = now.Add(-time.Minute)
		rec.State = StateSucceeded
		rec.StartedAt = now.Add(-2 * time.Minute)
		rec.UpdatedAt = now.Add(-time.Minute)
		j.records[rec.ID] = rec
	}
	if _, _, err := j.Begin(input()); err == nil || !strings.Contains(err.Error(), "prevent command ID replay") {
		t.Fatalf("expected fail-closed capacity error, got %v", err)
	}
	if len(j.records) != maxRecords {
		t.Fatalf("expired command tombstones were discarded: got %d records", len(j.records))
	}
	if _, ok := j.records["expired-0000"]; !ok {
		t.Fatal("expired command ID tombstone was removed")
	}
}

func TestInterruptedCommandIDCannotBeReplayedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, execute, err := j.Begin(input())
	if err != nil || !execute || first.State != StateRunning {
		t.Fatalf("initial begin: record=%#v execute=%v err=%v", first, execute, err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	retry, execute, err := reopened.Begin(input())
	if err != nil {
		t.Fatal(err)
	}
	if execute || retry.State != StateInterrupted {
		t.Fatalf("interrupted command was replayable: record=%#v execute=%v", retry, execute)
	}
}

func TestExpiredCommandTombstonesSurviveRestartAndRejectExtendedDeadlineReplay(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < maxRecords; i++ {
		rec := input()
		rec.ID = fmt.Sprintf("persisted-expired-%04d", i)
		rec.Deadline = now.Add(-time.Minute)
		rec.State = StateSucceeded
		rec.StartedAt = now.Add(-2 * time.Minute)
		rec.UpdatedAt = now.Add(-time.Minute)
		j.records[rec.ID] = rec
	}
	if err := j.persist(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	retry := input()
	retry.ID = "persisted-expired-0000"
	retry.Deadline = time.Now().Add(23 * time.Hour)
	record, execute, err := reopened.Begin(retry)
	if err != nil {
		t.Fatal(err)
	}
	if execute || record.State != StateSucceeded {
		t.Fatalf("extended-deadline duplicate was replayable: record=%#v execute=%v", record, execute)
	}
}
