package commanddispatch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/agent"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/commandjournal"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
)

const dispatcherConfig = `apiVersion: s5m.wireguard/v1alpha1
interface:
  name: wg0
  role: server
  backend: linux-kernel
  privateKeyFile: private.key
  addresses:
    - 10.77.0.1/24
  listenPort: 51820
peers: []
`

type fakeRuntime struct {
	mu           sync.Mutex
	applies      int
	stops        int
	statuses     int
	deadlineSeen bool
	entered      chan struct{}
	release      chan struct{}
}

func (f *fakeRuntime) Probe(context.Context) wr.Capabilities {
	return wr.Capabilities{Backend: "linux-kernel", Available: true}
}
func (f *fakeRuntime) Apply(context.Context, config.Config) error {
	f.mu.Lock()
	f.applies++
	f.mu.Unlock()
	return nil
}
func (f *fakeRuntime) Status(ctx context.Context, _ string) (wr.Status, error) {
	f.mu.Lock()
	f.statuses++
	_, f.deadlineSeen = ctx.Deadline()
	f.mu.Unlock()
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	if f.release != nil {
		<-f.release
	}
	return wr.Status{Interface: "wg0", Backend: "linux-kernel", Running: true}, nil
}
func (f *fakeRuntime) Stop(context.Context, string) error {
	f.mu.Lock()
	f.stops++
	f.mu.Unlock()
	return nil
}

func setupDispatcher(t *testing.T, runtime wr.Runtime) (*Dispatcher, string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "private.key"), []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(dispatcherConfig), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadWithDataDir(configPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := configRevision(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(dir, configPath, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return d, dir, revision
}

func configRevision(cfg config.Config) (string, error) {
	// Keep the test fixture aligned with the Agent's canonical revision function.
	return agent.ConfigRevision(cfg)
}

func makeCommand(t *testing.T, id, kind, revision, configSHA string, deadline time.Time) json.RawMessage {
	t.Helper()
	payload := json.RawMessage(`{"interface":"wg0"}`)
	cmd := command{
		ID: id, Type: kind, Deadline: deadline, Revision: revision,
		PayloadSHA256: commandjournal.PayloadHash(payload), ConfigSHA256: configSHA, Payload: payload,
	}
	raw, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDispatcherPassesCommandDeadlineToRuntime(t *testing.T) {
	runtime := &fakeRuntime{}
	d, _, revision := setupDispatcher(t, runtime)
	raw := makeCommand(t, "status-deadline", "status", revision, "", time.Now().Add(time.Minute))
	if status, _ := d.Handle(context.Background(), raw); status != "success" {
		t.Fatalf("status command = %q", status)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.deadlineSeen {
		t.Fatal("runtime did not receive a context bounded by command deadline")
	}
}

func TestLocalFileHashRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte("config"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := localFileHash(link); err == nil {
		t.Fatal("symlinked config file was accepted")
	}
}

func TestNewRejectsConfigOutsideDataVolumeAndSymlink(t *testing.T) {
	runtime := &fakeRuntime{}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte(dispatcherConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, outside, runtime); err == nil {
		t.Fatal("config path outside data directory was accepted")
	}
	if err := os.Symlink(outside, filepath.Join(dir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, filepath.Join(dir, "config.yaml"), runtime); err == nil {
		t.Fatal("symlinked config target was accepted")
	}
}

func TestApplyCommandIsJournaledAndDuplicateIsNotReexecuted(t *testing.T) {
	runtime := &fakeRuntime{}
	d, dir, revision := setupDispatcher(t, runtime)
	configBytes, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	configSHA := commandjournal.PayloadHash(configBytes)
	raw := makeCommand(t, "apply-1", "apply", revision, configSHA, time.Now().Add(time.Minute))

	status, message := d.Handle(context.Background(), raw)
	if status != "success" || message != "WireGuard configuration applied" {
		t.Fatalf("first apply result = %q %q", status, message)
	}
	status, _ = d.Handle(context.Background(), raw)
	if status != "success" {
		t.Fatalf("duplicate apply result = %q", status)
	}
	runtime.mu.Lock()
	applies := runtime.applies
	runtime.mu.Unlock()
	if applies != 1 {
		t.Fatalf("duplicate command executed %d times, want 1", applies)
	}
	record, ok := d.Journal.Get("apply-1")
	if !ok || record.State != commandjournal.StateSucceeded {
		t.Fatalf("journal record = %#v, exists=%t", record, ok)
	}
}

func TestDispatcherRejectsUnknownFieldsAndUnsupportedTypes(t *testing.T) {
	runtime := &fakeRuntime{}
	d, _, revision := setupDispatcher(t, runtime)
	raw := makeCommand(t, "shell-1", "shell", revision, "", time.Now().Add(time.Minute))
	if status, _ := d.Handle(context.Background(), raw); status != "failed" {
		t.Fatal("unsupported command type was accepted")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(makeCommand(t, "extra-1", "status", revision, "", time.Now().Add(time.Minute)), &object); err != nil {
		t.Fatal(err)
	}
	object["shell"] = json.RawMessage(`"id"`)
	encoded, _ := json.Marshal(object)
	if status, _ := d.Handle(context.Background(), encoded); status != "failed" {
		t.Fatal("unexpected command field was accepted")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.statuses != 0 || runtime.applies != 0 || runtime.stops != 0 {
		t.Fatal("invalid command reached the runtime")
	}
}

func TestDifferentCommandsForSameInterfaceAreSerialized(t *testing.T) {
	runtime := &fakeRuntime{entered: make(chan struct{}, 2), release: make(chan struct{})}
	d, _, revision := setupDispatcher(t, runtime)
	first := makeCommand(t, "status-serial-1", "status", revision, "", time.Now().Add(time.Minute))
	second := makeCommand(t, "status-serial-2", "status", revision, "", time.Now().Add(time.Minute))
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		if status, _ := d.Handle(context.Background(), first); status != "success" {
			t.Errorf("first status command = %q", status)
		}
	}()
	select {
	case <-runtime.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first command did not enter runtime")
	}
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		if status, _ := d.Handle(context.Background(), second); status != "success" {
			t.Errorf("second status command = %q", status)
		}
	}()
	select {
	case <-runtime.entered:
		t.Fatal("second command entered runtime concurrently for the same interface")
	case <-time.After(100 * time.Millisecond):
	}
	close(runtime.release)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first command did not finish")
	}
	select {
	case <-runtime.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("second command did not enter runtime after first completed")
	}
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("second command did not finish")
	}
}

func TestInterfaceLockWaitHonorsCommandDeadline(t *testing.T) {
	runtime := &fakeRuntime{entered: make(chan struct{}, 2), release: make(chan struct{})}
	d, _, revision := setupDispatcher(t, runtime)
	first := makeCommand(t, "status-lock-holder", "status", revision, "", time.Now().Add(time.Minute))
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		if status, _ := d.Handle(context.Background(), first); status != "success" {
			t.Errorf("lock holder status = %q", status)
		}
	}()
	select {
	case <-runtime.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first command did not acquire interface lock")
	}

	second := makeCommand(t, "status-lock-waiter", "status", revision, "", time.Now().Add(40*time.Millisecond))
	started := time.Now()
	status, message := d.Handle(context.Background(), second)
	if status != "failed" || !strings.Contains(message, "waiting for interface lock") {
		t.Fatalf("expired lock waiter result = %q %q", status, message)
	}
	if time.Since(started) > time.Second {
		t.Fatal("command deadline was not enforced while waiting for interface lock")
	}
	record, ok := d.Journal.Get("status-lock-waiter")
	if !ok || record.State != commandjournal.StateFailed {
		t.Fatalf("expired lock waiter was not durably completed as failed: %#v exists=%t", record, ok)
	}
	close(runtime.release)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first command did not finish after release")
	}
	runtime.mu.Lock()
	statuses := runtime.statuses
	runtime.mu.Unlock()
	if statuses != 1 {
		t.Fatalf("expired waiter reached runtime; status calls=%d", statuses)
	}
}

func TestInterruptedCommandIsNotReplayedAfterRestart(t *testing.T) {
	runtime := &fakeRuntime{}
	d, dir, revision := setupDispatcher(t, runtime)
	payload := json.RawMessage(`{"interface":"wg0"}`)
	record := commandjournal.Record{
		ID: "status-interrupted", Type: "status", PayloadSHA256: commandjournal.PayloadHash(payload),
		Deadline: time.Now().Add(time.Minute), Revision: revision,
	}
	if _, execute, err := d.Journal.Begin(record); err != nil || !execute {
		t.Fatalf("seed running record: execute=%t err=%v", execute, err)
	}
	reopened, err := New(dir, filepath.Join(dir, "config.yaml"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	raw := makeCommand(t, record.ID, "status", revision, "", time.Now().Add(time.Minute))
	if status, _ := reopened.Handle(context.Background(), raw); status != "failed" {
		t.Fatal("interrupted command was replayed")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.statuses != 0 {
		t.Fatal("interrupted command reached runtime after restart")
	}
}
