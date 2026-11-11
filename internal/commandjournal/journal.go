package commandjournal

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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxJournalBytes = 4 << 20
	maxRecords      = 4096
)

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type State string

const (
	StateRunning     State = "running"
	StateSucceeded   State = "succeeded"
	StateFailed      State = "failed"
	StateInterrupted State = "interrupted"
)

type Record struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	PayloadSHA256 string    `json:"payload_sha256"`
	Deadline      time.Time `json:"deadline"`
	Revision      string    `json:"revision"`
	ConfigSHA256  string    `json:"config_sha256,omitempty"`
	State         State     `json:"state"`
	StartedAt     time.Time `json:"started_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Result        string    `json:"result,omitempty"`
}

type Journal struct {
	mu      sync.Mutex
	dir     string
	path    string
	records map[string]Record
}

func Open(dataDir string) (*Journal, error) {
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, errors.New("command journal data directory is invalid")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("command journal data directory is unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("command journal data directory must be a real directory")
	}
	dir := filepath.Join(root, "runtime")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("cannot create command journal directory")
	}
	info, err = os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("command journal directory is unsafe")
	}
	j := &Journal{dir: dir, path: filepath.Join(dir, "commands.json"), records: make(map[string]Record)}
	if err := j.load(); err != nil {
		return nil, err
	}
	// A process may have died after persisting "running". Never replay such a
	// command automatically: its external side effect may already have happened.
	changed := false
	now := time.Now().UTC()
	for id, rec := range j.records {
		if rec.State == StateRunning {
			rec.State = StateInterrupted
			rec.Result = "agent restarted while command execution state was running; manual reconciliation required"
			rec.UpdatedAt = now
			j.records[id] = rec
			changed = true
		}
	}
	if changed {
		if err := j.persist(); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func (j *Journal) Begin(input Record) (Record, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := validateInput(input); err != nil {
		return Record{}, false, err
	}
	if existing, ok := j.records[input.ID]; ok {
		if existing.Type != input.Type || existing.PayloadSHA256 != strings.ToLower(input.PayloadSHA256) ||
			existing.Revision != input.Revision || existing.ConfigSHA256 != strings.ToLower(input.ConfigSHA256) {
			return Record{}, false, errors.New("command ID conflicts with an existing journal record")
		}
		return existing, false, nil
	}
	if len(j.records) >= maxRecords {
		// Keep command IDs as durable tombstones. Pruning an expired terminal
		// record would allow a delayed duplicate with an extended deadline to
		// reuse the same ID and execute again after the original record vanished.
		return Record{}, false, errors.New("command journal is full; records are retained to prevent command ID replay")
	}
	now := time.Now().UTC()
	input.PayloadSHA256 = strings.ToLower(input.PayloadSHA256)
	input.ConfigSHA256 = strings.ToLower(input.ConfigSHA256)
	input.Deadline = input.Deadline.UTC()
	input.State = StateRunning
	input.StartedAt = now
	input.UpdatedAt = now
	input.Result = ""
	j.records[input.ID] = input
	if err := j.persist(); err != nil {
		delete(j.records, input.ID)
		return Record{}, false, err
	}
	return input, true, nil
}

func (j *Journal) Complete(id, payloadSHA256 string, succeeded bool, result string) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	rec, ok := j.records[id]
	if !ok {
		return Record{}, errors.New("command journal record not found")
	}
	if !hashPattern.MatchString(strings.ToLower(payloadSHA256)) || rec.PayloadSHA256 != strings.ToLower(payloadSHA256) {
		return Record{}, errors.New("command completion payload hash does not match journal")
	}
	if rec.State != StateRunning {
		return Record{}, errors.New("command journal record is not running")
	}
	if len(result) > 512 {
		result = result[:512]
	}
	result = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, result)
	previous := rec
	rec.State = StateFailed
	if succeeded {
		rec.State = StateSucceeded
	}
	rec.Result = result
	rec.UpdatedAt = time.Now().UTC()
	j.records[id] = rec
	if err := j.persist(); err != nil {
		j.records[id] = previous
		return Record{}, err
	}
	return rec, nil
}

func (j *Journal) Get(id string) (Record, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	rec, ok := j.records[id]
	return rec, ok
}

func (j *Journal) List() []Record {
	j.mu.Lock()
	defer j.mu.Unlock()
	ids := make([]string, 0, len(j.records))
	for id := range j.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Record, 0, len(ids))
	for _, id := range ids {
		out = append(out, j.records[id])
	}
	return out
}

func validateInput(r Record) error {
	if !idPattern.MatchString(r.ID) {
		return errors.New("invalid command ID")
	}
	if r.Type != "apply" && r.Type != "stop" && r.Type != "status" {
		return errors.New("unsupported WireGuard command type")
	}
	if !hashPattern.MatchString(strings.ToLower(r.PayloadSHA256)) {
		return errors.New("invalid command payload SHA-256")
	}
	if r.Revision == "" || len(r.Revision) > 128 || strings.TrimSpace(r.Revision) != r.Revision {
		return errors.New("invalid command revision")
	}
	if r.ConfigSHA256 != "" && !hashPattern.MatchString(strings.ToLower(r.ConfigSHA256)) {
		return errors.New("invalid config SHA-256")
	}
	if r.Deadline.IsZero() || !r.Deadline.After(time.Now()) || r.Deadline.After(time.Now().Add(24*time.Hour)) {
		return errors.New("command deadline must be within the next 24 hours")
	}
	return nil
}

func (j *Journal) load() error {
	pathInfo, pathErr := os.Lstat(j.path)
	if errors.Is(pathErr, os.ErrNotExist) {
		return nil
	}
	if pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return errors.New("command journal path is unsafe")
	}
	file, err := os.Open(j.path)
	if err != nil {
		return errors.New("cannot open command journal")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxJournalBytes {
		return errors.New("command journal file is unsafe or oversized")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	if err != nil || len(data) > maxJournalBytes {
		return errors.New("cannot read command journal")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var records []Record
	if err := dec.Decode(&records); err != nil {
		return fmt.Errorf("decode command journal: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("command journal has trailing data")
	}
	if len(records) > maxRecords {
		return errors.New("command journal exceeds record limit")
	}
	for _, rec := range records {
		if err := validateStoredRecord(rec); err != nil {
			return err
		}
		if _, exists := j.records[rec.ID]; exists {
			return errors.New("command journal contains duplicate IDs")
		}
		j.records[rec.ID] = rec
	}
	return nil
}

func validateStoredRecord(r Record) error {
	if !idPattern.MatchString(r.ID) || (r.Type != "apply" && r.Type != "stop" && r.Type != "status") ||
		!hashPattern.MatchString(r.PayloadSHA256) || r.Revision == "" || len(r.Revision) > 128 ||
		(r.ConfigSHA256 != "" && !hashPattern.MatchString(r.ConfigSHA256)) ||
		(r.State != StateRunning && r.State != StateSucceeded && r.State != StateFailed && r.State != StateInterrupted) ||
		r.StartedAt.IsZero() || r.UpdatedAt.IsZero() || r.Deadline.IsZero() {
		return errors.New("command journal contains an invalid record")
	}
	return nil
}

func (j *Journal) persist() error {
	records := make([]Record, 0, len(j.records))
	for _, rec := range j.records {
		records = append(records, rec)
	}
	sort.Slice(records, func(a, b int) bool { return records[a].ID < records[b].ID })
	data, err := json.Marshal(records)
	if err != nil {
		return errors.New("encode command journal failed")
	}
	if len(data) > maxJournalBytes {
		return errors.New("command journal exceeds size limit")
	}
	tmp, err := os.CreateTemp(j.dir, ".commands-*.tmp")
	if err != nil {
		return errors.New("create command journal temporary file failed")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.New("write command journal failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.New("sync command journal failed")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("close command journal failed")
	}
	if err := os.Rename(tmpPath, j.path); err != nil {
		return errors.New("commit command journal failed")
	}
	dir, err := os.Open(j.dir)
	if err != nil {
		return errors.New("open command journal directory failed")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return errors.New("sync command journal directory failed")
	}
	return nil
}

func PayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
