package journald

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	checkpointVersion  = 1
	maxCheckpointBytes = 16 << 10
)

type checkpoint struct {
	Version       int    `json:"version"`
	Initialized   bool   `json:"initialized"`
	Cursor        string `json:"cursor,omitempty"`
	SinceUnixUsec uint64 `json:"since_unix_usec,omitempty"`
}

type checkpointStore struct {
	path  string
	state checkpoint
	dirty bool
}

func loadCheckpoint(path string) (*checkpointStore, error) {
	store := &checkpointStore{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("journald checkpoint: read: %w", err)
	}
	if len(data) > maxCheckpointBytes {
		return nil, fmt.Errorf(
			"journald checkpoint: file exceeds %d bytes",
			maxCheckpointBytes,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&store.state); err != nil {
		return nil, fmt.Errorf("journald checkpoint: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("journald checkpoint: trailing JSON data")
	}
	if store.state.Version != checkpointVersion {
		return nil, fmt.Errorf(
			"journald checkpoint: unsupported version %d",
			store.state.Version,
		)
	}
	if err := validateCursor(store.state.Cursor); err != nil {
		return nil, fmt.Errorf("journald checkpoint: %w", err)
	}
	if !store.state.Initialized {
		return nil, fmt.Errorf("journald checkpoint: state is not initialized")
	}
	return store, nil
}

func validateCursor(cursor string) error {
	if len(cursor) > maxCursorBytes || !utf8.ValidString(cursor) {
		return fmt.Errorf("invalid cursor")
	}
	for _, value := range cursor {
		if unicode.IsControl(value) {
			return fmt.Errorf("invalid cursor")
		}
	}
	return nil
}

func (s *checkpointStore) save() error {
	if !s.dirty {
		return nil
	}
	s.state.Version = checkpointVersion
	if err := validateCursor(s.state.Cursor); err != nil {
		return fmt.Errorf("journald checkpoint: %w", err)
	}
	if !s.state.Initialized {
		return fmt.Errorf("journald checkpoint: state is not initialized")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("journald checkpoint: mkdir: %w", err)
	}
	data, err := json.Marshal(s.state)
	if err != nil {
		return fmt.Errorf("journald checkpoint: encode: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxCheckpointBytes {
		return fmt.Errorf(
			"journald checkpoint: encoded file exceeds %d bytes",
			maxCheckpointBytes,
		)
	}
	file, err := os.CreateTemp(
		filepath.Dir(s.path),
		"."+filepath.Base(s.path)+".tmp-*",
	)
	if err != nil {
		return fmt.Errorf("journald checkpoint: create temp: %w", err)
	}
	tempPath := file.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("journald checkpoint: write: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("journald checkpoint: fsync: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("journald checkpoint: close: %w", err)
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("journald checkpoint: rename: %w", err)
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("journald checkpoint: open parent: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("journald checkpoint: fsync parent: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("journald checkpoint: close parent: %w", err)
	}
	s.dirty = false
	return nil
}

func validFilter(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00') &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}
