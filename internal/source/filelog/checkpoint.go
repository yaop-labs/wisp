package filelog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	checkpointVersion  = 1
	maxCheckpointBytes = 4 << 20
	maxCheckpointFiles = 10_000
)

type checkpoint struct {
	Identity string `json:"identity"`
	Offset   int64  `json:"offset"`
	Dropping bool   `json:"dropping_oversized,omitempty"`
}

type checkpointDocument struct {
	Version int                   `json:"version"`
	Files   map[string]checkpoint `json:"files"`
}

type checkpointStore struct {
	path  string
	files map[string]checkpoint
}

func loadCheckpointStore(path string) (*checkpointStore, error) {
	store := &checkpointStore{path: path, files: make(map[string]checkpoint)}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("filelog checkpoint: read: %w", err)
	}
	if len(data) > maxCheckpointBytes {
		return nil, fmt.Errorf("filelog checkpoint: file exceeds %d bytes", maxCheckpointBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document checkpointDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("filelog checkpoint: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("filelog checkpoint: trailing JSON data")
	}
	if document.Version != checkpointVersion {
		return nil, fmt.Errorf("filelog checkpoint: unsupported version %d", document.Version)
	}
	if len(document.Files) > maxCheckpointFiles {
		return nil, fmt.Errorf("filelog checkpoint: too many files")
	}
	for path, state := range document.Files {
		if path == "" || !filepath.IsAbs(path) || state.Identity == "" || state.Offset < 0 {
			return nil, fmt.Errorf("filelog checkpoint: invalid entry %q", path)
		}
		store.files[path] = state
	}
	return store, nil
}

func (s *checkpointStore) save() error {
	if len(s.files) > maxCheckpointFiles {
		return fmt.Errorf("filelog checkpoint: too many files")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("filelog checkpoint: mkdir: %w", err)
	}
	data, err := json.Marshal(checkpointDocument{
		Version: checkpointVersion,
		Files:   s.files,
	})
	if err != nil {
		return fmt.Errorf("filelog checkpoint: encode: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxCheckpointBytes {
		return fmt.Errorf("filelog checkpoint: encoded file exceeds %d bytes", maxCheckpointBytes)
	}
	file, err := os.CreateTemp(
		filepath.Dir(s.path),
		"."+filepath.Base(s.path)+".tmp-*",
	)
	if err != nil {
		return fmt.Errorf("filelog checkpoint: create temp: %w", err)
	}
	tmp := file.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("filelog checkpoint: write: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("filelog checkpoint: fsync: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("filelog checkpoint: close: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("filelog checkpoint: rename: %w", err)
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("filelog checkpoint: open parent: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("filelog checkpoint: fsync parent: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("filelog checkpoint: close parent: %w", err)
	}
	return nil
}
