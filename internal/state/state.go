// Package state stores the asset digests seen on earlier runs.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Version of the state file layout.
const Version = 1

// File is the whole state file.
type File struct {
	Version  int                 `json:"version"`
	Tool     string              `json:"tool"`
	Releases map[string]*Release `json:"releases"`
}

// Release holds what was seen for owner/repo@tag.
type Release struct {
	ETag      string            `json:"etag,omitempty"`
	Immutable *bool             `json:"immutable,omitempty"`
	CheckedAt time.Time         `json:"checked_at"`
	Assets    map[string]*Asset `json:"assets"`
}

// Asset is one recorded asset digest.
type Asset struct {
	// Digest is the first digest seen ("" for assets GitHub has no digest
	// for). It is kept when the digest changes, until the change is
	// accepted with --accept, so the alert repeats.
	Digest    string    `json:"digest"`
	FirstSeen time.Time `json:"first_seen"`
	// ChangedTo and ChangedAt are set when a later run saw another digest.
	ChangedTo string     `json:"changed_to,omitempty"`
	ChangedAt *time.Time `json:"changed_at,omitempty"`
}

// New returns an empty state.
func New() *File {
	return &File{Version: Version, Tool: "releasedrift", Releases: map[string]*Release{}}
}

// Load reads path. A missing file gives an empty state.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: not a releasedrift state file: %w", path, err)
	}
	if f.Tool != "releasedrift" || f.Version != Version {
		return nil, fmt.Errorf("%s: unsupported state file (tool=%q version=%d)", path, f.Tool, f.Version)
	}
	if f.Releases == nil {
		f.Releases = map[string]*Release{}
	}
	return &f, nil
}

// Save writes the state to path through a temporary file and a rename, so
// a crash never leaves half a file.
func (f *File) Save(path string) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".releasedrift-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Keys returns the release keys in sorted order.
func (f *File) Keys() []string {
	var k []string
	for key := range f.Releases {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}
