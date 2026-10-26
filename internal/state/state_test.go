package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSave(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	f, err := Load(p)
	if err != nil || len(f.Releases) != 0 || f.Version != Version {
		t.Fatalf("missing file: %+v %v", f, err)
	}
	yes := true
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	f.Releases["b/b@v1"] = &Release{ETag: `"x"`, Immutable: &yes, CheckedAt: now, Assets: map[string]*Asset{"a": {Digest: "sha256:1", FirstSeen: now}}}
	f.Releases["a/a@v1"] = &Release{CheckedAt: now, Assets: map[string]*Asset{}}
	if err := f.Save(p); err != nil {
		t.Fatal(err)
	}
	g, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	r := g.Releases["b/b@v1"]
	if r.ETag != `"x"` || !*r.Immutable || r.Assets["a"].Digest != "sha256:1" || !r.Assets["a"].FirstSeen.Equal(now) || r.Assets["a"].ChangedAt != nil {
		t.Errorf("round trip: %+v", r)
	}
	if k := g.Keys(); len(k) != 2 || k[0] != "a/a@v1" {
		t.Errorf("keys %v", k)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("temporary file left behind: %v", ents)
	}
}

func TestLoadBad(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"junk":  "not json",
		"other": `{"version":1,"tool":"something-else","releases":{}}`,
		"newer": `{"version":2,"tool":"releasedrift","releases":{}}`,
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
