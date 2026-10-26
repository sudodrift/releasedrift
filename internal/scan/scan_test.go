package scan

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	hashA = "62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8"
	hashB = "020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d"
)

func one(t *testing.T, rel, src string) Ref {
	t.Helper()
	refs := File(rel, []byte(src))
	if len(refs) != 1 {
		t.Fatalf("want 1 ref, got %d: %+v", len(refs), refs)
	}
	return refs[0]
}

func TestURLForms(t *testing.T) {
	r := one(t, "x.sh", "curl -fsSLO https://github.com/cli/cli/releases/download/v2.103.2/gh_2.103.2_linux_amd64.tar.gz\n")
	if r.Kind != "url" || r.Owner != "cli" || r.Repo != "cli" || r.Tag != "v2.103.2" || r.Asset != "gh_2.103.2_linux_amd64.tar.gz" || r.Line != 1 {
		t.Errorf("bad ref %+v", r)
	}
	if r.Pin.Kind != "none" || r.Unresolved {
		t.Errorf("pin %+v unresolved %v", r.Pin, r.Unresolved)
	}

	r = one(t, "x.sh", `wget "https://github.com/a/b/releases/download/v1/tool.zip";`+"\n")
	if r.Asset != "tool.zip" {
		t.Errorf("asset %q", r.Asset)
	}

	r = one(t, "x.sh", "curl -LO https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64\n")
	if r.Kind != "latest-url" || r.Owner != "mikefarah" || r.Tag != "" || r.Asset != "yq_linux_amd64" {
		t.Errorf("latest %+v", r)
	}

	r = one(t, "x.sh", "curl -LO https://github.com/a/b/releases/download/v${V}/b_${V}.tgz\n")
	if !r.Unresolved {
		t.Errorf("variable URL should be unresolved: %+v", r)
	}

	if refs := File("x.sh", []byte("# curl https://github.com/a/b/releases/download/v1/x\n")); len(refs) != 0 {
		t.Errorf("comment line should be ignored: %+v", refs)
	}
}

func TestGHReleaseDownload(t *testing.T) {
	refs := File("ci.yml", []byte("      - run: gh release download v2.103.2 -R cli/cli -p 'gh_*_linux_amd64.deb' --pattern=x.txt -D out\n"))
	if len(refs) != 2 {
		t.Fatalf("want 2 refs, got %+v", refs)
	}
	for i, want := range []string{"gh_*_linux_amd64.deb", "x.txt"} {
		r := refs[i]
		if r.Kind != "gh-release-download" || r.Owner != "cli" || r.Repo != "cli" || r.Tag != "v2.103.2" || r.Asset != want || r.Unresolved {
			t.Errorf("ref %d: %+v", i, r)
		}
	}
	r := one(t, "x.sh", "gh release download --repo=o/r v1.0\n")
	if r.Owner != "o" || r.Tag != "v1.0" || r.Asset != "" || r.Unresolved {
		t.Errorf("all assets: %+v", r)
	}
	r = one(t, "x.sh", "gh release download v1.0\n")
	if !r.Unresolved {
		t.Errorf("no repo should be unresolved: %+v", r)
	}
}

func TestPins(t *testing.T) {
	cases := []struct {
		name, src, kind, hash string
		line                  int
	}{
		{"dockerfile add", "ADD --checksum=sha256:" + hashA + " \\\n    https://github.com/cli/cli/releases/download/v2.103.2/gh.tar.gz /tmp/\n", "sha256", hashA, 1},
		{"echo pipe", "curl -LO https://github.com/a/b/releases/download/v1/b.tgz\necho \"" + hashA + "  b.tgz\" | sha256sum -c -\n", "sha256", hashA, 2},
		{"ansible", "url: https://github.com/a/b/releases/download/v1/b\nchecksum: \"sha256:" + hashA + "\"\n", "sha256", hashA, 2},
		{"make var", "SHA := " + hashB + "\nall:\n\tcurl -o b https://github.com/a/b/releases/download/v1/b\n\techo \"$(SHA)  b\" | sha256sum -c -\n", "sha256", hashB, 4},
		{"shell var", "B_SHA256=" + hashB + "\ncurl -o b https://github.com/a/b/releases/download/v1/b\necho \"${B_SHA256}  b\" | sha256sum --check\n", "sha256", hashB, 1},
		{"hash without check", "curl -o b https://github.com/a/b/releases/download/v1/b\n# " + hashA + "\n", "none", "", 0},
		{"hash far away", "curl -o b https://github.com/a/b/releases/download/v1/b\n\n\n\n\n\n\n\n\n\n\necho \"" + hashA + "  b\" | sha256sum -c -\n", "none", "", 0},
		{"checksums file", "curl -LO https://github.com/a/b/releases/download/v1/checksums.txt\ncurl -LO https://github.com/a/b/releases/download/v1/b.tgz\nsha256sum -c --ignore-missing checksums.txt\n", "checksums-file", "", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			refs := File("f", []byte(c.src))
			r := refs[len(refs)-1]
			if r.Pin.Kind != c.kind || r.Pin.Hash != c.hash || r.Pin.Line != c.line {
				t.Errorf("got %+v, want kind %s hash %s line %d", r.Pin, c.kind, c.hash, c.line)
			}
		})
	}
}

// A hash belongs to one download only: the closest, or the one named on the
// hash line.
func TestPinAssignment(t *testing.T) {
	src := "ADD --checksum=sha256:" + hashA + " \\\n" +
		"    https://github.com/a/b/releases/download/v1/b_amd64.tgz /tmp/\n" +
		"RUN curl -LO https://github.com/a/b/releases/download/v1/b_arm64.tgz\n"
	refs := File("Dockerfile", []byte(src))
	if len(refs) != 2 {
		t.Fatalf("refs %+v", refs)
	}
	if refs[0].Pin.Kind != "sha256" || refs[1].Pin.Kind != "none" {
		t.Errorf("pins %+v / %+v", refs[0].Pin, refs[1].Pin)
	}

	src = "curl -LO https://github.com/a/b/releases/download/v1/one.tgz\n" +
		"curl -LO https://github.com/a/b/releases/download/v1/two.tgz\n" +
		"echo \"" + hashA + "  one.tgz\" | sha256sum -c -\n" +
		"echo \"" + hashB + "  two.tgz\" | sha256sum -c -\n"
	refs = File("x.sh", []byte(src))
	if refs[0].Pin.Hash != hashA || refs[1].Pin.Hash != hashB {
		t.Errorf("one=%s two=%s", refs[0].Pin.Hash, refs[1].Pin.Hash)
	}
}

func TestDir(t *testing.T) {
	root := t.TempDir()
	write := func(rel, s string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	u := "https://github.com/a/b/releases/download/v1/b\n"
	write("Dockerfile", "RUN curl -LO "+u)
	write("build/Makefile", "\tcurl -LO "+u)
	write(".github/workflows/ci.yml", "- run: curl -LO "+u)
	write("tool", "#!/bin/bash\ncurl -LO "+u)
	write("README.md", "curl -LO "+u)         // not scanned
	write(".git/hooks/x.sh", "curl -LO "+u)   // skipped dir
	write("node_modules/y.sh", "curl -LO "+u) // skipped dir
	write("bin.sh", "\x00curl -LO "+u)        // binary
	res, err := Dir(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 4 || len(res.Refs) != 4 {
		t.Fatalf("files %d refs %+v", res.Files, res.Refs)
	}
	want := []string{".github/workflows/ci.yml", "Dockerfile", "build/Makefile", "tool"}
	for i, w := range want {
		if res.Refs[i].File != w {
			t.Errorf("ref %d file %s, want %s", i, res.Refs[i].File, w)
		}
	}
}
