// Package scan finds GitHub release downloads in a directory tree and works
// out whether each one is pinned to a SHA-256 checksum.
package scan

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Ref is one GitHub release download found in a file.
type Ref struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Kind  string `json:"kind"` // "url", "latest-url" or "gh-release-download"
	Owner string `json:"owner,omitempty"`
	Repo  string `json:"repo,omitempty"`
	Tag   string `json:"tag,omitempty"`
	// Asset is the file name for URLs, or a glob for gh release download
	// --pattern. Empty for gh release download without a pattern (all assets).
	Asset string `json:"asset,omitempty"`
	Text  string `json:"text"`
	// Unresolved is set when the URL or command uses a variable, so the
	// exact release or asset is not known.
	Unresolved bool `json:"unresolved,omitempty"`
	Pin        Pin  `json:"pin"`
}

// Pin describes how a download is checked.
type Pin struct {
	// Kind is "sha256" (a literal hash near the download), "checksums-file"
	// (checked only against a checksums file from the same release) or
	// "none".
	Kind string `json:"kind"`
	Hash string `json:"sha256,omitempty"`
	Line int    `json:"line,omitempty"`
}

// Key returns owner/repo@tag, the release a ref points at.
func (r Ref) Key() string { return r.Owner + "/" + r.Repo + "@" + r.Tag }

// Result of scanning a tree.
type Result struct {
	Files    int      `json:"files_scanned"`
	Refs     []Ref    `json:"refs"`
	Warnings []string `json:"warnings,omitempty"`
}

const maxFileSize = 2 << 20

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".terraform": true}

// wanted reports whether a file is worth reading: Dockerfiles, shell scripts,
// Makefiles, YAML (GitHub Actions, Ansible, compose), install scripts and
// anything with a shell shebang.
func wanted(rel string, head []byte) bool {
	base := path.Base(rel)
	lower := strings.ToLower(base)
	switch {
	case strings.HasPrefix(base, "Dockerfile"), strings.HasPrefix(base, "Containerfile"),
		strings.HasSuffix(lower, ".dockerfile"), strings.HasSuffix(lower, ".containerfile"):
		return true
	case base == "Makefile", base == "GNUmakefile", base == "makefile", strings.HasSuffix(lower, ".mk"):
		return true
	case strings.HasSuffix(lower, ".sh"), strings.HasSuffix(lower, ".bash"), strings.HasSuffix(lower, ".zsh"),
		strings.HasSuffix(lower, ".yml"), strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".ps1"):
		return true
	case strings.HasPrefix(lower, "install"), strings.HasPrefix(lower, "setup"), strings.HasPrefix(lower, "bootstrap"),
		strings.HasPrefix(lower, "get-"), strings.HasPrefix(lower, "get_"):
		return true
	}
	if bytes.HasPrefix(head, []byte("#!")) {
		first, _, _ := bytes.Cut(head, []byte("\n"))
		return bytes.Contains(first, []byte("sh"))
	}
	return false
}

// Dir scans every wanted file under root. Paths in the result are relative
// to root and use forward slashes.
func Dir(root string) (*Result, error) {
	res := &Result{Refs: []Ref{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
			return nil
		}
		head := b
		if len(head) > 8192 {
			head = head[:8192]
		}
		if bytes.IndexByte(head, 0) >= 0 || !wanted(rel, head) {
			return nil
		}
		res.Files++
		res.Refs = append(res.Refs, File(rel, b)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(res.Refs, func(i, j int) bool {
		if res.Refs[i].File != res.Refs[j].File {
			return res.Refs[i].File < res.Refs[j].File
		}
		return res.Refs[i].Line < res.Refs[j].Line
	})
	return res, nil
}

var (
	reURL = regexp.MustCompile(`https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/([^/\s"'<>]+)/([^\s"'<>)\]|;&,]+)`)
	// releases/latest/download/ASSET always points at the newest release.
	reLatest = regexp.MustCompile(`https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/latest/download/([^\s"'<>)\]|;&,]+)`)
	reGH     = regexp.MustCompile(`\bgh\s+release\s+download\b([^\n;&|]*)`)
	reHex64  = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	// Words that show a checksum is being checked.
	reVerify  = regexp.MustCompile(`(?i)sha256sum|shasum|sha256:|--checksum|checksum:|checksum=|get-filehash|openssl\s+dgst|sha256\s*[:=]|sha256_?(sum|hash)?\s*[:=]`)
	reCheckC  = regexp.MustCompile(`(sha256sum|shasum[^|;&\n]*)\s+(-c|--check)\b`)
	reVarRef  = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|\$\(([A-Za-z_][A-Za-z0-9_]*)\)|\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	reVarHash = regexp.MustCompile(`(?m)^\s*(?:export\s+|ARG\s+|ENV\s+|-\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|\?=|=|:)\s*["']?(?:sha256:)?([a-fA-F0-9]{64})\b`)
)

// Lines before and after a download that are searched for a checksum.
const (
	windowBefore = 5
	windowAfter  = 8
)

// File finds release downloads in one file.
func File(rel string, b []byte) []Ref {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), maxFileSize)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	varHashes := map[string]string{}
	for _, m := range reVarHash.FindAllStringSubmatch(string(b), -1) {
		varHashes[m[1]] = strings.ToLower(m[2])
	}
	var refs []Ref
	for i, l := range lines {
		text := strings.TrimSpace(l)
		if isComment(text) {
			continue
		}
		for _, m := range reURL.FindAllStringSubmatch(l, -1) {
			asset := strings.TrimRight(m[4], `.\`)
			r := Ref{File: rel, Line: i + 1, Kind: "url", Owner: m[1], Repo: m[2], Tag: m[3], Asset: asset, Text: text}
			r.Unresolved = hasVar(m[1] + m[2] + m[3] + asset)
			refs = append(refs, r)
		}
		for _, m := range reLatest.FindAllStringSubmatch(l, -1) {
			asset := strings.TrimRight(m[3], `.\`)
			refs = append(refs, Ref{File: rel, Line: i + 1, Kind: "latest-url", Owner: m[1], Repo: m[2], Asset: asset, Text: text, Unresolved: hasVar(m[1] + m[2] + asset)})
		}
		for _, m := range reGH.FindAllStringSubmatch(l, -1) {
			refs = append(refs, parseGH(rel, i+1, text, m[1])...)
		}
	}
	assignPins(lines, refs, varHashes)
	return refs
}

func isComment(t string) bool {
	return strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#!") || strings.HasPrefix(t, "//")
}

func hasVar(s string) bool { return strings.ContainsAny(s, "$%{}") }

// parseGH reads the arguments of "gh release download".
func parseGH(rel string, line int, text, args string) []Ref {
	f := strings.Fields(args)
	var tag, repo string
	var patterns []string
	for i := 0; i < len(f); i++ {
		a := strings.Trim(f[i], `"'`)
		next := func() string {
			if i+1 < len(f) {
				i++
				return strings.Trim(f[i], `"'`)
			}
			return ""
		}
		switch {
		case a == "-R" || a == "--repo":
			repo = next()
		case strings.HasPrefix(a, "--repo="):
			repo = strings.TrimPrefix(a, "--repo=")
		case a == "-p" || a == "--pattern":
			patterns = append(patterns, next())
		case strings.HasPrefix(a, "--pattern="):
			patterns = append(patterns, strings.TrimPrefix(a, "--pattern="))
		case a == "-D" || a == "--dir" || a == "-O" || a == "--output" || a == "-A" || a == "--archive":
			next()
		case strings.HasPrefix(a, "-"):
		case a == "\\":
		default:
			if tag == "" {
				tag = a
			}
		}
	}
	base := Ref{File: rel, Line: line, Kind: "gh-release-download", Tag: tag, Text: text}
	if o, r, ok := strings.Cut(repo, "/"); ok {
		base.Owner, base.Repo = o, r
	}
	base.Unresolved = repo == "" || tag == "" || hasVar(repo+tag)
	if len(patterns) == 0 {
		return []Ref{base}
	}
	var out []Ref
	for _, p := range patterns {
		r := base
		r.Asset = p
		r.Unresolved = base.Unresolved || hasVar(p)
		out = append(out, r)
	}
	return out
}

// window returns the line indexes searched around a ref.
func window(r Ref, n int) (lo, hi int) {
	lo, hi = r.Line-1-windowBefore, r.Line-1+windowAfter
	if lo < 0 {
		lo = 0
	}
	if hi >= n {
		hi = n - 1
	}
	return lo, hi
}

// score rates how well a hash on line idx fits ref r: closer is better, and
// a line that names the asset wins.
func score(r Ref, idx int, text string) int {
	d := idx - (r.Line - 1)
	if d < 0 {
		d = -d
	}
	sc := 100 - d
	base := path.Base(r.Asset)
	if r.Asset != "" && !strings.ContainsAny(base, "*?[") && strings.Contains(text, base) {
		sc += 50
	}
	return sc
}

// assignPins gives each SHA-256 found in the file to the one download it
// most likely belongs to, then decides how each download is checked.
func assignPins(lines []string, refs []Ref, varHashes map[string]string) {
	type occ struct {
		hash string
		idx  int
	}
	var occs []occ
	for i, l := range lines {
		if isComment(strings.TrimSpace(l)) {
			continue
		}
		for _, h := range reHex64.FindAllString(l, -1) {
			occs = append(occs, occ{strings.ToLower(h), i})
		}
		if reVerify.MatchString(l) {
			for _, m := range reVarRef.FindAllStringSubmatch(l, -1) {
				if h, ok := varHashes[m[1]+m[2]+m[3]]; ok {
					occs = append(occs, occ{h, i})
				}
			}
		}
	}
	type pick struct {
		hash       string
		idx, score int
	}
	best := make([]*pick, len(refs))
	for _, o := range occs {
		owner, ownerScore := -1, 0
		for k, r := range refs {
			lo, hi := window(r, len(lines))
			if o.idx < lo || o.idx > hi {
				continue
			}
			if sc := score(r, o.idx, lines[o.idx]); owner < 0 || sc > ownerScore {
				owner, ownerScore = k, sc
			}
		}
		if owner >= 0 && (best[owner] == nil || ownerScore > best[owner].score) {
			best[owner] = &pick{o.hash, o.idx, ownerScore}
		}
	}
	for k := range refs {
		refs[k].Pin = pinFor(lines, refs[k], refs, best[k] != nil)
		if refs[k].Pin.Kind == "sha256" {
			refs[k].Pin.Hash, refs[k].Pin.Line = best[k].hash, best[k].idx+1
		}
	}
}

// pinFor decides the pin kind for one ref. hasHash says whether a SHA-256
// was assigned to it.
func pinFor(lines []string, r Ref, all []Ref, hasHash bool) Pin {
	lo, hi := window(r, len(lines))
	if hasHash {
		for i := lo; i <= hi; i++ {
			if !isComment(strings.TrimSpace(lines[i])) && reVerify.MatchString(lines[i]) {
				return Pin{Kind: "sha256"}
			}
		}
	}
	// "sha256sum -c checksums.txt" where checksums.txt comes from the same
	// release only proves the files match each other.
	for i := lo; i <= hi; i++ {
		if !reCheckC.MatchString(lines[i]) {
			continue
		}
		for _, o := range all {
			if o.Line-1 >= lo && o.Line-1 <= hi && o.Key() == r.Key() && isChecksumAsset(o.Asset) {
				return Pin{Kind: "checksums-file", Line: i + 1}
			}
		}
	}
	return Pin{Kind: "none"}
}

func isChecksumAsset(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "checksum") || strings.Contains(n, "sha256") || strings.Contains(n, "shasum") || strings.HasSuffix(n, ".sha256sum")
}
