package check

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sudodrift/releasedrift/internal/ghapi"
	"github.com/sudodrift/releasedrift/internal/scan"
	"github.com/sudodrift/releasedrift/internal/state"
)

const (
	h1 = "1111111111111111111111111111111111111111111111111111111111111111"
	h2 = "2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeGitHub serves releases from a map that tests can change between runs.
type fakeGitHub struct {
	mu       sync.Mutex
	releases map[string]map[string]any // "owner/repo@tag" -> release JSON
	hits     int
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	p := strings.TrimPrefix(r.URL.Path, "/repos/")
	parts := strings.Split(p, "/")
	if len(parts) != 5 {
		http.NotFound(w, r)
		return
	}
	rel, ok := f.releases[parts[0]+"/"+parts[1]+"@"+parts[4]]
	if !ok {
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"Not Found"}`))
		return
	}
	b, _ := json.Marshal(rel)
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(304)
		return
	}
	w.Header().Set("ETag", etag)
	w.Write(b)
}

func release(immutable any, assets ...string) map[string]any {
	var as []map[string]any
	for i := 0; i+1 < len(assets); i += 2 {
		var d any
		if assets[i+1] != "" {
			d = "sha256:" + assets[i+1]
		}
		as = append(as, map[string]any{"name": assets[i], "digest": d})
	}
	m := map[string]any{"tag_name": "v1", "assets": as}
	if immutable != nil {
		m["immutable"] = immutable
	}
	return m
}

func setup(t *testing.T) (*fakeGitHub, *ghapi.Client) {
	t.Helper()
	fake := &fakeGitHub{releases: map[string]map[string]any{}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return fake, ghapi.New(srv.URL, "", "test")
}

func scanned(files map[string]string) *scan.Result {
	res := &scan.Result{Refs: []scan.Ref{}}
	for name, src := range files {
		res.Files++
		res.Refs = append(res.Refs, scan.File(name, []byte(src))...)
	}
	return res
}

func rules(rep *Report) map[string]Severity {
	m := map[string]Severity{}
	for _, f := range rep.Findings {
		m[f.Rule] = f.Severity
	}
	return m
}

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func TestPinnedImmutableIsClean(t *testing.T) {
	fake, c := setup(t)
	fake.releases["o/r@v1"] = release(true, "r.tgz", h1)
	res := scanned(map[string]string{"x.sh": "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\necho \"" + h1 + "  r.tgz\" | sha256sum -c -\n"})
	st := state.New()
	rep := Run(context.Background(), ".", res, c, st, Options{Now: t0})
	if len(rep.Findings) != 0 || len(rep.Errors) != 0 {
		t.Fatalf("want clean, got %+v %v", rep.Findings, rep.Errors)
	}
	if rep.Releases != 1 || rep.Requests != 1 || !rep.Refs[0].Checked || rep.Refs[0].Assets[0].Pin != "match" {
		t.Errorf("report %+v", rep)
	}
	if st.Releases["o/r@v1"].Assets["r.tgz"].Digest != "sha256:"+h1 {
		t.Errorf("state not recorded: %+v", st.Releases)
	}
}

func TestPinMismatch(t *testing.T) {
	fake, c := setup(t)
	fake.releases["o/r@v1"] = release(true, "r.tgz", h2)
	res := scanned(map[string]string{"x.sh": "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\necho \"" + h1 + "  r.tgz\" | sha256sum -c -\n"})
	rep := Run(context.Background(), ".", res, c, state.New(), Options{Now: t0})
	if got := rules(rep); got["pin-mismatch"] != High || len(got) != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
	if rep.Worst() != High || rep.Count(High) != 1 {
		t.Errorf("worst %v", rep.Worst())
	}
}

func TestNoDigest(t *testing.T) {
	fake, c := setup(t)
	fake.releases["o/r@v1"] = release(nil, "r.tgz", "")
	res := scanned(map[string]string{"x.sh": "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\necho \"" + h1 + "  r.tgz\" | sha256sum -c -\n"})
	rep := Run(context.Background(), ".", res, c, state.New(), Options{Now: t0})
	if got := rules(rep); got["no-digest"] != Info || len(got) != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
}

// The OVHcloud CLI case: a mutable release whose asset is replaced between
// two runs.
func TestDigestChanged(t *testing.T) {
	fake, c := setup(t)
	fake.releases["o/r@v1"] = release(false, "r.tgz", h1, "checksums.txt", h1)
	src := map[string]string{"install.sh": "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\n"}
	st := state.New()
	ctx := context.Background()

	rep := Run(ctx, ".", scanned(src), c, st, Options{Now: t0})
	got := rules(rep)
	if got["unpinned"] != Medium || got["mutable-release"] != Low || got["digest-changed"] != 0 {
		t.Fatalf("first run %+v", rep.Findings)
	}

	// Same digest, second run: ETag is reused and nothing new is reported.
	hits := fake.hits
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t0.Add(time.Hour)})
	if rules(rep)["digest-changed"] != 0 || fake.hits != hits+1 {
		t.Fatalf("second run %+v", rep.Findings)
	}

	// The asset is swapped.
	fake.releases["o/r@v1"] = release(false, "r.tgz", h2, "checksums.txt", h2)
	t2 := t0.Add(2 * time.Hour)
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t2})
	var f *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Rule == "digest-changed" {
			f = &rep.Findings[i]
		}
	}
	if f == nil || f.Severity != High || f.Asset != "r.tgz" || !strings.Contains(f.Message, h1) || !strings.Contains(f.Message, h2) {
		t.Fatalf("swap not reported: %+v", rep.Findings)
	}
	a := st.Releases["o/r@v1"].Assets["r.tgz"]
	if a.Digest != "sha256:"+h1 || a.ChangedTo != "sha256:"+h2 || !a.ChangedAt.Equal(t2) {
		t.Errorf("state after swap %+v", a)
	}

	// It keeps alerting until accepted.
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t2.Add(time.Hour)})
	if rules(rep)["digest-changed"] != High {
		t.Fatalf("alert should repeat: %+v", rep.Findings)
	}
	if !a.ChangedAt.Equal(t2) {
		t.Errorf("ChangedAt moved: %v", a.ChangedAt)
	}

	// Swapped back: still reported, as a revert.
	fake.releases["o/r@v1"] = release(false, "r.tgz", h1, "checksums.txt", h1)
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t2.Add(2 * time.Hour)})
	for _, f := range rep.Findings {
		if f.Rule == "digest-changed" && !strings.Contains(f.Message, "back to") {
			t.Errorf("revert message: %s", f.Message)
		}
	}

	// Accept the current file.
	fake.releases["o/r@v1"] = release(false, "r.tgz", h2)
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t2.Add(3 * time.Hour), Accept: true})
	if rules(rep)["digest-changed"] != 0 {
		t.Fatalf("accept should silence: %+v", rep.Findings)
	}
	if a := st.Releases["o/r@v1"].Assets["r.tgz"]; a.Digest != "sha256:"+h2 || a.ChangedTo != "" || a.ChangedAt != nil {
		t.Errorf("state after accept %+v", a)
	}
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t2.Add(4 * time.Hour)})
	if rules(rep)["digest-changed"] != 0 {
		t.Errorf("after accept %+v", rep.Findings)
	}
}

// Old assets have no digest. If one gets a digest later, it was uploaded
// again, which is exactly what a swap of an old release looks like.
func TestDigestAppears(t *testing.T) {
	fake, c := setup(t)
	fake.releases["o/r@v1"] = release(false, "r.tgz", "")
	src := map[string]string{"install.sh": "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\n"}
	st := state.New()
	ctx := context.Background()
	rep := Run(ctx, ".", scanned(src), c, st, Options{Now: t0})
	if rules(rep)["digest-changed"] != 0 {
		t.Fatalf("first run %+v", rep.Findings)
	}
	if a := st.Releases["o/r@v1"].Assets["r.tgz"]; a == nil || a.Digest != "" {
		t.Fatalf("asset without digest not recorded: %+v", st.Releases["o/r@v1"])
	}
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t0.Add(time.Hour)})
	if rules(rep)["digest-changed"] != 0 {
		t.Fatalf("no change yet %+v", rep.Findings)
	}
	fake.releases["o/r@v1"] = release(false, "r.tgz", h2)
	rep = Run(ctx, ".", scanned(src), c, st, Options{Now: t0.Add(2 * time.Hour)})
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "digest-changed" && f.Severity == High && strings.Contains(f.Message, "uploaded again") {
			found = true
		}
	}
	if !found {
		t.Errorf("re-upload not reported: %+v", rep.Findings)
	}
}

func TestChecksumsFileOnImmutableRelease(t *testing.T) {
	src := "curl -LO https://github.com/o/r/releases/download/v1/checksums.txt\n" +
		"curl -LO https://github.com/o/r/releases/download/v1/r.tgz\n" +
		"sha256sum -c --ignore-missing checksums.txt\n"
	for _, imm := range []bool{true, false} {
		fake, c := setup(t)
		fake.releases["o/r@v1"] = release(imm, "r.tgz", h1, "checksums.txt", h2)
		rep := Run(context.Background(), ".", scanned(map[string]string{"x.sh": src}), c, state.New(), Options{Now: t0})
		want := Low
		if imm {
			want = Info
		}
		if got := rules(rep)["same-release-checksums"]; got != want {
			t.Errorf("immutable=%v: severity %v, want %v (%+v)", imm, got, want, rep.Findings)
		}
	}
}

func TestMutableButPinned(t *testing.T) {
	fake, c := setup(t)
	fake.releases["o/r@v1"] = release(false, "r.tgz", h1)
	res := scanned(map[string]string{"x.sh": "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\necho \"" + h1 + "  r.tgz\" | sha256sum -c -\n"})
	rep := Run(context.Background(), ".", res, c, state.New(), Options{Now: t0})
	if got := rules(rep); got["mutable-release"] != Info || len(got) != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
}

func TestPatternsAndMissing(t *testing.T) {
	fake, c := setup(t)
	fake.releases["o/r@v1"] = release(true, "r_linux.deb", h1, "r_mac.zip", h2)
	res := scanned(map[string]string{
		"ci.yml": "run: gh release download v1 -R o/r -p '*.deb' -p '*.rpm'\n" +
			"run: curl -LO https://github.com/o/gone/releases/download/v9/x\n" +
			"run: gh release download v1 -R o/r\n",
	})
	rep := Run(context.Background(), ".", res, c, state.New(), Options{Now: t0})
	got := rules(rep)
	if got["asset-missing"] != Medium || got["release-missing"] != Medium {
		t.Errorf("findings %+v", rep.Findings)
	}
	for _, rs := range rep.Refs {
		switch {
		case rs.Asset == "*.deb" && (len(rs.Assets) != 1 || rs.Assets[0].Name != "r_linux.deb"):
			t.Errorf("deb pattern %+v", rs.Assets)
		case rs.Owner == "o" && rs.Repo == "r" && rs.Asset == "" && len(rs.Assets) != 2:
			t.Errorf("all assets %+v", rs.Assets)
		}
	}
	// Two releases, one request each.
	if rep.Requests != 2 || rep.Releases != 2 {
		t.Errorf("requests %d releases %d", rep.Requests, rep.Releases)
	}
}

func TestOfflineAndStatic(t *testing.T) {
	fake, c := setup(t)
	res := scanned(map[string]string{"x.sh": "curl -LO https://github.com/o/r/releases/latest/download/r\n" +
		"curl -LO https://github.com/o/r/releases/download/v${V}/r\n" +
		"\n\n\n\n\n\n\n\n\n\n" +
		"curl -LO https://github.com/o/r/releases/download/v1/checksums.txt\n" +
		"curl -LO https://github.com/o/r/releases/download/v1/r.tgz\n" +
		"sha256sum -c checksums.txt\n"})
	rep := Run(context.Background(), ".", res, c, state.New(), Options{Now: t0, Offline: true})
	if fake.hits != 0 || rep.Requests != 0 || rep.Releases != 0 {
		t.Errorf("offline made requests")
	}
	got := rules(rep)
	want := map[string]Severity{"latest-url": Medium, "unresolved": Info, "unpinned": Medium, "same-release-checksums": Low}
	if len(got) != len(want) {
		t.Errorf("got %v want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %v want %v", k, got[k], v)
		}
	}
	if rep.Findings[len(rep.Findings)-1].Severity != Info {
		t.Errorf("findings not sorted by severity: %+v", rep.Findings)
	}
}

func TestRateLimitStops(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(403)
	}))
	defer srv.Close()
	res := scanned(map[string]string{"x.sh": "curl -LO https://github.com/a/a/releases/download/v1/a\ncurl -LO https://github.com/b/b/releases/download/v1/b\n"})
	rep := Run(context.Background(), ".", res, ghapi.New(srv.URL, "", "t"), state.New(), Options{Now: t0})
	if hits != 1 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "rate limit") {
		t.Errorf("hits %d errors %v", hits, rep.Errors)
	}
}

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high"} {
		v, err := ParseSeverity(s)
		if err != nil || v.String() != s {
			t.Errorf("%s: %v %v", s, v, err)
		}
	}
	if _, err := ParseSeverity("bad"); err == nil {
		t.Error("want error")
	}
}
