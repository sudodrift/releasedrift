package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodHash = "1111111111111111111111111111111111111111111111111111111111111111"

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fakeAPI(t *testing.T, digest *string, token *string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*token = r.Header.Get("Authorization")
		if r.URL.Path != "/repos/o/r/releases/tags/v1" {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1", "immutable": true,
			"assets": []map[string]any{{"name": "r.tgz", "digest": "sha256:" + *digest}}})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func runCLI(env map[string]string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, func(k string) string { return env[k] })
	return code, out.String(), errb.String()
}

func TestCLI(t *testing.T) {
	pinned := "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\necho \"" + goodHash + "  r.tgz\" | sha256sum -c -\n"
	root := tree(t, map[string]string{"install.sh": pinned})
	digest, auth := goodHash, ""
	api := fakeAPI(t, &digest, &auth)
	statePath := filepath.Join(t.TempDir(), "state.json")

	code, out, errs := runCLI(nil, "--api-url", api, "--state", statePath, root)
	if code != 0 || !strings.Contains(out, "No findings.") || !strings.Contains(out, "State saved to") || errs != "" {
		t.Fatalf("clean run: %d\n%s\n%s", code, out, errs)
	}
	if auth != "" {
		t.Errorf("sent auth without token: %q", auth)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state not written: %v", err)
	}

	// The asset is replaced upstream: digest-changed and pin-mismatch, exit 1.
	digest = strings.Repeat("2", 64)
	code, out, _ = runCLI(map[string]string{"GITHUB_TOKEN": "t0k"}, "--api-url", api, "--state", statePath, "--format", "json", root)
	if code != 1 {
		t.Fatalf("swap exit %d\n%s", code, out)
	}
	if auth != "Bearer t0k" {
		t.Errorf("token not sent: %q", auth)
	}
	var doc struct {
		Version  int  `json:"version"`
		Token    bool `json:"token"`
		Findings []struct {
			Rule, Severity string
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	rules := map[string]string{}
	for _, f := range doc.Findings {
		rules[f.Rule] = f.Severity
	}
	if doc.Version != 1 || !doc.Token || rules["digest-changed"] != "high" || rules["pin-mismatch"] != "high" {
		t.Errorf("json %+v", doc)
	}
	if strings.Contains(out, "State saved") {
		t.Error("JSON output must stay valid JSON")
	}

	// --fail-on high with only a high finding still fails; accepting the
	// digest leaves only the pin mismatch.
	code, out, _ = runCLI(nil, "--api-url", api, "--state", statePath, "--accept", "--fail-on", "high", root)
	if code != 1 || strings.Contains(out, "digest-changed") || !strings.Contains(out, "pin-mismatch") {
		t.Errorf("accept run %d\n%s", code, out)
	}

	// Offline: no requests, no state written, unpinned finding only.
	root2 := tree(t, map[string]string{"Dockerfile": "RUN curl -LO https://github.com/o/r/releases/download/v1/r.tgz\n"})
	state2 := filepath.Join(t.TempDir(), "s.json")
	code, out, _ = runCLI(nil, "--offline", "--state", state2, "--api-url", "http://127.0.0.1:1", root2)
	if code != 1 || !strings.Contains(out, "[unpinned]") {
		t.Errorf("offline %d\n%s", code, out)
	}
	if _, err := os.Stat(state2); !os.IsNotExist(err) {
		t.Error("offline run wrote state")
	}
	code, _, _ = runCLI(nil, "--offline", "--no-state", "--fail-on", "high", root2)
	if code != 0 {
		t.Errorf("fail-on high with a medium finding: exit %d", code)
	}
}

func TestCLIErrors(t *testing.T) {
	root := tree(t, map[string]string{"a.sh": "curl -LO https://github.com/o/r/releases/download/v1/r.tgz\n"})
	for _, args := range [][]string{
		{"--format", "xml", root},
		{"--fail-on", "urgent", root},
		{root, root},
		{"--bogus"},
		{filepath.Join(root, "missing")},
		{"--no-state", "--api-url", "http://127.0.0.1:1", root}, // API unreachable
	} {
		if code, _, _ := runCLI(nil, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{"), 0o644)
	if code, _, _ := runCLI(nil, "--state", bad, root); code != 2 {
		t.Errorf("bad state: exit %d", code)
	}
	if code, out, _ := runCLI(nil, "version"); code != 0 || !strings.HasPrefix(out, "releasedrift ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, _ := runCLI(nil, "-h"); code != 0 {
		t.Errorf("help exit %d", code)
	}
}
