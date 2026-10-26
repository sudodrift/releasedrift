package ghapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetRelease(t *testing.T) {
	var gotAuth, gotAccept, gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAccept, gotVersion = r.Header.Get("Authorization"), r.Header.Get("Accept"), r.Header.Get("X-GitHub-Api-Version")
		switch r.URL.Path {
		case "/repos/o/r/releases/tags/v1":
			if r.Header.Get("If-None-Match") == `"e1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"e1"`)
			w.Write([]byte(`{"tag_name":"v1","immutable":true,"assets":[{"name":"a.tgz","digest":"sha256:abc","size":3}]}`))
		case "/repos/o/r/releases/tags/old":
			w.Write([]byte(`{"tag_name":"old","assets":[{"name":"a.tgz","digest":null}]}`))
		case "/repos/o/r/releases/tags/limited":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1700000000")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"API rate limit exceeded"}`))
		case "/repos/o/r/releases/tags/forbidden":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"Resource not accessible"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	c := New(srv.URL, "", "test")
	rel, etag, nm, err := c.GetRelease(ctx, "o", "r", "v1", "")
	if err != nil || nm || etag != `"e1"` {
		t.Fatalf("err %v nm %v etag %s", err, nm, etag)
	}
	if rel.Immutable == nil || !*rel.Immutable || len(rel.Assets) != 1 || rel.Assets[0].Digest != "sha256:abc" {
		t.Errorf("release %+v", rel)
	}
	if gotAuth != "" {
		t.Errorf("no token should send no Authorization, got %q", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" || gotVersion != "2022-11-28" {
		t.Errorf("headers %q %q", gotAccept, gotVersion)
	}

	c = New(srv.URL+"/", "tok", "test")
	rel, etag, nm, err = c.GetRelease(ctx, "o", "r", "v1", `"e1"`)
	if err != nil || !nm || rel != nil || etag != `"e1"` {
		t.Errorf("304: rel %v etag %s nm %v err %v", rel, etag, nm, err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth %q", gotAuth)
	}

	rel, _, _, err = c.GetRelease(ctx, "o", "r", "old", "")
	if err != nil || rel.Immutable != nil || rel.Assets[0].Digest != "" {
		t.Errorf("old release %+v err %v", rel, err)
	}

	if _, _, _, err = c.GetRelease(ctx, "o", "r", "nope", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	_, _, _, err = c.GetRelease(ctx, "o", "r", "limited", "")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Reset.Unix() != 1700000000 {
		t.Errorf("want rate limit error, got %v", err)
	}
	_, _, _, err = c.GetRelease(ctx, "o", "r", "forbidden", "")
	if err == nil || errors.As(err, &rl) || errors.Is(err, ErrNotFound) {
		t.Errorf("want plain error, got %v", err)
	}
	if c.Requests != 5 {
		t.Errorf("requests %d", c.Requests)
	}
}
