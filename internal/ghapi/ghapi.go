// Package ghapi is a small read-only client for the GitHub REST API
// releases endpoint.
package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public GitHub API.
const DefaultBaseURL = "https://api.github.com"

// Asset is the part of a release asset that releasedrift uses.
type Asset struct {
	Name string `json:"name"`
	// Digest is "sha256:<hex>". GitHub fills it for assets uploaded since
	// mid-2025; older assets may have none.
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Release is the part of a release that releasedrift uses.
type Release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	// Immutable is nil when the API response has no "immutable" field.
	Immutable *bool   `json:"immutable"`
	Assets    []Asset `json:"assets"`
}

// ErrNotFound means the release (or repository) does not exist or is not
// visible with the current token.
var ErrNotFound = errors.New("release not found")

// RateLimitError means GitHub refused the request because of rate limits.
type RateLimitError struct {
	Reset   time.Time
	Message string
}

func (e *RateLimitError) Error() string {
	msg := "GitHub API rate limit reached"
	if !e.Reset.IsZero() {
		msg += fmt.Sprintf(" (resets at %s)", e.Reset.UTC().Format(time.RFC3339))
	}
	return msg + "; set GITHUB_TOKEN to get a higher limit"
}

// Client talks to the API. The zero value is not usable; use New.
type Client struct {
	BaseURL   string
	Token     string
	HTTP      *http.Client
	UserAgent string
	// Requests counts HTTP requests made, for the summary line.
	Requests int
}

// New returns a client for baseURL (DefaultBaseURL if empty).
func New(baseURL, token, userAgent string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Token:     token,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		UserAgent: userAgent,
	}
}

// GetRelease fetches the release for tag. If etag is not empty it is sent as
// If-None-Match; notModified is true when GitHub answers 304, in which case
// rel is nil and the caller should reuse what it stored.
func (c *Client) GetRelease(ctx context.Context, owner, repo, tag, etag string) (rel *Release, newETag string, notModified bool, err error) {
	u := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", c.BaseURL, url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	c.Requests++
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, "", false, err
	}
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, etag, true, nil
	case resp.StatusCode == http.StatusOK:
		var r Release
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, "", false, fmt.Errorf("GET %s: bad JSON: %w", u, err)
		}
		return &r, resp.Header.Get("ETag"), false, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, "", false, ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0"):
		e := &RateLimitError{Message: apiMessage(body)}
		if s, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			e.Reset = time.Unix(s, 0)
		}
		return nil, "", false, e
	}
	return nil, "", false, fmt.Errorf("GET %s: HTTP %d: %s", u, resp.StatusCode, apiMessage(body))
}

func apiMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		return m.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
