// Package check combines the scan results, the GitHub API and the state file
// into findings.
package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/sudodrift/releasedrift/internal/ghapi"
	"github.com/sudodrift/releasedrift/internal/scan"
	"github.com/sudodrift/releasedrift/internal/state"
)

// Severity of a finding.
type Severity int

const (
	Info Severity = iota + 1
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "unknown"
}

// MarshalJSON writes the name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity parses info|low|medium|high.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want info, low, medium or high)", s)
}

// Finding is one problem.
type Finding struct {
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
	Release  string   `json:"release,omitempty"`
	Asset    string   `json:"asset,omitempty"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix"`
}

// AssetStatus is what the API said about one asset a ref points at.
type AssetStatus struct {
	Name   string `json:"name"`
	Digest string `json:"digest,omitempty"`
	// Pin is "match", "mismatch", "no-digest" or empty when the ref has no
	// literal hash.
	Pin string `json:"pin,omitempty"`
}

// RefStatus is a scanned ref plus what was learned about it.
type RefStatus struct {
	scan.Ref
	Checked   bool          `json:"checked"`
	Immutable *bool         `json:"immutable,omitempty"`
	Assets    []AssetStatus `json:"assets,omitempty"`
}

// Report is the result of a run.
type Report struct {
	Root     string      `json:"root"`
	Files    int         `json:"files_scanned"`
	Offline  bool        `json:"offline"`
	Token    bool        `json:"token"`
	Requests int         `json:"api_requests"`
	Releases int         `json:"releases_checked"`
	Refs     []RefStatus `json:"refs"`
	Findings []Finding   `json:"findings"`
	Errors   []string    `json:"errors,omitempty"`
	Warnings []string    `json:"warnings,omitempty"`
}

// Options for Run.
type Options struct {
	Offline bool
	// Accept records changed digests as the new expected values.
	Accept bool
	Now    time.Time
}

// Worst returns the highest severity in the report, or 0.
func (r *Report) Worst() Severity {
	var w Severity
	for _, f := range r.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

// Count returns how many findings have severity s.
func (r *Report) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

const incident = "https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw"

// Run checks every ref. st is updated in place; the caller saves it.
func Run(ctx context.Context, root string, res *scan.Result, client *ghapi.Client, st *state.File, opt Options) *Report {
	if opt.Now.IsZero() {
		opt.Now = time.Now().UTC()
	}
	rep := &Report{Root: root, Files: res.Files, Offline: opt.Offline, Refs: []RefStatus{}, Findings: []Finding{}, Warnings: res.Warnings}
	if client != nil {
		rep.Token = client.Token != ""
	}
	add := func(f Finding) { rep.Findings = append(rep.Findings, f) }

	for _, r := range res.Refs {
		rep.Refs = append(rep.Refs, RefStatus{Ref: r})
	}

	// Findings that need no network.
	for _, rs := range rep.Refs {
		r := rs.Ref
		rel := ""
		if r.Owner != "" {
			rel = r.Key()
		}
		switch {
		case r.Kind == "latest-url":
			add(Finding{Severity: Medium, Rule: "latest-url", File: r.File, Line: r.Line, Release: r.Owner + "/" + r.Repo, Asset: r.Asset,
				Message: "The URL uses releases/latest, so it downloads whatever the newest release is. The file changes with every release and cannot be compared with an earlier run.",
				Fix:     "Use a versioned URL (releases/download/TAG/ASSET) and pin its SHA-256."})
			continue
		case r.Unresolved:
			add(Finding{Severity: Info, Rule: "unresolved", File: r.File, Line: r.Line, Release: rel, Asset: r.Asset,
				Message: "The download uses a variable or omits the repository or tag, so releasedrift cannot tell which release it is and did not look it up.",
				Fix:     "Write the owner, repository and tag literally, or check this download by hand."})
		}
		if isChecksumAsset(r.Asset) {
			continue // the checksums file is the thing used to verify others
		}
		switch r.Pin.Kind {
		case "none":
			add(Finding{Severity: Medium, Rule: "unpinned", File: r.File, Line: r.Line, Release: rel, Asset: r.Asset,
				Message: "No SHA-256 check was found near this download, so a replaced file would be used without notice.",
				Fix:     "Pin the SHA-256 next to the download, for example: echo \"HASH  FILE\" | sha256sum -c -  (or ADD --checksum=sha256:HASH in a Dockerfile)."})
		case "checksums-file":
			add(Finding{Severity: Low, Rule: "same-release-checksums", File: r.File, Line: r.Line, Release: rel, Asset: r.Asset,
				Message: "The file is only checked against a checksums file downloaded from the same release. On a release that is not immutable, anyone who can replace the asset can replace the checksums file next to it as well.",
				Fix:     "Store the expected SHA-256 in this repository instead of fetching it from the release."})
		}
	}

	// Group resolved refs by release.
	byRelease := map[string][]int{}
	var keys []string
	for i, rs := range rep.Refs {
		r := rs.Ref
		if r.Kind == "latest-url" || r.Unresolved || r.Owner == "" || r.Tag == "" {
			continue
		}
		k := r.Key()
		if _, ok := byRelease[k]; !ok {
			keys = append(keys, k)
		}
		byRelease[k] = append(byRelease[k], i)
	}
	sort.Strings(keys)
	if opt.Offline || client == nil {
		return finish(rep, client)
	}

	immutableRel := map[string]bool{}
	stopped := false
	for _, k := range keys {
		if stopped {
			break
		}
		idx := byRelease[k]
		first := rep.Refs[idx[0]].Ref
		saved := st.Releases[k]

		etag := ""
		if saved != nil && saved.ETag != "" && haveAll(saved, rep.Refs, idx) {
			etag = saved.ETag
		}
		rel, newETag, notModified, err := client.GetRelease(ctx, first.Owner, first.Repo, first.Tag, etag)
		var rl *ghapi.RateLimitError
		switch {
		case errors.As(err, &rl):
			rep.Errors = append(rep.Errors, rl.Error())
			stopped = true
			continue
		case errors.Is(err, ghapi.ErrNotFound):
			for _, i := range idx {
				r := rep.Refs[i].Ref
				add(Finding{Severity: Medium, Rule: "release-missing", File: r.File, Line: r.Line, Release: k, Asset: r.Asset,
					Message: "GitHub has no release with this tag (or the repository is private or gone). The download will fail, or the release was deleted.",
					Fix:     "Check the tag. If the release was deleted on purpose, update the download."})
			}
			rep.Releases++
			continue
		case err != nil:
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", k, err))
			continue
		}
		rep.Releases++

		digests := map[string]string{}
		var names []string
		var immutable *bool
		if notModified {
			immutable = saved.Immutable
			for n, a := range saved.Assets {
				d := a.Digest
				if a.ChangedTo != "" {
					d = a.ChangedTo
				}
				digests[n] = d
				names = append(names, n)
			}
		} else {
			immutable = rel.Immutable
			for _, a := range rel.Assets {
				digests[a.Name] = a.Digest
				names = append(names, a.Name)
			}
		}
		sort.Strings(names)

		if saved == nil {
			saved = &state.Release{Assets: map[string]*state.Asset{}}
			st.Releases[k] = saved
		}
		if !notModified {
			saved.ETag = newETag
			saved.Immutable = immutable
		}
		saved.CheckedAt = opt.Now

		if immutable != nil && *immutable {
			immutableRel[k] = true
		}
		allPinned := true
		for _, i := range idx {
			rs := &rep.Refs[i]
			rs.Checked = true
			rs.Immutable = immutable
			r := rs.Ref
			var matched []string
			switch {
			case r.Kind == "url":
				if _, ok := digests[r.Asset]; ok {
					matched = []string{r.Asset}
				}
			case r.Asset == "":
				matched = names
			default:
				for _, n := range names {
					if ok, _ := path.Match(r.Asset, n); ok {
						matched = append(matched, n)
					}
				}
			}
			if len(matched) == 0 {
				add(Finding{Severity: Medium, Rule: "asset-missing", File: r.File, Line: r.Line, Release: k, Asset: r.Asset,
					Message: "The release exists but has no asset with this name. It may have been deleted or renamed.",
					Fix:     "Check the asset name against the release page."})
				continue
			}
			pinOK := false
			for _, n := range matched {
				d := digests[n]
				as := AssetStatus{Name: n, Digest: d}
				if r.Pin.Kind == "sha256" {
					switch {
					case d == "":
						as.Pin = "no-digest"
					case strings.EqualFold(strings.TrimPrefix(d, "sha256:"), r.Pin.Hash):
						as.Pin = "match"
						pinOK = true
					default:
						as.Pin = "mismatch"
					}
				}
				rs.Assets = append(rs.Assets, as)
				trackDigest(saved, n, d, r, k, opt, add)
			}
			if !pinOK {
				allPinned = false
			}
			if r.Pin.Kind == "sha256" && !pinOK {
				noDigest := true
				for _, a := range rs.Assets {
					if a.Pin != "no-digest" {
						noDigest = false
					}
				}
				if noDigest {
					add(Finding{Severity: Info, Rule: "no-digest", File: r.File, Line: r.Line, Release: k, Asset: r.Asset,
						Message: "GitHub reports no digest for this asset (assets uploaded before digests existed have none), so the pinned hash could not be compared.",
						Fix:     "Nothing to do here; your pinned hash still protects the download."})
				} else {
					add(Finding{Severity: High, Rule: "pin-mismatch", File: r.File, Line: r.Line, Release: k, Asset: r.Asset,
						Message: fmt.Sprintf("The pinned SHA-256 %s (line %d) does not match the digest GitHub reports now (%s). Either the pin is wrong or the asset was replaced.", short(r.Pin.Hash), r.Pin.Line, digestList(rs.Assets)),
						Fix:     "Do not update the pin blindly. Find out why the file changed (release notes, the project's security advisories) before trusting the new file."})
				}
			}
		}
		if immutable != nil && !*immutable {
			sev, extra := Low, ""
			if allPinned {
				sev, extra = Info, " Every download from it here is pinned to a SHA-256 that matches, so a swap would be caught."
			}
			add(Finding{Severity: sev, Rule: "mutable-release", File: first.File, Line: first.Line, Release: k,
				Message: "This release is not immutable, so its assets can still be deleted and replaced. That is how the ovhcloud-cli assets were swapped (" + incident + ")." + extra,
				Fix:     "Pin the SHA-256 of each asset you download. If you maintain the project, turn on immutable releases."})
		}
	}
	for i, f := range rep.Findings {
		if f.Rule == "same-release-checksums" && immutableRel[f.Release] {
			rep.Findings[i].Severity = Info
			rep.Findings[i].Message += " This release is immutable, so neither file can be replaced today; the finding matters if you switch to a release that is not."
		}
	}
	return finish(rep, client)
}

// trackDigest compares the current digest with the state and records it.
func trackDigest(saved *state.Release, name, digest string, r scan.Ref, key string, opt Options, add func(Finding)) {
	a := saved.Assets[name]
	if a == nil {
		// Assets uploaded before GitHub computed digests have none. They
		// are recorded too: if one gets a digest later, it was uploaded
		// again.
		saved.Assets[name] = &state.Asset{Digest: digest, FirstSeen: opt.Now}
		return
	}
	if a.Digest == digest && a.ChangedTo == "" || digest == "" {
		return
	}
	if opt.Accept {
		a.Digest, a.ChangedTo, a.ChangedAt, a.FirstSeen = digest, "", nil, opt.Now
		return
	}
	if a.Digest != digest && a.ChangedTo != digest {
		t := opt.Now
		a.ChangedTo, a.ChangedAt = digest, &t
	}
	msg := fmt.Sprintf("The digest of %s changed. It was %s when first seen on %s and is now %s.", name, a.Digest, a.FirstSeen.Format("2006-01-02"), digest)
	switch {
	case a.Digest == "" && a.ChangedTo == digest:
		msg = fmt.Sprintf("%s had no digest when first seen on %s and has %s now. GitHub computes digests when a file is uploaded, so this file was uploaded again.", name, a.FirstSeen.Format("2006-01-02"), digest)
	case a.Digest == digest:
		msg = fmt.Sprintf("The digest of %s changed to %s on %s and is now back to %s.", name, a.ChangedTo, a.ChangedAt.Format("2006-01-02"), digest)
	}
	add(Finding{Severity: High, Rule: "digest-changed", File: r.File, Line: r.Line, Release: key, Asset: name,
		Message: msg + " A release asset that changes after publication may have been swapped, as in the ovhcloud-cli incident (" + incident + ").",
		Fix:     "Do not use the file until you know why it changed. Compare with the project's announcements. Once you are sure the new file is good, run again with --accept."})
}

func haveAll(saved *state.Release, refs []RefStatus, idx []int) bool {
	for _, i := range idx {
		r := refs[i].Ref
		if r.Kind != "url" {
			return false // patterns need the full asset list
		}
		if _, ok := saved.Assets[r.Asset]; !ok {
			return false
		}
	}
	return true
}

func finish(rep *Report, client *ghapi.Client) *Report {
	if client != nil {
		rep.Requests = client.Requests
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return rep
}

func isChecksumAsset(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "checksum") || strings.Contains(n, "sha256") || strings.Contains(n, "shasum")
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}

func digestList(as []AssetStatus) string {
	var s []string
	for _, a := range as {
		s = append(s, short(strings.TrimPrefix(a.Digest, "sha256:")))
	}
	return strings.Join(s, ", ")
}
