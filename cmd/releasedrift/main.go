// releasedrift finds GitHub release downloads in a directory tree, checks
// that they are pinned to a SHA-256, and warns when a release asset changes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/sudodrift/releasedrift/internal/check"
	"github.com/sudodrift/releasedrift/internal/ghapi"
	"github.com/sudodrift/releasedrift/internal/scan"
	"github.com/sudodrift/releasedrift/internal/state"
)

// version is set with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func init() {
	if strings.HasSuffix(version, "-dev") {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = bi.Main.Version
		}
	}
}

const usage = `releasedrift %s: check GitHub release downloads for pinning and swapped assets

Usage:
  releasedrift [flags] [DIR]     scan DIR (default: current directory)
  releasedrift version

Flags (one or two dashes):
  --state FILE        state file with the digests seen before (default releasedrift.state.json)
  --no-state          do not read or write a state file
  --accept            record changed digests as the new expected values
  --offline           do not call the GitHub API; only look for missing pins
  --format text|json  output format (default text)
  --fail-on LEVEL     exit 1 if a finding is at this level or above: info, low, medium, high (default low)
  --api-url URL       GitHub API base URL (default https://api.github.com)

Environment:
  GITHUB_TOKEN        optional token; without one GitHub allows 60 API requests an hour

Exit codes: 0 no findings at the --fail-on level, 1 findings, 2 error.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)) }

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version") {
		fmt.Fprintln(stdout, "releasedrift", version)
		return 0
	}
	fs := flag.NewFlagSet("releasedrift", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintf(stderr, usage, version) }
	statePath := fs.String("state", "releasedrift.state.json", "state file")
	noState := fs.Bool("no-state", false, "do not use a state file")
	accept := fs.Bool("accept", false, "accept changed digests")
	offline := fs.Bool("offline", false, "no network")
	format := fs.String("format", "text", "text or json")
	failOn := fs.String("fail-on", "low", "info, low, medium or high")
	apiURL := fs.String("api-url", ghapi.DefaultBaseURL, "GitHub API base URL")

	var pos []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, "releasedrift: give at most one directory")
		return 2
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "releasedrift: unknown format %q (want text or json)\n", *format)
		return 2
	}
	fail, err := check.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "releasedrift: --fail-on:", err)
		return 2
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(stderr, "releasedrift: %s is not a directory\n", dir)
		return 2
	}

	st := state.New()
	if !*noState {
		if st, err = state.Load(*statePath); err != nil {
			fmt.Fprintln(stderr, "releasedrift:", err)
			return 2
		}
	}
	res, err := scan.Dir(dir)
	if err != nil {
		fmt.Fprintln(stderr, "releasedrift:", err)
		return 2
	}
	client := ghapi.New(*apiURL, getenv("GITHUB_TOKEN"), "releasedrift/"+version)
	rep := check.Run(context.Background(), dir, res, client, st, check.Options{Offline: *offline, Accept: *accept})

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(jsonOut{Version: 1, Tool: "releasedrift", ToolVersion: version, Report: rep}); err != nil {
			fmt.Fprintln(stderr, "releasedrift:", err)
			return 2
		}
	} else {
		writeText(stdout, rep)
	}

	if !*noState && !*offline && rep.Releases > 0 {
		if err := st.Save(*statePath); err != nil {
			fmt.Fprintln(stderr, "releasedrift: saving state:", err)
			return 2
		}
		if *format == "text" {
			fmt.Fprintf(stdout, "State saved to %s\n", *statePath)
		}
	}
	if len(rep.Errors) > 0 {
		for _, e := range rep.Errors {
			fmt.Fprintln(stderr, "releasedrift:", e)
		}
		return 2
	}
	if w := rep.Worst(); w != 0 && w >= fail {
		return 1
	}
	return 0
}

type jsonOut struct {
	Version     int    `json:"version"`
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
	*check.Report
}

func writeText(w io.Writer, rep *check.Report) {
	mode := "GitHub API without a token"
	switch {
	case rep.Offline:
		mode = "offline, GitHub API not used"
	case rep.Token:
		mode = "GitHub API with GITHUB_TOKEN"
	}
	fmt.Fprintf(w, "releasedrift %s: %d files scanned in %s, %d release downloads found (%s)\n", version, rep.Files, rep.Root, len(rep.Refs), mode)
	if !rep.Offline {
		fmt.Fprintf(w, "Releases checked: %d, API requests: %d\n", rep.Releases, rep.Requests)
	}
	if len(rep.Refs) > 0 {
		fmt.Fprintln(w, "\nDownloads:")
	}
	for _, r := range rep.Refs {
		what := r.Asset
		if what == "" {
			what = "(all assets)"
		}
		rel := r.Owner + "/" + r.Repo
		if r.Tag != "" {
			rel += " " + r.Tag
		}
		if r.Kind == "latest-url" {
			rel += " (latest)"
		}
		fmt.Fprintf(w, "  %s:%d  %s  %s\n", r.File, r.Line, rel, what)
		pin := "not pinned"
		switch r.Pin.Kind {
		case "sha256":
			pin = fmt.Sprintf("pinned sha256 %s... (line %d)", r.Pin.Hash[:12], r.Pin.Line)
		case "checksums-file":
			pin = fmt.Sprintf("checked against a checksums file from the same release (line %d)", r.Pin.Line)
		}
		var extra []string
		if r.Checked {
			if r.Immutable != nil {
				if *r.Immutable {
					extra = append(extra, "release immutable")
				} else {
					extra = append(extra, "release NOT immutable")
				}
			}
			for _, a := range r.Assets {
				s := a.Name + " " + a.Digest
				if a.Digest == "" {
					s = a.Name + " (no digest)"
				}
				if a.Pin != "" {
					s += " pin " + a.Pin
				}
				extra = append(extra, s)
			}
		} else if r.Unresolved {
			extra = append(extra, "not looked up (uses a variable)")
		}
		fmt.Fprintf(w, "      %s\n", pin)
		for _, e := range extra {
			fmt.Fprintf(w, "      %s\n", e)
		}
	}
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "\nNo findings.")
	} else {
		fmt.Fprintln(w, "\nFindings:")
		for _, f := range rep.Findings {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(w, "  %-6s %s  [%s]\n", strings.ToUpper(f.Severity.String()), loc, f.Rule)
			fmt.Fprintf(w, "         %s\n", f.Message)
			fmt.Fprintf(w, "         fix: %s\n", f.Fix)
		}
	}
	fmt.Fprintf(w, "\nSummary: %d high, %d medium, %d low, %d info\n", rep.Count(check.High), rep.Count(check.Medium), rep.Count(check.Low), rep.Count(check.Info))
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "Error: %s\n", e)
	}
}
