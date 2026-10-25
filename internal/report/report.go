// Package report prints scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2/pkg/tableprinter"

	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// Unpinned is one distinct unpinned reference and where it is used.
type Unpinned struct {
	Uses         string   `json:"uses"`
	Repos        []string `json:"repos"`
	SuggestedSHA string   `json:"suggested_sha,omitempty"`
}

// Summarize groups findings by reference: the list of things to pin.
func Summarize(fs []scan.Finding) []Unpinned {
	byUses := map[string]*Unpinned{}
	repos := map[string]map[string]bool{}
	for _, f := range fs {
		u := byUses[f.Uses]
		if u == nil {
			u = &Unpinned{Uses: f.Uses}
			byUses[f.Uses] = u
			repos[f.Uses] = map[string]bool{}
		}
		if f.SuggestedSHA != "" {
			u.SuggestedSHA = f.SuggestedSHA
		}
		if !repos[f.Uses][f.Repo] {
			repos[f.Uses][f.Repo] = true
			u.Repos = append(u.Repos, f.Repo)
		}
	}
	out := make([]Unpinned, 0, len(byUses))
	for _, u := range byUses {
		sort.Strings(u.Repos)
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Repos) != len(out[j].Repos) {
			return len(out[i].Repos) > len(out[j].Repos)
		}
		return out[i].Uses < out[j].Uses
	})
	return out
}

// JSON writes the result as one JSON document.
func JSON(w io.Writer, res scan.Result, repos int, stats any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Repos    int            `json:"repos_scanned"`
		Findings []scan.Finding `json:"findings"`
		Unpinned []Unpinned     `json:"unpinned"`
		Warnings []string       `json:"warnings"`
		Stats    any            `json:"stats"`
	}{repos, res.Findings, Summarize(res.Findings), res.Warnings, stats})
}

// Table writes findings as a table.
func Table(w io.Writer, fs []scan.Finding, isTTY bool, width int) error {
	tp := tableprinter.New(w, isTTY, width)
	tp.AddHeader([]string{"REPO", "FILE", "USES", "KIND", "OWNER", "VIA"})
	for _, f := range fs {
		owner := "same"
		if f.External {
			owner = "external"
		}
		tp.AddField(f.Repo)
		tp.AddField(fmt.Sprintf("%s:%d", f.File, f.Line))
		tp.AddField(f.Uses)
		tp.AddField(f.Kind)
		tp.AddField(owner)
		tp.AddField(strings.Join(f.Via, " > "))
		tp.EndRow()
	}
	return tp.Render()
}

// Summary writes the distinct unpinned references and any warnings.
func Summary(w io.Writer, res scan.Result, repos int) {
	un := Summarize(res.Findings)
	fmt.Fprintf(w, "\nScanned %d repositories: %d unpinned references (%d distinct).\n", repos, len(res.Findings), len(un))
	if len(un) > 0 {
		fmt.Fprintln(w, "\nTo pin:")
		for _, u := range un {
			line := fmt.Sprintf("  %s  (%d repos)", u.Uses, len(u.Repos))
			if u.SuggestedSHA != "" {
				line += "  -> " + u.SuggestedSHA
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(res.Warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings (%d):\n", len(res.Warnings))
		for _, msg := range res.Warnings {
			fmt.Fprintln(w, "  "+msg)
		}
	}
}
