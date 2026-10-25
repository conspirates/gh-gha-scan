// Package report prints scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cli/go-gh/v2/pkg/tableprinter"

	"github.com/conspirates/gh-gha-scan/internal/fix"
)

// JSON writes the result as one JSON document.
func JSON(w io.Writer, repos []fix.Repo, warnings []string, stats any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Repositories []fix.Repo `json:"repositories"`
		Warnings     []string   `json:"warnings"`
		Stats        any        `json:"stats"`
	}{repos, warnings, stats})
}

// Table writes one row per action that has to change, and a None row for
// each repository with nothing to change. Nothing is truncated: every column
// is needed to act on a row, so long rows wrap instead.
func Table(w io.Writer, repos []fix.Repo, isTTY bool, width int) error {
	tp := tableprinter.New(w, isTTY, width)
	whole := tableprinter.WithTruncate(nil)
	tp.AddHeader([]string{"REPOSITORY", "UNPINNED ACTION", "FIX"}, whole)
	for _, r := range repos {
		if len(r.Items) == 0 {
			tp.AddField(r.Repository, whole)
			tp.AddField("None", whole)
			tp.AddField("")
			tp.EndRow()
			continue
		}
		for _, it := range r.Items {
			tp.AddField(r.Repository, whole)
			tp.AddField(it.Action, whole)
			tp.AddField(it.Fix, whole)
			tp.EndRow()
		}
	}
	return tp.Render()
}

// Summary writes counts and warnings.
func Summary(w io.Writer, repos []fix.Repo, warnings []string) {
	affected, items := 0, 0
	for _, r := range repos {
		if len(r.Items) > 0 {
			affected++
			items += len(r.Items)
		}
	}
	fmt.Fprintf(w, "\nScanned %d repositories: %d affected, %d actions to change.\n", len(repos), affected, items)
	if len(warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings (%d):\n", len(warnings))
		for _, msg := range warnings {
			fmt.Fprintln(w, "  "+msg)
		}
	}
}
