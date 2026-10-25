// Package report prints scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cli/go-gh/v2/pkg/tableprinter"

	"github.com/conspirates/gh-gha-scan/internal/fix"
)

// Skipped is what an --owner scan left out.
type Skipped struct {
	// Forks counts the forks left out without --include-forks.
	Forks int `json:"forks"`
	// Workflows lists workflow files in included forks that GitHub won't
	// run, so the SHA pinning policy doesn't apply to them.
	Workflows []SkippedWorkflow `json:"workflows"`
}

// SkippedWorkflow is a workflow file that was not scanned.
type SkippedWorkflow struct {
	Repository string `json:"repository"`
	File       string `json:"file"`
	// State is the workflow's state on GitHub, e.g. "disabled_fork", or
	// "not_registered" when GitHub has never registered the file, as in a
	// fork where Actions was never enabled.
	State string `json:"state"`
}

// JSON writes the result as one JSON document.
func JSON(w io.Writer, repos []fix.Repo, skipped Skipped, warnings []string, stats any) error {
	if skipped.Workflows == nil {
		skipped.Workflows = []SkippedWorkflow{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Repositories []fix.Repo `json:"repositories"`
		Skipped      Skipped    `json:"skipped"`
		Warnings     []string   `json:"warnings"`
		Stats        any        `json:"stats"`
	}{repos, skipped, warnings, stats})
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
			none := "None"
			if r.Incomplete {
				none = "None (incomplete, see warnings)"
			}
			tp.AddField(r.Repository, whole)
			tp.AddField(none, whole)
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

// Summary writes counts, what was skipped, and warnings.
func Summary(w io.Writer, repos []fix.Repo, skipped Skipped, warnings []string) {
	affected, items, incomplete := 0, 0, 0
	for _, r := range repos {
		if len(r.Items) > 0 {
			affected++
			items += len(r.Items)
		}
		if r.Incomplete {
			incomplete++
		}
	}
	fmt.Fprintf(w, "\nScanned %d repositories: %d affected, %d actions to change.\n", len(repos), affected, items)
	if incomplete > 0 {
		fmt.Fprintf(w, "%d repositories were not fully checked; see the warnings below.\n", incomplete)
	}
	if skipped.Forks > 0 {
		fmt.Fprintf(w, "Skipped %d forks (use --include-forks).\n", skipped.Forks)
	}
	if len(skipped.Workflows) > 0 {
		fmt.Fprintf(w, "\nSkipped %d workflows in forks that GitHub won't run:\n", len(skipped.Workflows))
		for _, s := range skipped.Workflows {
			fmt.Fprintf(w, "  %s: %s (%s)\n", s.Repository, s.File, s.State)
		}
	}
	if len(warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings (%d):\n", len(warnings))
		for _, msg := range warnings {
			fmt.Fprintln(w, "  "+msg)
		}
	}
}
