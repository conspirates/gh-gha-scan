package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/conspirates/gh-gha-scan/internal/fix"
	"github.com/conspirates/gh-gha-scan/internal/gh"
	"github.com/conspirates/gh-gha-scan/internal/report"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

func TestStatus(t *testing.T) {
	clean := fix.Repo{Repository: "o/clean", Items: []fix.Item{}}
	incomplete := fix.Repo{Repository: "o/incomplete", Items: []fix.Item{}, Incomplete: true}
	affected := fix.Repo{Repository: "o/affected", Items: []fix.Item{{Action: "a/a@v1"}}}
	tests := []struct {
		name  string
		repos []fix.Repo
		want  error
	}{
		{"clean", []fix.Repo{clean}, nil},
		{"incomplete", []fix.Repo{clean, incomplete}, exitStatus(exitIncomplete)},
		{"unpinned wins over incomplete", []fix.Repo{incomplete, affected}, exitStatus(exitUnpinned)},
		{"no repositories", nil, nil},
	}
	for _, tt := range tests {
		if got := status(tt.repos); got != tt.want {
			t.Errorf("%s: status() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

type fakeStates map[string]map[string]string

func (f fakeStates) WorkflowStates(_ context.Context, repo string) (map[string]string, error) {
	s, ok := f[repo]
	if !ok {
		return nil, errors.New("HTTP 404: Not Found")
	}
	return s, nil
}

func TestDropNotRunnable(t *testing.T) {
	files := func(names ...string) []scan.File {
		var out []scan.File
		for _, n := range names {
			out = append(out, scan.File{Path: ".github/workflows/" + n})
		}
		return out
	}
	repos := []gh.Repo{
		{NameWithOwner: "o/app", Files: files("ci.yml")},
		{NameWithOwner: "o/enabled", IsFork: true, Files: files("ci.yml", "cron.yml", "new.yml")},
		{NameWithOwner: "o/never", IsFork: true, Files: files("ci.yml")},
		{NameWithOwner: "o/gone", IsFork: true, Files: files("ci.yml")},
	}
	states := fakeStates{
		"o/enabled": {".github/workflows/ci.yml": "active", ".github/workflows/cron.yml": "disabled_fork"},
		"o/never":   {},
	}
	skipped, warnings := dropNotRunnable(context.Background(), states, repos)

	kept := map[string]int{}
	for _, r := range repos {
		kept[r.NameWithOwner] = len(r.Files)
	}
	// Non-forks and forks whose states can't be read are scanned in full.
	if want := map[string]int{"o/app": 1, "o/enabled": 1, "o/never": 0, "o/gone": 1}; !reflect.DeepEqual(kept, want) {
		t.Errorf("files kept = %v, want %v", kept, want)
	}
	want := []report.SkippedWorkflow{
		{Repository: "o/enabled", File: ".github/workflows/cron.yml", State: "disabled_fork"},
		{Repository: "o/enabled", File: ".github/workflows/new.yml", State: "not_registered"},
		{Repository: "o/never", File: ".github/workflows/ci.yml", State: "not_registered"},
	}
	if !reflect.DeepEqual(skipped, want) {
		t.Errorf("skipped =\n%+v\nwant\n%+v", skipped, want)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "o/gone") {
		t.Errorf("warnings = %v", warnings)
	}
}
