package main

import (
	"testing"

	"github.com/conspirates/gh-gha-scan/internal/fix"
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
