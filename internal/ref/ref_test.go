package ref

import (
	"reflect"
	"testing"
)

const sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"

func TestParse(t *testing.T) {
	tests := []struct {
		in     string
		want   Ref
		pinned bool
	}{
		{"./.github/actions/setup", Ref{Kind: Local, Path: ".github/actions/setup"}, false},
		{"$/.github/actions/setup", Ref{Kind: Self, Path: ".github/actions/setup"}, false},
		{"$/.github/actions/setup@v1", Ref{Kind: Invalid}, false},
		{"docker://alpine:3.20", Ref{Kind: Docker}, false},
		{"actions/checkout@v4", Ref{Kind: Action, Owner: "actions", Repo: "checkout", Ref: "v4"}, false},
		{"actions/checkout@" + sha, Ref{Kind: Action, Owner: "actions", Repo: "checkout", Ref: sha}, true},
		{"actions/checkout@3d3c42e", Ref{Kind: Action, Owner: "actions", Repo: "checkout", Ref: "3d3c42e"}, false},
		{"github/codeql-action/init@main", Ref{Kind: Action, Owner: "github", Repo: "codeql-action", Path: "init", Ref: "main"}, false},
		{"o/r/a/b/@v1", Ref{Kind: Action, Owner: "o", Repo: "r", Path: "a/b", Ref: "v1"}, false},
		{"o/r/.github/workflows/ci.yml@v1", Ref{Kind: Workflow, Owner: "o", Repo: "r", Path: ".github/workflows/ci.yml", Ref: "v1"}, false},
		{"o/r/.github/workflows/ci.yaml@" + sha, Ref{Kind: Workflow, Owner: "o", Repo: "r", Path: ".github/workflows/ci.yaml", Ref: sha}, true},
		{"actions/checkout", Ref{Kind: Invalid}, false},
		{"actions/checkout@", Ref{Kind: Invalid}, false},
		{"checkout@v4", Ref{Kind: Invalid}, false},
		{"", Ref{Kind: Invalid}, false},
	}
	for _, tt := range tests {
		got := Parse(tt.in)
		tt.want.Raw = tt.in
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
		if got.IsPinned() != tt.pinned {
			t.Errorf("Parse(%q).IsPinned() = %v, want %v", tt.in, got.IsPinned(), tt.pinned)
		}
	}
}

func TestCandidates(t *testing.T) {
	tests := map[string][]string{
		"o/r@v1":                         {"action.yml", "action.yaml"},
		"o/r/sub/dir@v1":                 {"sub/dir/action.yml", "sub/dir/action.yaml"},
		"o/r/.github/workflows/x.yml@v1": {".github/workflows/x.yml"},
		"./.github/actions/setup":        {".github/actions/setup/action.yml", ".github/actions/setup/action.yaml"},
		"./.github/workflows/reuse.yml":  {".github/workflows/reuse.yml"},
		"$/.github/actions/setup":        {".github/actions/setup/action.yml", ".github/actions/setup/action.yaml"},
		"$/.github/workflows/reuse.yml":  {".github/workflows/reuse.yml"},
	}
	for in, want := range tests {
		if got := Parse(in).Candidates(); !reflect.DeepEqual(got, want) {
			t.Errorf("Candidates(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestKeyIsCaseInsensitiveForRepo(t *testing.T) {
	if Parse("Actions/Checkout@v4").Key() != Parse("actions/checkout@v4").Key() {
		t.Error("keys should match regardless of owner/repo case")
	}
}
