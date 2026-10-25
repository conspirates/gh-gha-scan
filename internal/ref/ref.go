// Package ref parses the value of a GitHub Actions `uses:` key.
package ref

import (
	"regexp"
	"strings"
)

// Kind classifies a `uses:` value.
type Kind int

const (
	// Invalid is a value that could not be parsed.
	Invalid Kind = iota
	// Local is a path in the same repository, e.g. ./.github/actions/foo.
	Local
	// Self is a path in the repository of the file it is written in, at the
	// running commit, e.g. $/.github/actions/foo.
	Self
	// Docker is a container image, e.g. docker://alpine:3.
	Docker
	// Action is a repository action, e.g. actions/checkout@v4.
	Action
	// Workflow is a reusable workflow, e.g. o/r/.github/workflows/x.yml@v1.
	Workflow
)

func (k Kind) String() string {
	switch k {
	case Local:
		return "local"
	case Self:
		return "self"
	case Docker:
		return "docker"
	case Action:
		return "action"
	case Workflow:
		return "workflow"
	}
	return "invalid"
}

// Ref is a parsed `uses:` value.
type Ref struct {
	Raw   string
	Kind  Kind
	Owner string
	Repo  string
	// Path is the subdirectory of an action, or the file path of a reusable
	// workflow. Empty for an action at the repository root.
	Path string
	// Ref is the git ref after '@'.
	Ref string
}

var fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// IsFullSHA reports whether s is a full-length commit SHA.
func IsFullSHA(s string) bool { return fullSHA.MatchString(s) }

// Parse parses a `uses:` value.
func Parse(s string) Ref {
	s = strings.TrimSpace(s)
	r := Ref{Raw: s}
	switch {
	case strings.HasPrefix(s, "./"):
		r.Kind = Local
		r.Path = strings.Trim(strings.TrimPrefix(s, "./"), "/")
		return r
	case strings.HasPrefix(s, "$/"):
		// The commit is always the running one, so a ref is not allowed.
		if strings.Contains(s, "@") {
			return r
		}
		r.Kind = Self
		r.Path = strings.Trim(strings.TrimPrefix(s, "$/"), "/")
		return r
	case strings.HasPrefix(s, "docker://"):
		r.Kind = Docker
		return r
	}

	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return r
	}
	name, gitRef := s[:at], s[at+1:]
	parts := strings.SplitN(name, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return r
	}
	r.Owner, r.Repo, r.Ref = parts[0], parts[1], gitRef
	if len(parts) == 3 {
		r.Path = strings.Trim(parts[2], "/")
	}
	r.Kind = Action
	if IsWorkflowPath(r.Path) {
		r.Kind = Workflow
	}
	return r
}

// IsWorkflowPath reports whether p is a workflow file, i.e. a reusable
// workflow rather than an action directory.
func IsWorkflowPath(p string) bool {
	return strings.HasPrefix(p, ".github/workflows/") &&
		(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"))
}

// IsRemote reports whether r refers to another repository (an action or a
// reusable workflow), which is what the SHA pinning policy applies to.
func (r Ref) IsRemote() bool { return r.Kind == Action || r.Kind == Workflow }

// IsPinned reports whether r is pinned to a full-length commit SHA.
func (r Ref) IsPinned() bool { return IsFullSHA(r.Ref) }

// Name returns owner/repo[/path].
func (r Ref) Name() string {
	if r.Path == "" {
		return r.Owner + "/" + r.Repo
	}
	return r.Owner + "/" + r.Repo + "/" + r.Path
}

// Key identifies the file content r points at. Owner and repo names are
// case-insensitive on GitHub, so they are lowercased.
func (r Ref) Key() string {
	return strings.ToLower(r.Owner+"/"+r.Repo) + "/" + r.Path + "@" + r.Ref
}

// Candidates returns the file paths that may hold r's definition, in the
// order GitHub looks them up. A local or self ref to a workflow file is a
// reusable workflow in the same repository, so it is the file itself.
func (r Ref) Candidates() []string {
	if r.Kind == Workflow || ((r.Kind == Local || r.Kind == Self) && IsWorkflowPath(r.Path)) {
		return []string{r.Path}
	}
	dir := r.Path
	if dir != "" {
		dir += "/"
	}
	return []string{dir + "action.yml", dir + "action.yaml"}
}
