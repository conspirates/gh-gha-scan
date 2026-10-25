// Package scan finds `uses:` references that are not pinned to a full commit
// SHA, following composite actions and reusable workflows transitively.
package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/conspirates/gh-gha-scan/internal/ref"
	"github.com/conspirates/gh-gha-scan/internal/workflow"
)

// FileReq asks for the first existing file among Paths in Owner/Repo at Ref.
type FileReq struct {
	Owner, Repo, Ref string
	Paths            []string
	// Resolve asks for the commit SHA that Ref points at.
	Resolve bool
}

// FileRes is the answer to a FileReq.
type FileRes struct {
	Found bool   `json:"found"`
	Path  string `json:"path,omitempty"`
	Text  string `json:"text,omitempty"`
	SHA   string `json:"sha,omitempty"`
	// Err is set when the repository could not be read at all.
	Err string `json:"err,omitempty"`
}

// Fetcher fetches files from GitHub, keyed by the caller's request keys.
// Implementations should batch requests.
type Fetcher interface {
	Fetch(ctx context.Context, reqs map[string]FileReq) (map[string]FileRes, error)
}

// File is a workflow file in a scanned repository.
type File struct {
	Path string
	Text string
}

// Root is a repository to scan.
type Root struct {
	// Name is owner/repo, or the directory for a local checkout.
	Name string
	// Owner is used to tell same-owner refs from external ones. May be empty.
	Owner string
	Files []File

	// Remote roots: the repository and commit that ./local refs resolve to.
	Repo    string
	HeadOID string
	// Local roots: reads a file relative to the checkout for ./local refs.
	ReadLocal func(path string) ([]byte, error)
}

// Finding is one unpinned reference.
type Finding struct {
	Repo string `json:"repo"`
	// File and Line locate the step in Repo where the chain starts.
	File string `json:"file"`
	Line int    `json:"line"`
	// Uses is the unpinned reference.
	Uses     string `json:"uses"`
	Kind     string `json:"kind"`
	External bool   `json:"external"`
	// Via lists the references between File and Uses, outermost first.
	Via []string `json:"via,omitempty"`
	// Source locates Uses when it is not in File itself.
	Source       string `json:"source,omitempty"`
	SuggestedSHA string `json:"suggested_sha,omitempty"`
	// Direct is the action or reusable workflow that Repo itself calls and
	// that leads to Uses. It equals Uses when Uses is not transitive.
	Direct Direct `json:"direct"`
}

// Direct is a reference written in the scanned repository: in a workflow, or
// in one of the repository's own local actions.
type Direct struct {
	Uses string `json:"uses"`
	// Comment is the trailing comment, usually the version of a pinned SHA.
	Comment string `json:"comment,omitempty"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

// IsTransitive reports whether f's unpinned reference is inside another
// action or reusable workflow rather than written in the repository.
func (f Finding) IsTransitive() bool { return f.Uses != f.Direct.Uses }

// Result is the outcome of a scan.
type Result struct {
	Findings []Finding `json:"findings"`
	Warnings []string  `json:"warnings"`
	// Incomplete holds the names of roots with a reference that could not
	// be read or was not followed because of the depth limit, so their
	// findings may be missing some.
	Incomplete map[string]bool `json:"-"`
}

// Scanner scans roots using Fetcher.
type Scanner struct {
	Fetcher Fetcher
	// Depth limits how many levels of references are followed. Direct
	// references from a workflow are depth 1.
	Depth int
	// Resolve looks up the commit SHA of each unpinned reference.
	Resolve bool
}

// node is a fetched action or reusable workflow.
type node struct {
	// repo, path and at say where the node was read. repo is empty for a
	// file read from a local checkout, where path alone locates it.
	repo, path, at string
	uses           []workflow.Use
	sha            string
}

// loc locates n for Finding.Source and Direct.File. A file in root's own
// repository at the commit being scanned is shown by its path in the
// repository, as in a local scan.
func (n *node) loc(root *Root) string {
	if n.repo == "" || (strings.EqualFold(n.repo, root.Repo) && n.at == root.HeadOID) {
		return n.path
	}
	return n.repo + "/" + n.path + "@" + n.at
}

// target is a reference resolved in the context of a root.
type target struct {
	key  string
	ref  ref.Ref
	root *Root
	// local refs are read from the root rather than fetched.
	local bool
}

type scanner struct {
	*Scanner
	nodes    map[string]*node
	missing  map[string]bool
	warnings []string
	warned   map[string]bool
}

// Scan scans roots.
func (s *Scanner) Scan(ctx context.Context, roots []Root) (Result, error) {
	sc := &scanner{Scanner: s, nodes: map[string]*node{}, missing: map[string]bool{}, warned: map[string]bool{}}

	rootUses := make([][][]workflow.Use, len(roots))
	var level []target
	for i := range roots {
		root := &roots[i]
		rootUses[i] = make([][]workflow.Use, len(root.Files))
		for j, f := range root.Files {
			uses, err := workflow.Extract([]byte(f.Text))
			if err != nil {
				sc.warn("%s: %s: %v", root.Name, f.Path, err)
				continue
			}
			rootUses[i][j] = uses
			level = append(level, sc.targets(root, uses)...)
		}
	}

	expanded := map[string]bool{}
	for depth := 1; depth <= s.Depth && len(level) > 0; depth++ {
		if err := sc.load(ctx, level); err != nil {
			return Result{}, err
		}
		if depth == s.Depth {
			break
		}
		var next []target
		for _, t := range level {
			n := sc.nodes[t.key]
			if n == nil {
				continue
			}
			// ./local refs anywhere below a node resolve against the root, so
			// each node is expanded once per root. Files are still fetched
			// only once, since load skips keys it already has.
			ek := t.key + "|" + t.root.Name
			if expanded[ek] {
				continue
			}
			expanded[ek] = true
			next = append(next, sc.targets(t.root, n.uses)...)
		}
		level = next
	}

	res := Result{Incomplete: map[string]bool{}}
	for i := range roots {
		root := &roots[i]
		for j, f := range root.Files {
			for _, u := range rootUses[i][j] {
				sc.walk(&res, root, f.Path, u, u, "", nil, 1, map[string]bool{}, nil)
			}
		}
	}
	res.Warnings = sc.warnings
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	return res, nil
}

func (sc *scanner) warn(format string, args ...any) {
	sc.warnings = append(sc.warnings, fmt.Sprintf(format, args...))
}

// warnOnce is warn for messages that the walk can reach on many paths.
func (sc *scanner) warnOnce(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !sc.warned[msg] {
		sc.warned[msg] = true
		sc.warnings = append(sc.warnings, msg)
	}
}

// targets resolves the references in uses that point at fetchable content.
func (sc *scanner) targets(root *Root, uses []workflow.Use) []target {
	var ts []target
	for _, u := range uses {
		if t, ok := resolve(root, ref.Parse(u.Value)); ok {
			ts = append(ts, t)
		}
	}
	return ts
}

func resolve(root *Root, r ref.Ref) (target, bool) {
	switch {
	case r.IsRemote():
		return target{key: r.Key(), ref: r, root: root}, true
	case r.Kind == ref.Local && root.ReadLocal != nil:
		return target{key: "local:" + root.Name + ":" + r.Path, ref: r, root: root, local: true}, true
	case r.Kind == ref.Local && root.HeadOID != "":
		owner, repo, _ := strings.Cut(root.Repo, "/")
		kind := ref.Action
		if ref.IsWorkflowPath(r.Path) {
			kind = ref.Workflow
		}
		r = ref.Ref{Raw: r.Raw, Kind: kind, Owner: owner, Repo: repo, Path: r.Path, Ref: root.HeadOID}
		return target{key: r.Key(), ref: r, root: root}, true
	}
	return target{}, false
}

// load fetches every target that is not loaded yet, remote ones in one batch.
func (sc *scanner) load(ctx context.Context, ts []target) error {
	reqs := map[string]FileReq{}
	for _, t := range ts {
		if sc.nodes[t.key] != nil || sc.missing[t.key] {
			continue
		}
		if t.local {
			sc.loadLocal(t)
			continue
		}
		reqs[t.key] = FileReq{
			Owner: t.ref.Owner, Repo: t.ref.Repo, Ref: t.ref.Ref,
			Paths:   t.ref.Candidates(),
			Resolve: sc.Resolve && !t.ref.IsPinned(),
		}
	}
	if len(reqs) == 0 {
		return nil
	}
	got, err := sc.Fetcher.Fetch(ctx, reqs)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(reqs))
	for k := range reqs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		req, res := reqs[k], got[k]
		name := req.Owner + "/" + req.Repo + "@" + req.Ref
		switch {
		case res.Err != "":
			sc.warn("%s: %s", name, res.Err)
			sc.missing[k] = true
		case !res.Found:
			sc.warn("%s: none of %s found", name, strings.Join(req.Paths, ", "))
			sc.missing[k] = true
		default:
			sc.addNode(k, &node{repo: req.Owner + "/" + req.Repo, path: res.Path, at: req.Ref, sha: res.SHA}, []byte(res.Text))
		}
	}
	return nil
}

func (sc *scanner) loadLocal(t target) {
	for _, p := range t.ref.Candidates() {
		data, err := t.root.ReadLocal(p)
		if err == nil {
			sc.addNode(t.key, &node{path: p}, data)
			return
		}
	}
	sc.warn("%s: %s: none of %s found", t.root.Name, t.ref.Raw, strings.Join(t.ref.Candidates(), ", "))
	sc.missing[t.key] = true
}

func (sc *scanner) addNode(key string, n *node, data []byte) {
	uses, err := workflow.Extract(data)
	if err != nil {
		sc.warn("%s: %v", n.loc(&Root{}), err)
	}
	n.uses = uses
	sc.nodes[key] = n
}

// walk reports u if it is unpinned and descends into what it references.
// start is the use in the root file where the chain began, src the location
// of u when it is not in the root file. direct is the first remote reference
// on the chain, or nil while the chain has only passed through local actions.
func (sc *scanner) walk(res *Result, root *Root, file string, start, u workflow.Use, src string, via []string, depth int, onPath map[string]bool, direct *Direct) {
	r := ref.Parse(u.Value)
	if r.Kind == ref.Invalid {
		sc.warn("%s: %s:%d: cannot parse uses %q", root.Name, file, start.Line, u.Value)
		return
	}
	t, ok := resolve(root, r)
	if !ok {
		return
	}
	if direct == nil && r.IsRemote() {
		loc := file
		if src != "" {
			loc = src
		}
		direct = &Direct{Uses: u.Value, Comment: u.Comment, File: loc, Line: u.Line}
	}
	if r.IsRemote() && !r.IsPinned() {
		f := Finding{
			Repo: root.Name, File: file, Line: start.Line,
			Uses: u.Value, Kind: r.Kind.String(),
			External: root.Owner == "" || !strings.EqualFold(r.Owner, root.Owner),
			Via:      via,
			Direct:   *direct,
		}
		if src != "" {
			f.Source = fmt.Sprintf("%s:%d", src, u.Line)
		}
		if n := sc.nodes[t.key]; n != nil {
			f.SuggestedSHA = n.sha
		}
		res.Findings = append(res.Findings, f)
	}
	n := sc.nodes[t.key]
	if n == nil {
		if sc.missing[t.key] {
			res.Incomplete[root.Name] = true
		}
		return
	}
	if onPath[t.key] {
		return
	}
	if depth >= sc.Depth {
		if len(sc.targets(root, n.uses)) > 0 {
			sc.warnOnce("%s: stopped at --depth %d; refs inside %s were not checked", root.Name, sc.Depth, n.loc(root))
			res.Incomplete[root.Name] = true
		}
		return
	}
	onPath[t.key] = true
	defer delete(onPath, t.key)
	via = append(via[:len(via):len(via)], label(u))
	for _, c := range n.uses {
		sc.walk(res, root, file, start, c, n.loc(root), via, depth+1, onPath, direct)
	}
}

func label(u workflow.Use) string {
	r := ref.Parse(u.Value)
	if !r.IsPinned() {
		return u.Value
	}
	s := r.Name() + "@" + r.Ref[:7]
	if u.Comment != "" {
		s += " (" + u.Comment + ")"
	}
	return s
}
