// Package fix turns findings into one suggested change per action that a
// repository calls: pin it, upgrade it, or report that no fix exists yet.
package fix

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/conspirates/gh-gha-scan/internal/ref"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// Tag is a git tag and the commit it points at.
type Tag struct {
	Name string
	SHA  string
}

// RepoRefs is what the planner needs to know about a dependency's
// repository.
type RepoRefs struct {
	// Tags are the most recent tags.
	Tags []Tag
	// Default is the default branch, by name, and its head commit.
	Default Tag
}

// RefLister looks up the refs of repositories (owner/repo), keyed by
// lowercase owner/repo. Repositories that cannot be read have no entry.
// Implementations should batch requests.
type RefLister interface {
	Refs(ctx context.Context, repos []string) (map[string]RepoRefs, error)
}

// Kind classifies a suggested fix.
type Kind string

const (
	// Pin: pin the reference to the commit its current version points at.
	Pin Kind = "pin"
	// Upgrade: move to a release whose own references are all pinned.
	Upgrade Kind = "upgrade"
	// PinUpstream: the dependency belongs to the same owner, so fix the
	// references inside it: pin those in the owner's files, and upgrade the
	// third-party actions those files call when the problem is inside them.
	PinUpstream Kind = "pin-upstream"
	// None: no release of the dependency is fully pinned yet.
	None Kind = "none"
)

// Item is one action a repository calls that has to change.
type Item struct {
	// Action is the reference as written in the repository.
	Action string `json:"action"`
	// File and Line locate Action in the repository.
	File string `json:"file"`
	Line int    `json:"line"`
	// Fix is a one-line suggestion; FixKind and Replacement are its parts.
	Fix         string `json:"fix"`
	FixKind     Kind   `json:"fix_kind"`
	Replacement string `json:"replacement,omitempty"`
	// Findings are the unpinned references behind this item.
	Findings []scan.Finding `json:"findings"`
}

// Repo is the outcome for one scanned repository. Items is empty when
// nothing needs to change.
type Repo struct {
	Repository string `json:"repository"`
	Items      []Item `json:"items"`
	// Incomplete means some references could not be read or were beyond
	// the depth limit, so Items may be missing some; see the warnings.
	Incomplete bool `json:"incomplete"`
}

// Planner computes fixes.
type Planner struct {
	// Scanner checks candidate upgrades, with the same depth as the scan.
	Scanner *scan.Scanner
	Refs    RefLister
	// Warnings collects problems found while checking candidate upgrades.
	Warnings []string
}

type group struct {
	direct   scan.Direct
	ref      ref.Ref
	findings []scan.Finding
}

// Plan groups res by repository and the action each repository calls, and
// suggests a fix for each. repos lists every scanned repository, in order.
func (p *Planner) Plan(ctx context.Context, repos []scan.Root, res scan.Result) ([]Repo, error) {
	byRepo := map[string][]*group{}
	index := map[string]*group{}
	for _, f := range res.Findings {
		k := f.Repo + "\x00" + f.Direct.Uses
		g := index[k]
		if g == nil {
			g = &group{direct: f.Direct, ref: ref.Parse(f.Direct.Uses)}
			index[k] = g
			byRepo[f.Repo] = append(byRepo[f.Repo], g)
		}
		g.findings = append(g.findings, f)
	}

	st, err := p.check(ctx, repos, index)
	if err != nil {
		return nil, err
	}

	out := make([]Repo, 0, len(repos))
	for _, root := range repos {
		r := Repo{Repository: root.Name, Items: []Item{}, Incomplete: res.Incomplete[root.Name]}
		for _, g := range byRepo[root.Name] {
			it := Item{
				Action:   display(g.direct),
				File:     g.direct.File,
				Line:     g.direct.Line,
				Findings: g.findings,
			}
			describe(&it, root, g, st)
			r.Items = append(r.Items, it)
		}
		sort.SliceStable(r.Items, func(i, j int) bool { return r.Items[i].Action < r.Items[j].Action })
		out = append(out, r)
	}
	return out, nil
}

// display shows a pinned SHA shortened, with its version comment, and names
// the local action a reference is written in.
func display(d scan.Direct) string {
	s := short(d)
	if !strings.HasPrefix(d.File, ".github/workflows/") {
		s += " (in " + d.File + ")"
	}
	return s
}

// short shows a pinned SHA shortened, with its version comment.
func short(d scan.Direct) string {
	r := ref.Parse(d.Uses)
	if !r.IsPinned() {
		return d.Uses
	}
	s := r.Name() + "@" + r.Ref[:7]
	if d.Comment != "" {
		s += " (" + d.Comment + ")"
	}
	return s
}

func transitive(fs []scan.Finding) []scan.Finding {
	var out []scan.Finding
	for _, f := range fs {
		if f.IsTransitive() {
			out = append(out, f)
		}
	}
	return out
}

// candidate is the outcome of checking one version of a dependency: its
// latest release, or its default branch head.
type candidate struct {
	tag   Tag
	clean bool
	// blocker is an unpinned reference that remains in this version.
	blocker string
	// unverified means part of this version could not be read, so it is not
	// known to be clean.
	unverified bool
	// findings are the unpinned references inside this version.
	findings []scan.Finding
}

func upgradeKey(r ref.Ref) string { return strings.ToLower(r.Owner + "/" + r.Repo + "/" + r.Path) }

func repoKey(r ref.Ref) string { return strings.ToLower(r.Owner + "/" + r.Repo) }

func versionKey(r ref.Ref, sha string) string { return upgradeKey(r) + "@" + sha }

// state is what the planner learned about dependencies.
type state struct {
	refs map[string]RepoRefs   // by repoKey
	done map[string]*candidate // by versionKey
}

// release returns the check of r's latest release, or nil.
func (st *state) release(r ref.Ref) *candidate {
	t, ok := Latest(st.refs[repoKey(r)].Tags)
	if !ok {
		return nil
	}
	return st.done[versionKey(r, t.SHA)]
}

// head returns the check of r's default branch head, or nil.
func (st *state) head(r ref.Ref) *candidate {
	d := st.refs[repoKey(r)].Default
	if d.SHA == "" {
		return nil
	}
	return st.done[versionKey(r, d.SHA)]
}

// upstream returns the unpinned references inside g's same-owner dependency
// where they have to be fixed: on its default branch when that could be
// read, otherwise at the commit in use.
func (st *state) upstream(g *group) (fs []scan.Finding, onDefault bool) {
	if h := st.head(g.ref); h != nil && !h.unverified {
		return h.findings, true
	}
	return transitive(g.findings), false
}

// wanted asks for a version of a dependency to be checked.
type wanted struct {
	ref ref.Ref
	// head asks for the default branch head instead of the latest release.
	head bool
	// owner is the scanned repository's owner, so that findings inside a
	// same-owner dependency know which files that owner controls.
	owner string
}

// check checks the versions of dependencies that fixes may suggest: the
// latest release of each dependency with unpinned references inside it,
// and for a same-owner dependency also its default branch head. A
// same-owner dependency that is fixed in neither is fixed on its default
// branch, so the third-party actions it calls there are checked next.
func (p *Planner) check(ctx context.Context, roots []scan.Root, index map[string]*group) (*state, error) {
	st := &state{refs: map[string]RepoRefs{}, done: map[string]*candidate{}}
	owners := map[string]string{}
	for _, r := range roots {
		owners[r.Name] = r.Owner
	}
	ownerOf := func(k string) string { return owners[k[:strings.IndexByte(k, 0)]] }

	var ws []wanted
	for k, g := range index {
		if len(transitive(g.findings)) == 0 {
			continue
		}
		owner := ownerOf(k)
		ws = append(ws, wanted{ref: g.ref, owner: owner})
		if sameOwner(owner, g.ref) {
			ws = append(ws, wanted{ref: g.ref, head: true, owner: owner})
		}
	}
	if err := p.verify(ctx, st, ws); err != nil {
		return nil, err
	}

	ws = nil
	for k, g := range index {
		owner := ownerOf(k)
		if len(transitive(g.findings)) == 0 || !sameOwner(owner, g.ref) {
			continue
		}
		if c := st.release(g.ref); c != nil && c.clean {
			continue
		}
		if h := st.head(g.ref); h != nil && h.clean {
			continue
		}
		fs, _ := st.upstream(g)
		for _, f := range fs {
			if f.SourceExternal {
				ws = append(ws, wanted{ref: ref.Parse(f.Boundary.Uses), owner: owner})
			}
		}
	}
	if err := p.verify(ctx, st, ws); err != nil {
		return nil, err
	}
	return st, nil
}

// verify looks up the refs of repositories not seen yet, then scans every
// wanted version not checked yet, all in one scan.
func (p *Planner) verify(ctx context.Context, st *state, ws []wanted) error {
	var repos []string
	for _, w := range ws {
		k := repoKey(w.ref)
		if _, ok := st.refs[k]; !ok && !slices.Contains(repos, k) {
			repos = append(repos, k)
		}
	}
	if len(repos) > 0 {
		sort.Strings(repos)
		got, err := p.Refs.Refs(ctx, repos)
		if err != nil {
			return err
		}
		for _, k := range repos {
			st.refs[k] = got[k]
		}
	}

	cands := map[string]*candidate{}
	var probes []scan.Root
	for _, w := range ws {
		rr := st.refs[repoKey(w.ref)]
		t := rr.Default
		if !w.head {
			t, _ = Latest(rr.Tags)
		}
		if t.SHA == "" {
			continue
		}
		k := versionKey(w.ref, t.SHA)
		if st.done[k] != nil || cands[k] != nil {
			continue
		}
		cands[k] = &candidate{tag: t}
		pinned := ref.Ref{Kind: w.ref.Kind, Owner: w.ref.Owner, Repo: w.ref.Repo, Path: w.ref.Path, Ref: t.SHA}
		probes = append(probes, scan.Root{Name: k, Owner: w.owner, Files: []scan.File{probe(pinned)}})
	}
	if len(probes) == 0 {
		return nil
	}
	sort.Slice(probes, func(i, j int) bool { return probes[i].Name < probes[j].Name })

	s := *p.Scanner
	s.Resolve = false
	res, err := s.Scan(ctx, probes)
	if err != nil {
		return err
	}
	for k, c := range cands {
		c.unverified = res.Incomplete[k]
		c.clean = !c.unverified
		st.done[k] = c
	}
	for _, w := range res.Warnings {
		p.Warnings = append(p.Warnings, "checking upgrades: "+w)
	}
	for _, f := range res.Findings {
		if c := cands[f.Repo]; c != nil {
			c.clean = false
			c.findings = append(c.findings, f)
			if c.blocker == "" {
				c.blocker = f.Uses
			}
		}
	}
	return nil
}

// probe is a workflow that calls r, used to scan a candidate release.
func probe(r ref.Ref) scan.File {
	uses := r.Name() + "@" + r.Ref
	text := "jobs:\n  probe:\n    steps:\n      - uses: " + uses + "\n"
	if r.Kind == ref.Workflow {
		text = "jobs:\n  probe:\n    uses: " + uses + "\n"
	}
	return scan.File{Path: "probe.yml", Text: text}
}

func sameOwner(owner string, r ref.Ref) bool {
	return owner != "" && strings.EqualFold(owner, r.Owner)
}

func describe(it *Item, root scan.Root, g *group, st *state) {
	nested := transitive(g.findings)
	c := st.release(g.ref)
	switch {
	case len(nested) == 0:
		it.FixKind = Pin
		sha := g.findings[0].SuggestedSHA
		if sha == "" {
			it.Fix = fmt.Sprintf("Pin to a full commit SHA (could not resolve %s)", g.ref.Ref)
			return
		}
		it.Replacement = fmt.Sprintf("%s@%s # %s", g.ref.Name(), sha, g.ref.Ref)
		it.Fix = "Pin to " + it.Replacement

	case c != nil && c.clean:
		it.FixKind = Upgrade
		it.Replacement = fmt.Sprintf("%s@%s # %s", g.ref.Name(), c.tag.SHA, c.tag.Name)
		it.Fix = "Upgrade to " + it.Replacement
		if cur := current(g); cur != "" && major(cur) >= 0 && major(c.tag.Name) >= 0 && major(cur) != major(c.tag.Name) {
			it.Fix += fmt.Sprintf(" (major version change from %s)", cur)
		}

	case sameOwner(root.Owner, g.ref):
		describeUpstream(it, g, st)

	default:
		it.FixKind = None
		it.Fix = noFix(g.ref, c, nested[0].Uses)
	}
}

// describeUpstream suggests fixes inside a same-owner dependency whose latest
// release is not fully pinned. If its default branch is, that only needs a
// release. Otherwise each nested reference is fixed on the default branch: in
// a file the owner controls it is pinned there, and one in a third-party
// file can only be fixed through the reference to that third party: upgrade
// it, or there is no fix yet.
func describeUpstream(it *Item, g *group, st *state) {
	it.FixKind = PinUpstream
	d := st.refs[repoKey(g.ref)].Default
	if h := st.head(g.ref); h != nil && h.clean {
		latest := "it has no releases yet"
		if c := st.release(g.ref); c != nil {
			latest = "latest release " + c.tag.Name + " isn't"
		}
		it.Fix = fmt.Sprintf("Release %s from %s at %s, which is fully pinned (%s), then upgrade to it", g.ref.Name(), d.Name, d.SHA[:7], latest)
		return
	}

	nested, onDefault := st.upstream(g)
	// loc shows a file at the default branch head by its branch, since that
	// is where the edit goes.
	loc := func(file string, line int) string {
		if f, ok := strings.CutSuffix(file, "@"+d.SHA); ok && onDefault {
			return fmt.Sprintf("%s:%d on %s", f, line, d.Name)
		}
		return fmt.Sprintf("%s:%d", file, line)
	}
	var steps []string
	seen := map[string]bool{}
	for _, f := range nested {
		var s string
		if !f.SourceExternal {
			i := strings.LastIndexByte(f.Source, ':')
			line, _ := strconv.Atoi(f.Source[i+1:])
			s = "Pin " + f.Uses + " in " + loc(f.Source[:i], line)
		} else {
			b := ref.Parse(f.Boundary.Uses)
			at := short(f.Boundary) + " in " + loc(f.Boundary.File, f.Boundary.Line)
			if c := st.release(b); c != nil && c.clean {
				s = fmt.Sprintf("Upgrade %s to %s@%s # %s", at, b.Name(), c.tag.SHA, c.tag.Name)
			} else {
				it.FixKind = None
				s = at + ": " + noFix(b, c, f.Uses)
			}
		}
		if !seen[s] {
			seen[s] = true
			steps = append(steps, s)
		}
	}
	it.Fix = strings.Join(steps, "; ")
	if it.FixKind == PinUpstream {
		it.Fix += ", then update this reference"
	}
}

// noFix explains why r has no fix: c is its newest release, or nil when it
// has none, and uses is an unpinned reference inside it.
func noFix(r ref.Ref, c *candidate, uses string) string {
	switch {
	case c != nil && c.blocker == "" && c.unverified:
		return fmt.Sprintf("No verified fix: could not read all of latest release %s to check it (see warnings)", c.tag.Name)
	case c == nil:
		return fmt.Sprintf("No fix upstream yet: %s has no releases and uses %s unpinned; fork it or ask upstream to pin", r.Name(), uses)
	}
	return fmt.Sprintf("No fix upstream yet: latest release %s still uses %s; fork it or ask upstream to pin", c.tag.Name, c.blocker)
}

// current returns the version in use: the ref itself, or the comment next to
// a pinned SHA.
func current(g *group) string {
	if !g.ref.IsPinned() {
		return g.ref.Ref
	}
	return g.direct.Comment
}

type version struct {
	parts []int
	name  string
}

// parseVersion parses tags like v1, v1.2 and v1.2.3. Pre-releases and other
// names are rejected.
func parseVersion(name string) (version, bool) {
	s := strings.TrimPrefix(name, "v")
	fields := strings.Split(s, ".")
	if len(fields) == 0 || len(fields) > 3 {
		return version{}, false
	}
	v := version{name: name}
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			return version{}, false
		}
		v.parts = append(v.parts, n)
	}
	return v, true
}

func major(name string) int {
	if v, ok := parseVersion(name); ok {
		return v.parts[0]
	}
	return -1
}

// less orders by version, then prefers the more specific tag (v2.1.0 over
// v2), since moving major tags change over time.
func (a version) less(b version) bool {
	for i := 0; i < max(len(a.parts), len(b.parts)); i++ {
		var x, y int
		if i < len(a.parts) {
			x = a.parts[i]
		}
		if i < len(b.parts) {
			y = b.parts[i]
		}
		if x != y {
			return x < y
		}
	}
	return len(a.parts) < len(b.parts)
}

// Latest returns the highest version tag. Tags that are not versions are
// ignored; with no version tags at all, there is no candidate.
func Latest(tags []Tag) (Tag, bool) {
	var best version
	var bestTag Tag
	found := false
	for _, t := range tags {
		v, ok := parseVersion(t.Name)
		if !ok || t.SHA == "" {
			continue
		}
		if !found || best.less(v) {
			best, bestTag, found = v, t, true
		}
	}
	return bestTag, found
}
