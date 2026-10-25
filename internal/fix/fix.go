// Package fix turns findings into one suggested change per action that a
// repository calls: pin it, upgrade it, or report that no fix exists yet.
package fix

import (
	"context"
	"fmt"
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

// TagLister lists the tags of repositories, keyed by lowercase owner/repo.
// Implementations should batch requests.
type TagLister interface {
	Tags(ctx context.Context, repos []string) (map[string][]Tag, error)
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
	Tags    TagLister
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

	upgrades, err := p.upgrades(ctx, repos, index)
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
			describe(&it, root, g, upgrades)
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

// candidate is the outcome of checking a dependency's newest release.
type candidate struct {
	tag   Tag
	clean bool
	// blocker is an unpinned reference that remains in the newest release.
	blocker string
	// unverified means part of the release could not be read, so it is not
	// known to be clean.
	unverified bool
}

func upgradeKey(r ref.Ref) string { return strings.ToLower(r.Owner + "/" + r.Repo + "/" + r.Path) }

// upgrades checks the newest release of each external dependency that has
// unpinned references inside it: one a repository calls directly, or one
// called from a file in a same-owner dependency. Tags are listed in one
// batch, and all candidates are scanned together.
func (p *Planner) upgrades(ctx context.Context, roots []scan.Root, index map[string]*group) (map[string]*candidate, error) {
	owners := map[string]string{}
	for _, r := range roots {
		owners[r.Name] = r.Owner
	}
	need := map[string]ref.Ref{}
	repoSet := map[string]bool{}
	for k, g := range index {
		owner := owners[k[:strings.IndexByte(k, 0)]]
		for _, f := range transitive(g.findings) {
			r := g.ref
			if sameOwner(owner, g.ref) {
				if !f.SourceExternal {
					continue
				}
				r = ref.Parse(f.Boundary.Uses)
			}
			need[upgradeKey(r)] = r
			repoSet[strings.ToLower(r.Owner+"/"+r.Repo)] = true
		}
	}
	if len(need) == 0 {
		return nil, nil
	}

	repos := make([]string, 0, len(repoSet))
	for r := range repoSet {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	tags, err := p.Tags.Tags(ctx, repos)
	if err != nil {
		return nil, err
	}

	out := map[string]*candidate{}
	var cands []scan.Root
	for k, r := range need {
		t, ok := Latest(tags[strings.ToLower(r.Owner+"/"+r.Repo)])
		if !ok {
			continue
		}
		c := &candidate{tag: t}
		out[k] = c
		pinned := ref.Ref{Kind: r.Kind, Owner: r.Owner, Repo: r.Repo, Path: r.Path, Ref: t.SHA}
		cands = append(cands, scan.Root{Name: k, Files: []scan.File{probe(pinned)}})
	}
	if len(cands) == 0 {
		return out, nil
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Name < cands[j].Name })

	s := *p.Scanner
	s.Resolve = false
	res, err := s.Scan(ctx, cands)
	if err != nil {
		return nil, err
	}
	for k, c := range out {
		c.clean = !res.Incomplete[k]
		c.unverified = res.Incomplete[k]
	}
	for _, w := range res.Warnings {
		p.Warnings = append(p.Warnings, "checking upgrades: "+w)
	}
	for _, f := range res.Findings {
		if c := out[f.Repo]; c != nil && c.blocker == "" {
			c.clean = false
			c.blocker = f.Uses
		}
	}
	return out, nil
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

func describe(it *Item, root scan.Root, g *group, upgrades map[string]*candidate) {
	nested := transitive(g.findings)
	c := upgrades[upgradeKey(g.ref)]
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

	case sameOwner(root.Owner, g.ref):
		describeUpstream(it, nested, upgrades)

	case c != nil && c.clean:
		it.FixKind = Upgrade
		it.Replacement = fmt.Sprintf("%s@%s # %s", g.ref.Name(), c.tag.SHA, c.tag.Name)
		it.Fix = "Upgrade to " + it.Replacement
		if cur := current(g); cur != "" && major(cur) >= 0 && major(c.tag.Name) >= 0 && major(cur) != major(c.tag.Name) {
			it.Fix += fmt.Sprintf(" (major version change from %s)", cur)
		}

	default:
		it.FixKind = None
		it.Fix = noFix(g.ref, c, nested[0].Uses)
	}
}

// describeUpstream suggests fixes inside a same-owner dependency. A nested
// reference in a file the owner controls is pinned there. One in a
// third-party file can only be fixed through the reference to that third
// party in the owner's file: upgrade it, or there is no fix yet.
func describeUpstream(it *Item, nested []scan.Finding, upgrades map[string]*candidate) {
	it.FixKind = PinUpstream
	var steps []string
	seen := map[string]bool{}
	for _, f := range nested {
		var s string
		if !f.SourceExternal {
			s = "Pin " + f.Uses + " in " + f.Source
		} else {
			b := ref.Parse(f.Boundary.Uses)
			at := fmt.Sprintf("%s in %s:%d", short(f.Boundary), f.Boundary.File, f.Boundary.Line)
			if c := upgrades[upgradeKey(b)]; c != nil && c.clean {
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
