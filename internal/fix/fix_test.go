package fix

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/conspirates/gh-gha-scan/internal/ref"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

var (
	shaV1 = strings.Repeat("1", 40)
	shaV2 = strings.Repeat("2", 40)
)

// fakeFetcher serves composite actions whose steps use the given refs.
type fakeFetcher map[string][]string

func (f fakeFetcher) Fetch(_ context.Context, reqs map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	out := map[string]scan.FileRes{}
	for k, req := range reqs {
		uses, ok := f[k]
		if !ok {
			out[k] = scan.FileRes{}
			continue
		}
		text := "runs:\n  using: composite\n  steps:\n"
		for _, u := range uses {
			text += "    - uses: " + u + "\n"
		}
		res := scan.FileRes{Found: true, Path: req.Paths[0], Text: text}
		if req.Resolve {
			res.SHA = "sha-of-" + req.Ref
		}
		out[k] = res
	}
	return out, nil
}

// fakeTags serves tags only, with no default branch.
type fakeTags map[string][]Tag

func (f fakeTags) Refs(_ context.Context, repos map[string][]string) (map[string]RepoRefs, error) {
	out := map[string]RepoRefs{}
	for r := range repos {
		if ts, ok := f[r]; ok {
			out[r] = RepoRefs{Tags: ts}
		}
	}
	return out, nil
}

// fakeRefs serves tags, default branches, and the branches asked for.
type fakeRefs map[string]RepoRefs

func (f fakeRefs) Refs(_ context.Context, repos map[string][]string) (map[string]RepoRefs, error) {
	out := map[string]RepoRefs{}
	for r, names := range repos {
		rr, ok := f[r]
		if !ok {
			continue
		}
		branches := rr.Branches
		rr.Branches = nil
		for _, n := range names {
			if sha, ok := branches[n]; ok {
				if rr.Branches == nil {
					rr.Branches = map[string]string{}
				}
				rr.Branches[n] = sha
			}
		}
		out[r] = rr
	}
	return out, nil
}

func workflow(uses ...string) scan.File {
	text := "jobs:\n  build:\n    steps:\n"
	for _, u := range uses {
		text += "      - uses: " + u + "\n"
	}
	return scan.File{Path: ".github/workflows/ci.yml", Text: text}
}

func plan(t *testing.T, f fakeFetcher, refs RefLister, roots ...scan.Root) []Repo {
	t.Helper()
	if refs == nil {
		refs = fakeTags{}
	}
	s := &scan.Scanner{Fetcher: f, Depth: 10, Resolve: true}
	res, err := s.Scan(context.Background(), roots)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&Planner{Scanner: s, Refs: refs}).Plan(context.Background(), roots, res)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func only(t *testing.T, repos []Repo) Item {
	t.Helper()
	if len(repos) != 1 || len(repos[0].Items) != 1 {
		t.Fatalf("want exactly one item, got %+v", repos)
	}
	return repos[0].Items[0]
}

func TestPinDirectRef(t *testing.T) {
	f := fakeFetcher{"actions/checkout/@v5": {}}
	it := only(t, plan(t, f, nil, scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("actions/checkout@v5")}}))
	if it.FixKind != Pin || it.Replacement != "actions/checkout@sha-of-v5 # v5" {
		t.Errorf("got %+v", it)
	}
	if it.Action != "actions/checkout@v5" || it.File != ".github/workflows/ci.yml" || it.Line != 4 {
		t.Errorf("location = %s %s:%d", it.Action, it.File, it.Line)
	}
}

func TestUpgradeToCleanRelease(t *testing.T) {
	f := fakeFetcher{
		"up/action/@" + shaV1:        {"actions/setup-go@v5", "actions/cache@v4"},
		"up/action/@" + shaV2:        {"actions/setup-go@" + shaV2},
		"actions/setup-go/@" + shaV2: {},
	}
	tags := fakeTags{"up/action": {{"v2", shaV2}, {"v2.1.0", shaV2}, {"v1.0.0", shaV1}, {"latest", shaV2}}}
	root := scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("up/action@" + shaV1 + " # v1.0.0")}}
	it := only(t, plan(t, f, tags, root))
	if it.FixKind != Upgrade {
		t.Fatalf("got %+v", it)
	}
	if it.Replacement != "up/action@"+shaV2+" # v2.1.0" {
		t.Errorf("Replacement = %q", it.Replacement)
	}
	if !strings.Contains(it.Fix, "major version change from v1.0.0") {
		t.Errorf("Fix = %q, want a major version warning", it.Fix)
	}
	if it.Action != "up/action@1111111 (v1.0.0)" || len(it.Findings) != 2 {
		t.Errorf("Action = %q, %d findings; want one row for both nested refs", it.Action, len(it.Findings))
	}
}

func TestNoCleanRelease(t *testing.T) {
	f := fakeFetcher{
		"up/action/@v1":       {"actions/setup-go@v5"},
		"up/action/@" + shaV2: {"actions/setup-go@v6"},
	}
	tags := fakeTags{"up/action": {{"v1.0.0", shaV1}, {"v1.1.0", shaV2}}}
	it := only(t, plan(t, f, tags, scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("up/action@v1")}}))
	if it.FixKind != None || it.Reason != NoUpstreamFix || !strings.Contains(it.Fix, "v1.1.0 still uses actions/setup-go@v6") {
		t.Errorf("got %+v", it)
	}
}

func TestNoReleasesAtAll(t *testing.T) {
	f := fakeFetcher{"up/action/@main": {"actions/setup-go@v5"}}
	it := only(t, plan(t, f, fakeTags{}, scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("up/action@main")}}))
	if it.FixKind != None || !strings.Contains(it.Fix, "has no releases") {
		t.Errorf("got %+v", it)
	}
}

func TestSameOwnerDependencyIsPinnedUpstream(t *testing.T) {
	f := fakeFetcher{"me/shared/@" + shaV1: {"actions/setup-go@v5"}}
	it := only(t, plan(t, f, nil, scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("me/shared@" + shaV1)}}))
	if it.FixKind != PinUpstream || !strings.Contains(it.Fix, "actions/setup-go@v5 in me/shared/action.yml@"+shaV1+":4") {
		t.Errorf("got %+v", it)
	}
}

func TestCleanRepoHasNoItems(t *testing.T) {
	f := fakeFetcher{"actions/checkout/@" + shaV1: {}}
	repos := plan(t, f, nil,
		scan.Root{Name: "me/clean", Files: []scan.File{workflow("actions/checkout@" + shaV1)}},
		scan.Root{Name: "me/empty"},
	)
	if len(repos) != 2 || len(repos[0].Items) != 0 || len(repos[1].Items) != 0 {
		t.Errorf("got %+v", repos)
	}
}

func TestLocalActionRefsAreDirect(t *testing.T) {
	f := fakeFetcher{"ext/x/@v1": {}}
	read := func(p string) ([]byte, error) {
		if p == ".github/actions/a/action.yml" {
			return []byte("runs:\n  using: composite\n  steps:\n    - uses: ext/x@v1\n"), nil
		}
		return nil, errors.New("not found")
	}
	it := only(t, plan(t, f, nil, scan.Root{Name: "me/app", ReadLocal: read, Files: []scan.File{workflow("./.github/actions/a")}}))
	if it.FixKind != Pin || it.Action != "ext/x@v1 (in .github/actions/a/action.yml)" || it.Line != 4 {
		t.Errorf("got %+v", it)
	}
}

func TestLatest(t *testing.T) {
	got, ok := Latest([]Tag{{"v9.0.0", "a"}, {"v10.0.0", "b"}, {"v10", "c"}, {"v11.0.0-rc1", "d"}, {"nightly", "e"}})
	if !ok || got.Name != "v10.0.0" {
		t.Errorf("Latest = %+v, %v; want v10.0.0", got, ok)
	}
	if _, ok := Latest([]Tag{{"nightly", "a"}}); ok {
		t.Error("tags without versions should give no candidate")
	}
}

func TestUnreadableReleaseIsNotSuggested(t *testing.T) {
	tags := fakeTags{"up/action": {{"v2.0.0", shaV2}}}
	root := scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("up/action@v1")}}
	tests := map[string]fakeFetcher{
		// v2.0.0 uses a dependency that can't be read.
		"missing dependency": {
			"up/action/@v1":       {"actions/setup-go@v5"},
			"up/action/@" + shaV2: {"gone/action@" + shaV1},
		},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			s := &scan.Scanner{Fetcher: f, Depth: 10, Resolve: true}
			res, err := s.Scan(context.Background(), []scan.Root{root})
			if err != nil {
				t.Fatal(err)
			}
			p := &Planner{Scanner: s, Refs: tags}
			repos, err := p.Plan(context.Background(), []scan.Root{root}, res)
			if err != nil {
				t.Fatal(err)
			}
			it := only(t, repos)
			if it.FixKind != None || it.Reason != Unverified || !strings.Contains(it.Fix, "could not read all of latest release v2.0.0") {
				t.Errorf("got %+v", it)
			}
			if len(p.Warnings) == 0 || !strings.HasPrefix(p.Warnings[0], "checking upgrades: ") {
				t.Errorf("warnings = %v, want the candidate's read failure", p.Warnings)
			}
		})
	}
}

func TestThirdPartyInsideSameOwnerDependencyIsUpgradedThere(t *testing.T) {
	// me/shared calls ext/tp v1, which uses z/z unpinned; ext/tp v2 is clean.
	// The fix is in me/shared's file, not in ext/tp's.
	f := fakeFetcher{
		"me/shared/@" + shaV1: {"ext/tp@" + shaV1},
		"ext/tp/@" + shaV1:    {"z/z@v1"},
		"ext/tp/@" + shaV2:    {},
		"z/z/@v1":             {},
	}
	tags := fakeTags{"ext/tp": {{Name: "v2.0.0", SHA: shaV2}}}
	it := only(t, plan(t, f, tags, scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("me/shared@" + shaV1)}}))
	want := "Upgrade ext/tp@1111111 in me/shared/action.yml@" + shaV1 + ":4 to ext/tp@" + shaV2 + " # v2.0.0, then update this reference"
	if it.FixKind != PinUpstream || it.Fix != want {
		t.Errorf("got %s: %q\nwant %q", it.FixKind, it.Fix, want)
	}
}

func TestThirdPartyInsideSameOwnerDependencyWithNoFix(t *testing.T) {
	f := fakeFetcher{
		"me/shared/@" + shaV1: {"ext/tp@" + shaV1, "actions/setup-go@v5"},
		"ext/tp/@" + shaV1:    {"z/z@v1"},
		"z/z/@v1":             {},
	}
	it := only(t, plan(t, f, nil, scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("me/shared@" + shaV1)}}))
	if it.FixKind != None {
		t.Errorf("FixKind = %s, want none", it.FixKind)
	}
	for _, want := range []string{
		"Pin actions/setup-go@v5 in me/shared/action.yml@" + shaV1 + ":5",
		"ext/tp@1111111 in me/shared/action.yml@" + shaV1 + ":4: No fix upstream yet: ext/tp has no releases and uses z/z@v1 unpinned",
	} {
		if !strings.Contains(it.Fix, want) {
			t.Errorf("Fix = %q\nmissing %q", it.Fix, want)
		}
	}
	if strings.Contains(it.Fix, "in ext/tp/") {
		t.Errorf("Fix = %q suggests editing a third-party file", it.Fix)
	}
}

var shaV3 = strings.Repeat("3", 40)

func sameOwnerApp(uses string) scan.Root {
	return scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow(uses)}}
}

func TestSameOwnerDependencyIsUpgradedWhenReleaseIsPinned(t *testing.T) {
	// From issue #3: v1 uses x/x unpinned, and the latest release fixed it.
	f := fakeFetcher{
		"me/shared/@" + shaV1: {"x/x@v1"},
		"me/shared/@" + shaV2: {},
		"x/x/@v1":             {},
	}
	refs := fakeRefs{"me/shared": {Tags: []Tag{{"v2.0.0", shaV2}}, Default: Tag{"main", shaV3}}}
	it := only(t, plan(t, f, refs, sameOwnerApp("me/shared@"+shaV1+" # v1")))
	want := "Upgrade to me/shared@" + shaV2 + " # v2.0.0 (major version change from v1)"
	if it.FixKind != Upgrade || it.Fix != want {
		t.Errorf("got %s: %q\nwant %q", it.FixKind, it.Fix, want)
	}
}

func TestSameOwnerDependencyFixedOnlyOnDefaultBranchIsReleased(t *testing.T) {
	f := fakeFetcher{
		"me/shared/@" + shaV1: {"x/x@v1"},
		"me/shared/@" + shaV2: {"x/x@v1"},
		"me/shared/@" + shaV3: {},
		"x/x/@v1":             {},
	}
	refs := fakeRefs{"me/shared": {Tags: []Tag{{"v2.0.0", shaV2}}, Default: Tag{"main", shaV3}}}
	it := only(t, plan(t, f, refs, sameOwnerApp("me/shared@"+shaV1)))
	want := "Release me/shared from main at 3333333, which is fully pinned (latest release v2.0.0 isn't), then upgrade to it"
	if it.FixKind != PinUpstream || it.Fix != want {
		t.Errorf("got %s: %q\nwant %q", it.FixKind, it.Fix, want)
	}
}

func TestSameOwnerDependencyIsPinnedOnDefaultBranch(t *testing.T) {
	// The default branch moved x/x down a line and added a third-party
	// action, ext/tp, that has a clean release.
	f := fakeFetcher{
		"me/shared/@" + shaV1: {"x/x@v1"},
		"me/shared/@" + shaV3: {"y/y@" + shaV1, "x/x@v1", "ext/tp@" + shaV1},
		"y/y/@" + shaV1:       {},
		"x/x/@v1":             {},
		"ext/tp/@" + shaV1:    {"z/z@v1"},
		"ext/tp/@" + shaV2:    {},
		"z/z/@v1":             {},
	}
	refs := fakeRefs{
		"me/shared": {Default: Tag{"main", shaV3}},
		"ext/tp":    {Tags: []Tag{{"v2.0.0", shaV2}}},
	}
	it := only(t, plan(t, f, refs, sameOwnerApp("me/shared@"+shaV1)))
	want := "Pin x/x@v1 in me/shared/action.yml:5 on main; " +
		"Upgrade ext/tp@1111111 in me/shared/action.yml:6 on main to ext/tp@" + shaV2 + " # v2.0.0, then update this reference"
	if it.FixKind != PinUpstream || it.Fix != want {
		t.Errorf("got %s: %q\nwant %q", it.FixKind, it.Fix, want)
	}
}

func TestPathRemovedInLatestRelease(t *testing.T) {
	// v2.0.0 has no action.yml at that path any more.
	f := fakeFetcher{"up/action/@v1": {"actions/setup-go@v5"}}
	tags := fakeTags{"up/action": {{"v2.0.0", shaV2}}}
	root := scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("up/action@v1")}}
	s := &scan.Scanner{Fetcher: f, Depth: 10, Resolve: true}
	res, err := s.Scan(context.Background(), []scan.Root{root})
	if err != nil {
		t.Fatal(err)
	}
	p := &Planner{Scanner: s, Refs: tags}
	repos, err := p.Plan(context.Background(), []scan.Root{root}, res)
	if err != nil {
		t.Fatal(err)
	}
	it := only(t, repos)
	want := "up/action no longer exists in v2.0.0; migrate to its replacement"
	if it.FixKind != None || it.Reason != Removed || it.Fix != want {
		t.Errorf("got %s/%s: %q, want none/removed: %q", it.FixKind, it.Reason, it.Fix, want)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("warnings = %v, want none: the removal is the fix", p.Warnings)
	}
}

func TestBranchRefs(t *testing.T) {
	const app = "me/app"
	tests := []struct {
		name  string
		uses  string
		fetch fakeFetcher
		want  string
		kind  Kind
	}{{
		name:  "1: unpinned branch with nothing unpinned underneath stays pinned to it",
		uses:  "up/action@main",
		fetch: fakeFetcher{"up/action/@main": {}},
		want:  "Pin to up/action@sha-of-main # main (on branch main; consider a release tag such as v2.0.0)",
		kind:  Pin,
	}, {
		name: "2: branch head is now fully pinned",
		uses: "up/action@" + shaV1 + " # main",
		fetch: fakeFetcher{
			"up/action/@" + shaV1: {"x/x@v1"},
			"up/action/@" + shaV2: {},
			"up/action/@" + shaV3: {},
			"x/x/@v1":             {},
		},
		want: "Update to up/action@" + shaV3 + " # main (consider a release tag such as v2.0.0)",
		kind: Upgrade,
	}, {
		name: "3: stale branch, latest release is fully pinned",
		uses: "up/action@" + shaV1 + " # main",
		fetch: fakeFetcher{
			"up/action/@" + shaV1: {"x/x@v1"},
			"up/action/@" + shaV2: {},
			"up/action/@" + shaV3: {"x/x@v1"},
			"x/x/@v1":             {},
		},
		want: "Upgrade to up/action@" + shaV2 + " # v2.0.0 (currently on branch main)",
		kind: Upgrade,
	}, {
		name: "4: neither is fully pinned",
		uses: "up/action@" + shaV1 + " # main",
		fetch: fakeFetcher{
			"up/action/@" + shaV1: {"x/x@v1"},
			"up/action/@" + shaV2: {"x/x@v1"},
			"up/action/@" + shaV3: {"x/x@v1"},
			"x/x/@v1":             {},
		},
		want: "No fix upstream yet: latest release v2.0.0 still uses x/x@v1; fork it or ask upstream to pin (on branch main)",
		kind: None,
	}}
	refs := fakeRefs{"up/action": {Tags: []Tag{{"v2.0.0", shaV2}}, Branches: map[string]string{"main": shaV3}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			it := only(t, plan(t, tt.fetch, refs, scan.Root{Name: app, Owner: "me", Files: []scan.File{workflow(tt.uses)}}))
			if it.FixKind != tt.kind || it.Fix != tt.want {
				t.Errorf("got %s: %q\nwant %s: %q", it.FixKind, it.Fix, tt.kind, tt.want)
			}
		})
	}
}

func TestBranchName(t *testing.T) {
	tests := map[string]string{
		"up/action@main":                 "main",
		"up/action@release/v2":           "release/v2",
		"up/action@" + shaV1 + " # main": "main",
		// Only a comment that is exactly one name is taken as a ref.
		"up/action@" + shaV1 + " # main branch":    "",
		"up/action@" + shaV1 + " # pinned 2026-03": "",
		// Versions are tags, not branches.
		"up/action@" + shaV1 + " # v4":     "",
		"up/action@" + shaV1 + " # v4.1.0": "",
		"up/action@" + shaV1:               "",
	}
	for uses, want := range tests {
		value, comment, _ := strings.Cut(uses, " # ")
		g := &group{direct: scan.Direct{Uses: value, Comment: comment}, ref: ref.Parse(value)}
		if got := branchName(g); got != want {
			t.Errorf("branchName(%q) = %q, want %q", uses, got, want)
		}
	}
}

func TestTagsThatAreNotVersions(t *testing.T) {
	f := fakeFetcher{"up/action/@v1": {"actions/setup-go@v5"}}
	tags := fakeTags{"up/action": {{"latest", shaV2}, {"release-2026", shaV2}}}
	it := only(t, plan(t, f, tags, scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("up/action@v1")}}))
	want := "No fix upstream yet: up/action has no version tags (like v1.2.3) to upgrade to, and uses actions/setup-go@v5 unpinned"
	if it.FixKind != None || !strings.HasPrefix(it.Fix, want) {
		t.Errorf("got %s: %q\nwant prefix %q", it.FixKind, it.Fix, want)
	}
}

func TestPinWhenOnlyTheFileIsMissing(t *testing.T) {
	// The ref resolved, but its action.yml wasn't found: pin to the commit
	// rather than claim it couldn't be resolved.
	s := &scan.Scanner{Fetcher: shaOnlyFetcher{}, Depth: 10, Resolve: true}
	root := scan.Root{Name: "me/app", Owner: "me", Files: []scan.File{workflow("up/action@main")}}
	res, err := s.Scan(context.Background(), []scan.Root{root})
	if err != nil {
		t.Fatal(err)
	}
	repos, err := (&Planner{Scanner: s, Refs: fakeTags{}}).Plan(context.Background(), []scan.Root{root}, res)
	if err != nil {
		t.Fatal(err)
	}
	it := only(t, repos)
	if want := "Pin to up/action@" + shaV3 + " # main"; it.Fix != want {
		t.Errorf("Fix = %q, want %q", it.Fix, want)
	}
}

// shaOnlyFetcher resolves every ref to shaV3 but finds no files.
type shaOnlyFetcher struct{}

func (shaOnlyFetcher) Fetch(_ context.Context, reqs map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	out := map[string]scan.FileRes{}
	for k := range reqs {
		out[k] = scan.FileRes{SHA: shaV3}
	}
	return out, nil
}
