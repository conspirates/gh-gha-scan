package fix

import (
	"context"
	"errors"
	"strings"
	"testing"

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

type fakeTags map[string][]Tag

func (f fakeTags) Tags(_ context.Context, repos []string) (map[string][]Tag, error) {
	out := map[string][]Tag{}
	for _, r := range repos {
		if ts, ok := f[r]; ok {
			out[r] = ts
		}
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

func plan(t *testing.T, f fakeFetcher, tags fakeTags, roots ...scan.Root) []Repo {
	t.Helper()
	s := &scan.Scanner{Fetcher: f, Depth: 10, Resolve: true}
	res, err := s.Scan(context.Background(), roots)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&Planner{Scanner: s, Tags: tags}).Plan(context.Background(), roots, res)
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
	if it.FixKind != None || !strings.Contains(it.Fix, "v1.1.0 still uses actions/setup-go@v6") {
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
		// v2.0.0 has no action.yml at that path.
		"missing action": {"up/action/@v1": {"actions/setup-go@v5"}},
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
			p := &Planner{Scanner: s, Tags: tags}
			repos, err := p.Plan(context.Background(), []scan.Root{root}, res)
			if err != nil {
				t.Fatal(err)
			}
			it := only(t, repos)
			if it.FixKind != None || !strings.Contains(it.Fix, "could not read all of latest release v2.0.0") {
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
