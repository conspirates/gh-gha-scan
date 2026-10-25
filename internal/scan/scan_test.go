package scan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const pinned = "1111111111111111111111111111111111111111"

// fakeFetcher serves composite actions whose steps use the given refs.
type fakeFetcher struct {
	actions map[string][]string // ref key -> uses
	calls   [][]string          // keys requested per Fetch call
}

func composite(uses ...string) string {
	var b strings.Builder
	b.WriteString("runs:\n  using: composite\n  steps:\n")
	for _, u := range uses {
		b.WriteString("    - uses: " + u + "\n")
	}
	return b.String()
}

func (f *fakeFetcher) Fetch(_ context.Context, reqs map[string]FileReq) (map[string]FileRes, error) {
	out := map[string]FileRes{}
	var keys []string
	for k, req := range reqs {
		keys = append(keys, k)
		uses, ok := f.actions[k]
		if !ok {
			out[k] = FileRes{}
			continue
		}
		res := FileRes{Found: true, Path: req.Paths[0], Text: composite(uses...)}
		if req.Resolve {
			res.SHA = "sha-of-" + req.Ref
		}
		out[k] = res
	}
	f.calls = append(f.calls, keys)
	return out, nil
}

func workflowFile(uses ...string) File {
	var b strings.Builder
	b.WriteString("jobs:\n  build:\n    steps:\n")
	for _, u := range uses {
		b.WriteString("      - uses: " + u + "\n")
	}
	return File{Path: ".github/workflows/ci.yml", Text: b.String()}
}

type brief struct {
	Uses string
	Via  []string
}

func briefs(fs []Finding) []brief {
	var out []brief
	for _, f := range fs {
		out = append(out, brief{f.Uses, f.Via})
	}
	return out
}

func TestTransitiveThroughPinnedAction(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"a/pinned/@" + pinned: {"b/unpinned@v1"},
		"b/unpinned/@v1":      {"c/deep@main"},
		"c/deep/@main":        {},
		"d/direct/@v2":        {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "me/repo", Owner: "me",
		Files: []File{workflowFile("a/pinned@"+pinned, "d/direct@v2")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{
		{"b/unpinned@v1", []string{"a/pinned@1111111"}},
		{"c/deep@main", []string{"a/pinned@1111111", "b/unpinned@v1"}},
		{"d/direct@v2", nil},
	}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings =\n%+v\nwant\n%+v", got, want)
	}
	if got := res.Findings[1].Source; got != "b/unpinned/action.yml@v1:4" {
		t.Errorf("Source = %q", got)
	}
	if len(f.calls) != 3 {
		t.Errorf("Fetch called %d times, want one per level (3)", len(f.calls))
	}
}

func TestDedupeAcrossRoots(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"shared/action/@v1": {"inner/x@v1"},
		"inner/x/@v1":       {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10}
	roots := []Root{
		{Name: "o/one", Files: []File{workflowFile("shared/action@v1")}},
		{Name: "o/two", Files: []File{workflowFile("shared/action@v1")}},
	}
	res, err := s.Scan(context.Background(), roots)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, call := range f.calls {
		for _, k := range call {
			seen[k]++
		}
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("%s fetched %d times, want 1", k, n)
		}
	}
	// Each root still gets its own findings.
	if len(res.Findings) != 4 {
		t.Errorf("got %d findings, want 4: %+v", len(res.Findings), briefs(res.Findings))
	}
}

func TestCycleTerminates(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"x/a/@v1": {"y/b@v1"},
		"y/b/@v1": {"x/a@v1"},
	}}
	s := &Scanner{Fetcher: f, Depth: 50}
	res, err := s.Scan(context.Background(), []Root{{Name: "o/r", Files: []File{workflowFile("x/a@v1")}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 3 {
		t.Errorf("got %+v", briefs(res.Findings))
	}
	if res.Incomplete["o/r"] || len(res.Warnings) != 0 {
		t.Errorf("a cycle is not incomplete: Incomplete = %v, warnings = %v", res.Incomplete, res.Warnings)
	}
}

func TestDepthLimit(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"a/a/@v1": {"b/b@v1"},
		"b/b/@v1": {"c/c@v1"},
		"c/c/@v1": {},
	}}
	s := &Scanner{Fetcher: f, Depth: 2}
	res, err := s.Scan(context.Background(), []Root{{Name: "o/r", Files: []File{workflowFile("a/a@v1")}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{{"a/a@v1", nil}, {"b/b@v1", []string{"a/a@v1"}}}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v, want %+v", got, want)
	}
	if len(f.calls) != 2 {
		t.Errorf("Fetch called %d times, want 2", len(f.calls))
	}
	// b/b uses c/c, which was cut off by the depth limit.
	if !res.Incomplete["o/r"] || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "stopped at --depth 2") {
		t.Errorf("Incomplete = %v, warnings = %v; want one depth warning", res.Incomplete, res.Warnings)
	}
}

func TestDepthLimitWithNothingBelowIsComplete(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{"a/a/@v1": {"b/b@v1"}, "b/b/@v1": {}}}
	s := &Scanner{Fetcher: f, Depth: 2}
	res, err := s.Scan(context.Background(), []Root{{Name: "o/r", Files: []File{workflowFile("a/a@v1")}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Incomplete["o/r"] || len(res.Warnings) != 0 {
		t.Errorf("Incomplete = %v, warnings = %v; want complete", res.Incomplete, res.Warnings)
	}
}

func TestExternalAndResolve(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"me/own/@v1":    {},
		"other/ext/@v2": {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10, Resolve: true}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "me/repo", Owner: "Me",
		Files: []File{workflowFile("me/own@v1", "other/ext@v2")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("got %+v", res.Findings)
	}
	if res.Findings[0].External || !res.Findings[1].External {
		t.Errorf("External = %v, %v; want false, true", res.Findings[0].External, res.Findings[1].External)
	}
	if res.Findings[1].SuggestedSHA != "sha-of-v2" {
		t.Errorf("SuggestedSHA = %q", res.Findings[1].SuggestedSHA)
	}
}

func TestLocalRootReadsLocalActions(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{"ext/a/@v1": {}}}
	files := map[string]string{
		".github/actions/setup/action.yml":  composite("ext/a@v1", "./.github/actions/other"),
		".github/actions/other/action.yaml": composite("ext/b@" + pinned),
	}
	read := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("not found")
	}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: ".", ReadLocal: read,
		Files: []File{workflowFile("./.github/actions/setup")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{{"ext/a@v1", []string{"./.github/actions/setup"}}}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v, want %+v", got, want)
	}
	// ext/b is pinned but not served by the fake, so it is reported missing.
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "ext/b@") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestRemoteRootResolvesLocalAtHead(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"me/repo/.github/actions/x@" + pinned: {"ext/a@v1"},
		"ext/a/@v1":                           {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "me/repo", Repo: "me/repo", HeadOID: pinned,
		Files: []File{workflowFile("./.github/actions/x")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{{"ext/a@v1", []string{"./.github/actions/x"}}}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v, want %+v", got, want)
	}
}

func TestLocalReusableWorkflow(t *testing.T) {
	reusable := "jobs:\n  build:\n    steps:\n      - uses: ext/a@v1\n"
	read := func(p string) ([]byte, error) {
		if p == ".github/workflows/reuse.yml" {
			return []byte(reusable), nil
		}
		return nil, errors.New("not found")
	}
	f := &fakeFetcher{actions: map[string][]string{"ext/a/@v1": {}}}
	s := &Scanner{Fetcher: f, Depth: 10}
	caller := File{Path: ".github/workflows/ci.yml", Text: "jobs:\n  call:\n    uses: ./.github/workflows/reuse.yml\n"}
	res, err := s.Scan(context.Background(), []Root{{Name: "me/app", ReadLocal: read, Files: []File{caller}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{{"ext/a@v1", []string{"./.github/workflows/reuse.yml"}}}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v, want %+v", got, want)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}
}

func TestRemoteRootResolvesLocalReusableWorkflowAtHead(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"me/repo/.github/workflows/reuse.yml@" + pinned: {"ext/a@v1"},
		"ext/a/@v1": {},
	}}
	rec := &recordingFetcher{inner: f, reqs: map[string]FileReq{}}
	s := &Scanner{Fetcher: rec, Depth: 10}
	caller := File{Path: ".github/workflows/ci.yml", Text: "jobs:\n  call:\n    uses: ./.github/workflows/reuse.yml\n"}
	res, err := s.Scan(context.Background(), []Root{{Name: "me/repo", Repo: "me/repo", HeadOID: pinned, Files: []File{caller}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Uses != "ext/a@v1" || len(res.Warnings) != 0 {
		t.Errorf("findings = %+v, warnings = %v", briefs(res.Findings), res.Warnings)
	}
	req := rec.reqs["me/repo/.github/workflows/reuse.yml@"+pinned]
	if !reflect.DeepEqual(req.Paths, []string{".github/workflows/reuse.yml"}) {
		t.Errorf("requested paths %v, want the workflow file itself", req.Paths)
	}
}

// recordingFetcher remembers the last request for each key.
type recordingFetcher struct {
	inner Fetcher
	reqs  map[string]FileReq
}

func (r *recordingFetcher) Fetch(ctx context.Context, reqs map[string]FileReq) (map[string]FileRes, error) {
	for k, req := range reqs {
		r.reqs[k] = req
	}
	return r.inner.Fetch(ctx, reqs)
}

func TestLocalRefsBelowSharedDependencyAreFollowedForEveryRoot(t *testing.T) {
	// x/a has no local refs itself, but y/b below it does.
	f := &fakeFetcher{actions: map[string][]string{
		"x/a/@v1":        {"y/b@" + pinned},
		"y/b/@" + pinned: {"./.github/actions/setup"},
		"ext/one/@v1":    {},
		"ext/two/@v1":    {},
	}}
	local := func(uses string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			if p == ".github/actions/setup/action.yml" {
				return []byte(composite(uses)), nil
			}
			return nil, errors.New("not found")
		}
	}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{
		{Name: "o/one", ReadLocal: local("ext/one@v1"), Files: []File{workflowFile("x/a@v1")}},
		{Name: "o/two", ReadLocal: local("ext/two@v1"), Files: []File{workflowFile("x/a@v1")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Repo+" "+f.Uses] = true
	}
	for _, want := range []string{"o/one ext/one@v1", "o/two ext/two@v1"} {
		if !got[want] {
			t.Errorf("missing finding %q; got %v", want, got)
		}
	}
}

func TestRemoteRootShowsLocalActionPathInRepo(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"me/repo/.github/actions/x@" + pinned: {"ext/a@v1"},
		"ext/a/@v1":                           {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "me/repo", Repo: "me/repo", HeadOID: pinned,
		Files: []File{workflowFile("./.github/actions/x")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %+v", res.Findings)
	}
	f0 := res.Findings[0]
	if f0.Direct.File != ".github/actions/x/action.yml" || f0.Source != ".github/actions/x/action.yml:4" {
		t.Errorf("Direct.File = %q, Source = %q; want paths in the repository", f0.Direct.File, f0.Source)
	}
}

func TestSelfRefInLocalRoot(t *testing.T) {
	// From the fixture in issue #2.
	read := func(p string) ([]byte, error) {
		if p == ".github/actions/local/action.yml" {
			return []byte(composite("actions/cache@v4")), nil
		}
		return nil, errors.New("not found")
	}
	f := &fakeFetcher{actions: map[string][]string{"actions/cache/@v4": {}}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "example/fixture", ReadLocal: read,
		Files: []File{workflowFile("$/.github/actions/local")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{{"actions/cache@v4", []string{"$/.github/actions/local"}}}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v, want %+v", got, want)
	}
	if len(res.Warnings) != 0 || res.Incomplete["example/fixture"] {
		t.Errorf("warnings = %v, incomplete = %v; want none", res.Warnings, res.Incomplete)
	}
}

func TestSelfRefInRemoteRootResolvesAtHead(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{
		"me/repo/.github/actions/x@" + pinned: {"ext/a@v1"},
		"ext/a/@v1":                           {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "me/repo", Repo: "me/repo", HeadOID: pinned,
		Files: []File{workflowFile("$/.github/actions/x")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{{"ext/a@v1", []string{"$/.github/actions/x"}}}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v, want %+v", got, want)
	}
}

func TestSelfRefBelowRemoteResolvesInThatRepo(t *testing.T) {
	// A $/ ref in ext/lib resolves in ext/lib at the same ref, not in the
	// scanned repository, even though the root could read ./ refs locally.
	f := &fakeFetcher{actions: map[string][]string{
		"ext/lib/@" + pinned:                      {"$/.github/actions/inner"},
		"ext/lib/.github/actions/inner@" + pinned: {"ext/deep@v1"},
		"ext/deep/@v1":                            {},
	}}
	read := func(string) ([]byte, error) { return nil, errors.New("not found") }
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "me/app", ReadLocal: read,
		Files: []File{workflowFile("ext/lib@" + pinned)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []brief{{"ext/deep@v1", []string{"ext/lib@1111111", "$/.github/actions/inner"}}}
	if got := briefs(res.Findings); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v, want %+v", got, want)
	}
	if got := res.Findings[0].Source; got != "ext/lib/.github/actions/inner/action.yml@"+pinned+":4" {
		t.Errorf("Source = %q", got)
	}
	if len(res.Warnings) != 0 || res.Incomplete["me/app"] {
		t.Errorf("warnings = %v, incomplete = %v; want none", res.Warnings, res.Incomplete)
	}
}

func TestInvalidUsesMarksIncomplete(t *testing.T) {
	s := &Scanner{Fetcher: &fakeFetcher{}, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{
		Name: "o/r", Files: []File{workflowFile("$/.github/actions/x@v1", "checkout@v4")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete["o/r"] || len(res.Warnings) != 2 || len(res.Findings) != 0 {
		t.Errorf("incomplete = %v, warnings = %v, findings = %+v; want incomplete with two warnings", res.Incomplete, res.Warnings, briefs(res.Findings))
	}
}

func TestUnparsableRootFileMarksIncomplete(t *testing.T) {
	// From the fixture in issue #2.
	broken := File{Path: ".github/workflows/broken.yml", Text: "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n     bad: [indent\n"}
	s := &Scanner{Fetcher: &fakeFetcher{}, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{Name: "o/r", Files: []File{broken}}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete["o/r"] || len(res.Warnings) != 1 {
		t.Errorf("incomplete = %v, warnings = %v; want incomplete with one warning", res.Incomplete, res.Warnings)
	}
}

// brokenFetcher serves an unparsable file for every request.
type brokenFetcher struct{}

func (brokenFetcher) Fetch(_ context.Context, reqs map[string]FileReq) (map[string]FileRes, error) {
	out := map[string]FileRes{}
	for k, req := range reqs {
		out[k] = FileRes{Found: true, Path: req.Paths[0], Text: "runs:\n  steps: [unclosed\n"}
	}
	return out, nil
}

func TestUnparsableFetchedFileMarksIncomplete(t *testing.T) {
	s := &Scanner{Fetcher: brokenFetcher{}, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{
		{Name: "o/one", Files: []File{workflowFile("ext/a@" + pinned)}},
		{Name: "o/two", Files: []File{workflowFile("ext/a@" + pinned)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The file is parsed once, but every repository that uses it is affected.
	if !res.Incomplete["o/one"] || !res.Incomplete["o/two"] || len(res.Warnings) != 1 {
		t.Errorf("incomplete = %v, warnings = %v; want both incomplete with one warning", res.Incomplete, res.Warnings)
	}
}

func TestSharedDependencyIsWalkedOnce(t *testing.T) {
	// A chain of diamonds: each level reaches the next through two paths,
	// which used to double the work and the findings at every level.
	actions := map[string][]string{}
	const levels = 12
	for i := 0; i < levels; i++ {
		next := fmt.Sprintf("d/l%d@%s", i+1, pinned)
		actions[fmt.Sprintf("d/l%d/@%s", i, pinned)] = []string{fmt.Sprintf("d/a%d@%s", i, pinned), fmt.Sprintf("d/b%d@%s", i, pinned)}
		actions[fmt.Sprintf("d/a%d/@%s", i, pinned)] = []string{next}
		actions[fmt.Sprintf("d/b%d/@%s", i, pinned)] = []string{next}
	}
	actions[fmt.Sprintf("d/l%d/@%s", levels, pinned)] = []string{"x/x@v1"}
	actions["x/x/@v1"] = []string{}
	s := &Scanner{Fetcher: &fakeFetcher{actions: actions}, Depth: 100}
	res, err := s.Scan(context.Background(), []Root{{Name: "o/r", Files: []File{workflowFile("d/l0@" + pinned)}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Uses != "x/x@v1" {
		t.Errorf("got %d findings, want x/x@v1 once: %+v", len(res.Findings), briefs(res.Findings)[:min(len(res.Findings), 3)])
	}
	if res.Incomplete["o/r"] || len(res.Warnings) != 0 {
		t.Errorf("incomplete = %v, warnings = %v", res.Incomplete, res.Warnings)
	}
}

func TestSharedDependencyIsReportedUnderEachDirectRef(t *testing.T) {
	// Two direct refs that share a dependency each need their own fix.
	f := &fakeFetcher{actions: map[string][]string{
		"a/a/@v1":        {"s/s@" + pinned},
		"b/b/@v1":        {"s/s@" + pinned},
		"s/s/@" + pinned: {"x/x@v1"},
		"x/x/@v1":        {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{Name: "o/r", Files: []File{workflowFile("a/a@v1", "b/b@v1")}}})
	if err != nil {
		t.Fatal(err)
	}
	directs := map[string]bool{}
	for _, f := range res.Findings {
		if f.Uses == "x/x@v1" {
			directs[f.Direct.Uses] = true
		}
	}
	if !directs["a/a@v1"] || !directs["b/b@v1"] {
		t.Errorf("x/x@v1 reported under %v, want both a/a@v1 and b/b@v1", directs)
	}
}

func TestNestedInvalidUsesWarnsAtItsOwnLocation(t *testing.T) {
	f := &fakeFetcher{actions: map[string][]string{"ext/a/@" + pinned: {"checkout@v4"}}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{Name: "o/r", Files: []File{workflowFile("ext/a@" + pinned)}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "o/r: ext/a/action.yml@" + pinned + `:4: cannot parse uses "checkout@v4"`
	if len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Errorf("warnings = %q, want %q", res.Warnings, want)
	}
}

func TestSourceOwnerAndBoundary(t *testing.T) {
	// me/lib is a same-owner composite: it uses y/y unpinned itself, and
	// the pinned third-party ext/tp, which uses z/z unpinned.
	f := &fakeFetcher{actions: map[string][]string{
		"me/lib/@" + pinned: {"y/y@v1", "ext/tp@" + pinned},
		"ext/tp/@" + pinned: {"z/z@v1"},
		"y/y/@v1":           {},
		"z/z/@v1":           {},
	}}
	s := &Scanner{Fetcher: f, Depth: 10}
	res, err := s.Scan(context.Background(), []Root{{Name: "me/app", Owner: "me", Files: []File{workflowFile("me/lib@" + pinned)}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("got %+v", briefs(res.Findings))
	}
	y, z := res.Findings[0], res.Findings[1]
	if y.Uses != "y/y@v1" || y.SourceOwner != "me" || y.SourceExternal || !y.External {
		t.Errorf("y: uses %q, source owner %q, source external %v, external %v; want me, false, true", y.Uses, y.SourceOwner, y.SourceExternal, y.External)
	}
	// y/y is in a file me controls, so it is its own boundary.
	if y.Boundary.Uses != "y/y@v1" {
		t.Errorf("y: boundary = %+v, want y/y@v1 itself", y.Boundary)
	}
	if z.Uses != "z/z@v1" || z.SourceOwner != "ext" || !z.SourceExternal {
		t.Errorf("z: uses %q, source owner %q, source external %v; want ext, true", z.Uses, z.SourceOwner, z.SourceExternal)
	}
	wantB := Direct{Uses: "ext/tp@" + pinned, File: "me/lib/action.yml@" + pinned, Line: 5}
	if z.Boundary != wantB || z.Direct.Uses != "me/lib@"+pinned {
		t.Errorf("z: boundary = %+v, want %+v; direct = %+v", z.Boundary, wantB, z.Direct)
	}
}
