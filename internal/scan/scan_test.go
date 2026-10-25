package scan

import (
	"context"
	"errors"
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
