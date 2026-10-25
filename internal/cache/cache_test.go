package cache

import (
	"context"
	"testing"

	"github.com/conspirates/gh-gha-scan/internal/scan"
)

const sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"

type countingFetcher struct{ calls map[string]int }

func (c *countingFetcher) Fetch(_ context.Context, reqs map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	out := map[string]scan.FileRes{}
	for k, req := range reqs {
		c.calls[k]++
		if k == "missing" {
			out[k] = scan.FileRes{}
			continue
		}
		out[k] = scan.FileRes{Found: true, Path: req.Paths[0], Text: "runs: {using: node20}"}
	}
	return out, nil
}

func TestCachesOnlyPinnedRefs(t *testing.T) {
	inner := &countingFetcher{calls: map[string]int{}}
	f := &Fetcher{Inner: inner, Dir: t.TempDir()}
	reqs := map[string]scan.FileReq{
		"pinned": {Owner: "o", Repo: "r", Ref: sha, Paths: []string{"action.yml"}},
		"tag":    {Owner: "o", Repo: "r", Ref: "v1", Paths: []string{"action.yml"}},
	}
	for i := 0; i < 2; i++ {
		got, err := f.Fetch(context.Background(), reqs)
		if err != nil {
			t.Fatal(err)
		}
		if !got["pinned"].Found || got["pinned"].Text == "" {
			t.Fatalf("pinned result = %+v", got["pinned"])
		}
	}
	if inner.calls["pinned"] != 1 {
		t.Errorf("pinned fetched %d times, want 1", inner.calls["pinned"])
	}
	if inner.calls["tag"] != 2 {
		t.Errorf("tag fetched %d times, want 2", inner.calls["tag"])
	}
	if f.Hits != 1 {
		t.Errorf("Hits = %d, want 1", f.Hits)
	}
}

func TestDoesNotCacheNotFound(t *testing.T) {
	inner := &countingFetcher{calls: map[string]int{}}
	f := &Fetcher{Inner: inner, Dir: t.TempDir()}
	reqs := map[string]scan.FileReq{"missing": {Owner: "o", Repo: "r", Ref: sha, Paths: []string{"action.yml"}}}
	for i := 0; i < 2; i++ {
		if _, err := f.Fetch(context.Background(), reqs); err != nil {
			t.Fatal(err)
		}
	}
	if inner.calls["missing"] != 2 {
		t.Errorf("not-found fetched %d times, want 2 (never cached)", inner.calls["missing"])
	}
}

func TestDifferentPathsDoNotShareEntries(t *testing.T) {
	inner := &countingFetcher{calls: map[string]int{}}
	f := &Fetcher{Inner: inner, Dir: t.TempDir()}
	a := map[string]scan.FileReq{"k": {Owner: "o", Repo: "r", Ref: sha, Paths: []string{"x/action.yml"}}}
	b := map[string]scan.FileReq{"k": {Owner: "o", Repo: "r", Ref: sha, Paths: []string{"x"}}}
	if _, err := f.Fetch(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	got, err := f.Fetch(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls["k"] != 2 || got["k"].Path != "x" {
		t.Errorf("calls = %d, path = %q; want a fresh fetch for different paths", inner.calls["k"], got["k"].Path)
	}
}
