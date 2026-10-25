package gh

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/conspirates/gh-gha-scan/internal/fix"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// handlerTransport serves requests with a handler instead of the network.
type handlerTransport http.HandlerFunc

func (h handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	h(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// testClient returns a client whose GraphQL and REST requests go to h,
// through the retry transport without real waits.
func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	c, err := newClient(handlerTransport(h), api.ClientOptions{Host: "github.com", AuthToken: "test"})
	if err != nil {
		t.Fatal(err)
	}
	c.retry.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestRetriesAreCounted(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			// A secondary rate limit that asks for no wait, to keep the test fast.
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"rateLimit":{"cost":1,"remaining":4999,"resetAt":"x"}}}`))
	})
	var out struct{}
	if err := c.do(context.Background(), "query { rateLimit { cost } }", nil, &out); err != nil {
		t.Fatal(err)
	}
	s := c.Stats()
	if calls != 3 || s.Retries != 2 || s.Queries != 1 {
		t.Errorf("calls = %d, stats = %+v; want 3 calls, 2 retries, 1 query", calls, s)
	}
}

// memRoots is an in-memory RootCache.
type memRoots struct {
	mu    sync.Mutex
	files map[string][]scan.File
}

func (m *memRoots) Files(repo, commit string) ([]scan.File, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[repo+"@"+commit]
	return f, ok
}

func (m *memRoots) StoreFiles(repo, commit string, files []scan.File) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[repo+"@"+commit] = files
}

func TestOwnerReposFetchesOnlyUncachedCommits(t *testing.T) {
	const listing = `{"data":{"rateLimit":{"cost":1,"remaining":4999},"repositoryOwner":{
		"forks":{"totalCount":2},
		"repositories":{"pageInfo":{"hasNextPage":false},"nodes":[
			{"nameWithOwner":"o/cached","defaultBranchRef":{"target":{"oid":"c1"}}},
			{"nameWithOwner":"o/changed","defaultBranchRef":{"target":{"oid":"c2"}}},
			{"nameWithOwner":"o/empty","defaultBranchRef":null},
			{"nameWithOwner":"o/deleted","defaultBranchRef":{"target":{"oid":"c3"}}}]}}}}`
	// o/changed is r0 and o/deleted r1, in listing order.
	const workflows = `{"data":{"rateLimit":{"cost":1,"remaining":4998},
		"r0":{"object":{"entries":[{"name":"ci.yml","type":"blob","object":{"text":"jobs: {}","isTruncated":false,"isBinary":false}}]}},
		"r1":null},
		"errors":[{"type":"NOT_FOUND","path":["r1"],"message":"Could not resolve to a Repository"}]}`
	var queries []string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Query string }
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		queries = append(queries, body.Query)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(body.Query, "repositoryOwner") {
			w.Write([]byte(listing))
		} else {
			w.Write([]byte(workflows))
		}
	})
	cachedFiles := []scan.File{{Path: ".github/workflows/old.yml", Text: "jobs: {}"}}
	roots := &memRoots{files: map[string][]scan.File{"o/cached@c1": cachedFiles}}
	c.Roots = roots

	repos, skipped, err := c.OwnerRepos(context.Background(), "o", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 2 {
		t.Errorf("skipped forks = %d, want 2", skipped)
	}
	got := map[string][]scan.File{}
	for _, r := range repos {
		got[r.NameWithOwner] = r.Files
	}
	changed := []scan.File{{Path: ".github/workflows/ci.yml", Text: "jobs: {}"}}
	want := map[string][]scan.File{"o/cached": cachedFiles, "o/changed": changed, "o/empty": nil}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("repos = %+v, want %+v", got, want)
	}
	if len(queries) != 2 {
		t.Fatalf("got %d queries, want a listing and one workflows query", len(queries))
	}
	q := queries[1]
	if !strings.Contains(q, `"c2:.github/workflows"`) || !strings.Contains(q, `"c3:.github/workflows"`) || strings.Contains(q, "o/cached") || strings.Contains(q, `"cached"`) {
		t.Errorf("workflows query should read only uncached commits:\n%s", q)
	}
	if f, ok := roots.Files("o/changed", "c2"); !ok || !reflect.DeepEqual(f, changed) {
		t.Errorf("o/changed@c2 not stored in the cache: %v %v", f, ok)
	}
}

func TestRefsTellsBranchesFromTags(t *testing.T) {
	// "main" is only a branch; "v1" is both a branch and a tag, so it is
	// taken as the tag.
	const resp = `{"data":{"rateLimit":{"cost":1,"remaining":4999},"t0":{
		"defaultBranchRef":{"name":"main","target":{"oid":"d1"}},
		"refs":{"nodes":[{"name":"v1","target":{"oid":"t1"}}]},
		"b0":{"target":{"oid":"h0"}},"x0":null,
		"b1":{"target":{"oid":"h1"}},"x1":{"name":"v1"}}}}`
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	})
	got, err := c.Refs(context.Background(), map[string][]string{"o/r": {"main", "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	rr := got["o/r"]
	if rr.Default != (fix.Tag{Name: "main", SHA: "d1"}) || len(rr.Tags) != 1 {
		t.Errorf("default = %+v, tags = %+v", rr.Default, rr.Tags)
	}
	if want := map[string]string{"main": "h0"}; !reflect.DeepEqual(rr.Branches, want) {
		t.Errorf("branches = %v, want %v", rr.Branches, want)
	}
}
