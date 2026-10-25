package gh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// Stats summarizes API usage.
type Stats struct {
	Queries   int    `json:"queries"`
	Cost      int    `json:"cost"`
	Remaining int    `json:"remaining"`
	ResetAt   string `json:"reset_at,omitempty"`
}

// Client talks to the GitHub API.
type Client struct {
	gql  *api.GraphQLClient
	rest *api.RESTClient
	// Concurrency bounds parallel GraphQL queries. GitHub's secondary rate
	// limits penalize parallel GraphQL, so keep it low.
	Concurrency int

	mu    sync.Mutex
	stats Stats
	known bool // whether stats.Remaining has been observed
}

// Repo is a repository with its top-level workflow files.
type Repo struct {
	NameWithOwner string
	HeadOID       string
	Files         []scan.File
}

// New returns a client authenticated the way gh is.
func New() (*Client, error) {
	gql, err := api.DefaultGraphQLClient()
	if err != nil {
		return nil, err
	}
	rest, err := api.NewRESTClient(api.ClientOptions{
		Headers: map[string]string{"Accept": "application/vnd.github.raw+json"},
	})
	if err != nil {
		return nil, err
	}
	return &Client{gql: gql, rest: rest, Concurrency: 2}, nil
}

// Stats returns API usage so far.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// minRemaining is the GraphQL budget below which the client stops instead of
// running into the hard limit.
const minRemaining = 20

// do runs a query, retrying transient server errors and tracking rate limits.
// GraphQL errors are returned together with the partial data in out.
func (c *Client) do(ctx context.Context, query string, vars map[string]any, out any) error {
	c.mu.Lock()
	if c.known && c.stats.Remaining < minRemaining {
		c.mu.Unlock()
		return fmt.Errorf("GraphQL rate limit nearly exhausted (%d points left), resets at %s", c.stats.Remaining, c.stats.ResetAt)
	}
	c.mu.Unlock()

	var data map[string]json.RawMessage
	var err error
	for attempt := 0; ; attempt++ {
		data = nil
		err = c.gql.DoWithContext(ctx, query, vars, &data)
		wait, retry := retryAfter(err, attempt)
		if !retry {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}

	if raw, ok := data["rateLimit"]; ok {
		var rl rateLimit
		if json.Unmarshal(raw, &rl) == nil {
			c.mu.Lock()
			c.stats.Queries++
			c.stats.Cost += rl.Cost
			c.stats.Remaining = rl.Remaining
			c.stats.ResetAt = rl.ResetAt
			c.known = true
			c.mu.Unlock()
		}
	}
	if data != nil {
		b, _ := json.Marshal(data)
		if uerr := json.Unmarshal(b, out); uerr != nil {
			return uerr
		}
	}
	return err
}

// retryAfter decides whether err is worth retrying and how long to wait.
func retryAfter(err error, attempt int) (time.Duration, bool) {
	var he *api.HTTPError
	if !errors.As(err, &he) || attempt >= 3 {
		return 0, false
	}
	switch {
	case he.StatusCode >= 500:
		return time.Duration(1<<attempt) * time.Second, true
	case he.StatusCode == http.StatusForbidden || he.StatusCode == http.StatusTooManyRequests:
		// Secondary rate limits say how long to wait; primary ones don't
		// recover within a run, so only wait for short Retry-After values.
		if s, err := strconv.Atoi(he.Headers.Get("Retry-After")); err == nil && s <= 60 {
			return time.Duration(s) * time.Second, true
		}
	}
	return 0, false
}

func isServerError(err error) bool {
	var he *api.HTTPError
	return errors.As(err, &he) && he.StatusCode >= 500
}

// notFound returns the top-level aliases that GraphQL reported as not found
// (or not accessible), and an error for anything else.
func notFound(err error) (map[string]string, error) {
	var ge *api.GraphQLError
	if !errors.As(err, &ge) {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range ge.Errors {
		if e.Type != "NOT_FOUND" || len(e.Path) == 0 {
			return nil, err
		}
		if alias, ok := e.Path[0].(string); ok {
			out[alias] = e.Message
		}
	}
	return out, nil
}

// OwnerRepos lists the repositories of an organization or user, with their
// workflow files.
func (c *Client) OwnerRepos(ctx context.Context, login string, includeArchived, includeForks bool) ([]Repo, error) {
	vars := map[string]any{"login": login}
	if !includeArchived {
		vars["archived"] = false
	}
	if !includeForks {
		vars["fork"] = false
	}
	// Some repositories have huge workflow files, so start small and shrink
	// the page further if GitHub times out.
	first := 25
	var repos []Repo
	for {
		vars["first"] = first
		var resp struct {
			RepositoryOwner *struct {
				Repositories struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []repoNode `json:"nodes"`
				} `json:"repositories"`
			} `json:"repositoryOwner"`
		}
		err := c.do(ctx, ownerReposQuery, vars, &resp)
		if isServerError(err) && first > 1 {
			first /= 2
			continue
		}
		if err != nil {
			return nil, err
		}
		if resp.RepositoryOwner == nil {
			return nil, fmt.Errorf("no organization or user named %q", login)
		}
		for _, n := range resp.RepositoryOwner.Repositories.Nodes {
			r, err := c.repo(ctx, n)
			if err != nil {
				return nil, err
			}
			repos = append(repos, r)
		}
		page := resp.RepositoryOwner.Repositories.PageInfo
		if !page.HasNextPage {
			return repos, nil
		}
		vars["after"] = page.EndCursor
	}
}

// Repo returns one repository with its workflow files.
func (c *Client) Repo(ctx context.Context, owner, name string) (Repo, error) {
	var resp struct {
		Repository *repoNode `json:"repository"`
	}
	err := c.do(ctx, repoQuery, map[string]any{"owner": owner, "name": name}, &resp)
	if _, nfErr := notFound(err); err != nil && nfErr != nil {
		return Repo{}, err
	}
	if resp.Repository == nil {
		return Repo{}, fmt.Errorf("repository %s/%s not found", owner, name)
	}
	return c.repo(ctx, *resp.Repository)
}

func (c *Client) repo(ctx context.Context, n repoNode) (Repo, error) {
	r := Repo{NameWithOwner: n.NameWithOwner}
	if n.DefaultBranchRef != nil {
		r.HeadOID = n.DefaultBranchRef.Target.OID
	}
	if n.Object == nil {
		return r, nil
	}
	for _, e := range n.Object.Entries {
		// GitHub only runs workflow files directly in .github/workflows.
		if e.Type != "blob" || !(strings.HasSuffix(e.Name, ".yml") || strings.HasSuffix(e.Name, ".yaml")) || e.Object == nil || e.Object.IsBinary {
			continue
		}
		p := ".github/workflows/" + e.Name
		text, err := c.text(ctx, n.NameWithOwner, r.HeadOID, p, e.Object)
		if err != nil {
			return Repo{}, err
		}
		r.Files = append(r.Files, scan.File{Path: p, Text: text})
	}
	return r, nil
}

// text returns a blob's text, falling back to REST for blobs GraphQL truncated.
func (c *Client) text(ctx context.Context, repo, commit, p string, b *blob) (string, error) {
	if b.Text != nil && !b.IsTruncated {
		return *b.Text, nil
	}
	endpoint := fmt.Sprintf("repos/%s/contents/%s?ref=%s", repo, p, url.QueryEscape(commit))
	resp, err := c.rest.RequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("read %s/%s: %w", repo, p, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read %s/%s: %w", repo, p, err)
	}
	return string(data), nil
}

// Fetch implements scan.Fetcher with batched GraphQL queries.
func (c *Client) Fetch(ctx context.Context, reqs map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	keys := make([]string, 0, len(reqs))
	for k := range reqs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var (
		mu       sync.Mutex
		out      = make(map[string]scan.FileRes, len(reqs))
		firstErr error
		wg       sync.WaitGroup
		sem      = make(chan struct{}, max(c.Concurrency, 1))
	)
	for start := 0; start < len(keys); start += BatchSize {
		chunk := keys[start:min(start+BatchSize, len(keys))]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := c.fetchBatch(ctx, chunk, reqs)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for k, v := range res {
				out[k] = v
			}
		}()
	}
	wg.Wait()
	return out, firstErr
}

func (c *Client) fetchBatch(ctx context.Context, keys []string, all map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	reqs := make([]scan.FileReq, len(keys))
	for i, k := range keys {
		reqs[i] = all[k]
	}
	var resp map[string]json.RawMessage
	err := c.do(ctx, batchQuery(reqs), nil, &resp)
	missing, err := notFound(err)
	if err != nil {
		return nil, err
	}

	out := make(map[string]scan.FileRes, len(keys))
	for i, k := range keys {
		req, alias := reqs[i], fmt.Sprintf("r%d", i)
		var objs map[string]json.RawMessage
		if raw := resp[alias]; len(raw) > 0 {
			_ = json.Unmarshal(raw, &objs)
		}
		if objs == nil {
			msg := "repository not found or not accessible"
			if m, ok := missing[alias]; ok && m != "" {
				msg = m
			}
			out[k] = scan.FileRes{Err: msg}
			continue
		}
		var res scan.FileRes
		for j, p := range req.Paths {
			var b *blob
			_ = json.Unmarshal(objs[fmt.Sprintf("f%d", j)], &b)
			if b == nil || b.IsBinary {
				continue
			}
			text, err := c.text(ctx, req.Owner+"/"+req.Repo, req.Ref, p, b)
			if err != nil {
				return nil, err
			}
			res = scan.FileRes{Found: true, Path: p, Text: text}
			break
		}
		if req.Resolve {
			var o *object
			_ = json.Unmarshal(objs["c"], &o)
			res.SHA = o.commit()
		}
		out[k] = res
	}
	return out, nil
}
