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

	"github.com/conspirates/gh-gha-scan/internal/fix"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// Stats summarizes API usage.
type Stats struct {
	Queries   int    `json:"queries"`
	Cost      int    `json:"cost"`
	Remaining int    `json:"remaining"`
	ResetAt   string `json:"reset_at,omitempty"`
	// Retries counts queries retried after a server error or a secondary
	// rate limit, and RetryWait is the total time spent waiting for them.
	Retries          int           `json:"retries"`
	RetryWait        time.Duration `json:"-"`
	RetryWaitSeconds float64       `json:"retry_wait_seconds"`
}

// Client talks to the GitHub API.
type Client struct {
	gql  *api.GraphQLClient
	rest *api.RESTClient
	// Concurrency bounds parallel GraphQL queries. GitHub's secondary rate
	// limits penalize parallel GraphQL, so keep it low; Stats counts the
	// retries they cause.
	Concurrency int
	// Roots, if set, caches the workflow files of listed repositories.
	Roots RootCache

	mu    sync.Mutex
	stats Stats
	known bool // whether stats.Remaining has been observed
}

// Repo is a repository with its top-level workflow files.
type Repo struct {
	NameWithOwner string
	IsFork        bool
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
	return &Client{gql: gql, rest: rest, Concurrency: 4}, nil
}

// Stats returns API usage so far.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.RetryWaitSeconds = s.RetryWait.Seconds()
	return s
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
		c.mu.Lock()
		c.stats.Retries++
		c.stats.RetryWait += wait
		c.mu.Unlock()
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

// RootCache keeps the top-level workflow files of repositories by commit.
// It must be safe for concurrent use.
type RootCache interface {
	Files(repo, commit string) ([]scan.File, bool)
	StoreFiles(repo, commit string, files []scan.File)
}

// OwnerRepos lists the repositories of an organization or user, with their
// workflow files at the default branch commit. Files for a commit that
// Roots already has are not fetched. skippedForks counts the forks left out
// when includeForks is false.
func (c *Client) OwnerRepos(ctx context.Context, login string, includeArchived, includeForks bool) (repos []Repo, skippedForks int, err error) {
	vars := map[string]any{"login": login}
	if !includeArchived {
		vars["archived"] = false
	}
	if !includeForks {
		vars["fork"] = false
	}
	var nodes []repoNode
	for {
		var resp struct {
			RepositoryOwner *struct {
				Forks struct {
					TotalCount int `json:"totalCount"`
				} `json:"forks"`
				Repositories struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []repoNode `json:"nodes"`
				} `json:"repositories"`
			} `json:"repositoryOwner"`
		}
		if err := c.do(ctx, ownerReposQuery, vars, &resp); err != nil {
			return nil, 0, err
		}
		if resp.RepositoryOwner == nil {
			return nil, 0, fmt.Errorf("no organization or user named %q", login)
		}
		if !includeForks {
			skippedForks = resp.RepositoryOwner.Forks.TotalCount
		}
		nodes = append(nodes, resp.RepositoryOwner.Repositories.Nodes...)
		page := resp.RepositoryOwner.Repositories.PageInfo
		if !page.HasNextPage {
			break
		}
		vars["after"] = page.EndCursor
	}

	repos = make([]Repo, len(nodes))
	var need []repoNode
	fetched := map[string]bool{}
	for i, n := range nodes {
		repos[i] = Repo{NameWithOwner: n.NameWithOwner, IsFork: n.IsFork, HeadOID: n.oid()}
		if n.oid() == "" {
			continue
		}
		if c.Roots != nil {
			if files, ok := c.Roots.Files(n.NameWithOwner, n.oid()); ok {
				repos[i].Files = files
				continue
			}
		}
		need = append(need, n)
		fetched[n.NameWithOwner] = true
	}
	got, err := c.workflows(ctx, need)
	if err != nil {
		return nil, 0, err
	}
	// A repository deleted since it was listed has no entry and is dropped.
	out := repos[:0]
	for _, r := range repos {
		if fetched[r.NameWithOwner] {
			var ok bool
			if r, ok = got[r.NameWithOwner]; !ok {
				continue
			}
		}
		out = append(out, r)
	}
	return out, skippedForks, nil
}

// workflows reads the workflow files of nodes at their default branch
// commits, WorkflowsPerQuery repositories per query, and stores them in
// Roots. Repositories that can no longer be read have no entry.
func (c *Client) workflows(ctx context.Context, nodes []repoNode) (map[string]Repo, error) {
	var (
		mu       sync.Mutex
		out      = map[string]Repo{}
		firstErr error
		wg       sync.WaitGroup
		sem      = make(chan struct{}, max(c.Concurrency, 1))
	)
	for start := 0; start < len(nodes); start += WorkflowsPerQuery {
		chunk := nodes[start:min(start+WorkflowsPerQuery, len(nodes))]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			repos, err := c.workflowsBatch(ctx, chunk)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for _, r := range repos {
				out[r.NameWithOwner] = r
			}
		}()
	}
	wg.Wait()
	return out, firstErr
}

// workflowsBatch reads one batch, splitting it when GitHub times out.
func (c *Client) workflowsBatch(ctx context.Context, nodes []repoNode) ([]Repo, error) {
	var resp map[string]*struct {
		Object json.RawMessage `json:"object"`
	}
	err := c.do(ctx, workflowsQuery(nodes), nil, &resp)
	if isServerError(err) && len(nodes) > 1 {
		half := len(nodes) / 2
		a, err := c.workflowsBatch(ctx, nodes[:half])
		if err != nil {
			return nil, err
		}
		b, err := c.workflowsBatch(ctx, nodes[half:])
		return append(a, b...), err
	}
	if _, err := notFound(err); err != nil {
		return nil, err
	}
	var repos []Repo
	for i, n := range nodes {
		got := resp[fmt.Sprintf("r%d", i)]
		if got == nil {
			continue
		}
		if len(got.Object) > 0 {
			if err := json.Unmarshal(got.Object, &n.Object); err != nil {
				return nil, err
			}
		}
		r, err := c.repo(ctx, n)
		if err != nil {
			return nil, err
		}
		if c.Roots != nil {
			c.Roots.StoreFiles(r.NameWithOwner, r.HeadOID, r.Files)
		}
		repos = append(repos, r)
	}
	return repos, nil
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
	r := Repo{NameWithOwner: n.NameWithOwner, IsFork: n.IsFork}
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

// WorkflowStates returns the state of each workflow GitHub has registered in
// repo, keyed by path: "active", "disabled_fork", "disabled_manually" and so
// on. Workflow files GitHub has never registered, e.g. in a fork where
// Actions was never enabled, have no entry.
func (c *Client) WorkflowStates(ctx context.Context, repo string) (map[string]string, error) {
	out := map[string]string{}
	for page := 1; ; page++ {
		var resp struct {
			TotalCount int `json:"total_count"`
			Workflows  []struct {
				Path  string `json:"path"`
				State string `json:"state"`
			} `json:"workflows"`
		}
		endpoint := fmt.Sprintf("repos/%s/actions/workflows?per_page=100&page=%d", repo, page)
		if err := c.rest.DoWithContext(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
			return nil, fmt.Errorf("list workflows of %s: %w", repo, err)
		}
		for _, w := range resp.Workflows {
			out[w.Path] = w.State
		}
		if len(resp.Workflows) == 0 || page*100 >= resp.TotalCount {
			return out, nil
		}
	}
}

// Refs implements fix.RefLister with batched GraphQL queries. Repositories
// that cannot be read have no entry.
func (c *Client) Refs(ctx context.Context, repos map[string][]string) (map[string]fix.RepoRefs, error) {
	names := make([]string, 0, len(repos))
	for r := range repos {
		names = append(names, r)
	}
	sort.Strings(names)
	out := map[string]fix.RepoRefs{}
	for start := 0; start < len(names); start += BatchSize {
		chunk := names[start:min(start+BatchSize, len(names))]
		var resp map[string]map[string]json.RawMessage
		err := c.do(ctx, tagsQuery(chunk, repos), nil, &resp)
		if _, err := notFound(err); err != nil {
			return nil, err
		}
		for i, r := range chunk {
			repo := resp[fmt.Sprintf("t%d", i)]
			if repo == nil {
				continue
			}
			var def *struct {
				Name   string `json:"name"`
				Target object `json:"target"`
			}
			var tags struct {
				Nodes []tagNode `json:"nodes"`
			}
			_ = json.Unmarshal(repo["defaultBranchRef"], &def)
			_ = json.Unmarshal(repo["refs"], &tags)
			var rr fix.RepoRefs
			if def != nil {
				rr.Default = fix.Tag{Name: def.Name, SHA: def.Target.OID}
			}
			for _, n := range tags.Nodes {
				rr.Tags = append(rr.Tags, fix.Tag{Name: n.Name, SHA: n.Target.commit()})
			}
			for j, name := range repos[r] {
				var head, tag *struct {
					Target object `json:"target"`
				}
				_ = json.Unmarshal(repo[fmt.Sprintf("b%d", j)], &head)
				_ = json.Unmarshal(repo[fmt.Sprintf("x%d", j)], &tag)
				if head != nil && tag == nil {
					if rr.Branches == nil {
						rr.Branches = map[string]string{}
					}
					rr.Branches[name] = head.Target.OID
				}
			}
			out[strings.ToLower(r)] = rr
		}
	}
	return out, nil
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
