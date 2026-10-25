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
	// Retries counts requests retried after a transport failure, a server
	// error or a rate limit, and RetryWait is the total time spent waiting
	// for them.
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

	retry *retryTransport
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
	// Err says why the workflow files could not all be read.
	Err string
}

// New returns a client authenticated the way gh is.
func New() (*Client, error) {
	return newClient(http.DefaultTransport, api.ClientOptions{})
}

// newClient returns a client whose requests go through base, with retries.
// Empty opts fields default the way gh's do.
func newClient(base http.RoundTripper, opts api.ClientOptions) (*Client, error) {
	c := &Client{Concurrency: 4}
	c.retry = newRetryTransport(base, func(wait time.Duration) {
		c.mu.Lock()
		c.stats.Retries++
		c.stats.RetryWait += wait
		c.mu.Unlock()
	})
	opts.Transport = c.retry
	gql, err := api.NewGraphQLClient(opts)
	if err != nil {
		return nil, err
	}
	opts.Headers = map[string]string{"Accept": "application/vnd.github.raw+json"}
	rest, err := api.NewRESTClient(opts)
	if err != nil {
		return nil, err
	}
	c.gql, c.rest = gql, rest
	return c, nil
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

// do runs a query and tracks the rate limit. GraphQL errors are returned
// together with the partial data in out.
func (c *Client) do(ctx context.Context, query string, vars map[string]any, out any) error {
	c.mu.Lock()
	if c.known && c.stats.Remaining < minRemaining {
		c.mu.Unlock()
		return fmt.Errorf("GraphQL rate limit nearly exhausted (%d points left), resets at %s", c.stats.Remaining, c.stats.ResetAt)
	}
	c.mu.Unlock()

	var data map[string]json.RawMessage
	err := c.gql.DoWithContext(ctx, query, vars, &data)

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

// workflowsBatch reads one batch, in halves if GitHub rejects it whole. A
// repository deleted since it was listed has no entry; one that can't be
// read has Err set.
func (c *Client) workflowsBatch(ctx context.Context, nodes []repoNode) ([]Repo, error) {
	run := func(nodes []repoNode) ([]Repo, error) {
		var resp map[string]*struct {
			Object json.RawMessage `json:"object"`
		}
		errs, err := aliasErrors(c.do(ctx, workflowsQuery(nodes), nil, &resp))
		if err != nil {
			return nil, err
		}
		var repos []Repo
		for i, n := range nodes {
			alias := fmt.Sprintf("r%d", i)
			got := resp[alias]
			if got == nil {
				if e, ok := errs[alias]; ok && e.typ != "NOT_FOUND" {
					repos = append(repos, failedRepo(n, errors.New(e.message(ownerOf(n.NameWithOwner)))))
				}
				continue
			}
			if len(got.Object) > 0 {
				if err := json.Unmarshal(got.Object, &n.Object); err != nil {
					return nil, err
				}
			}
			r := c.repo(ctx, n)
			if c.Roots != nil && r.Err == "" {
				c.Roots.StoreFiles(r.NameWithOwner, r.HeadOID, r.Files)
			}
			repos = append(repos, r)
		}
		return repos, nil
	}
	return inHalves(nodes, run, failedRepo)
}

// failedRepo is n with the reason its workflow files couldn't be read.
func failedRepo(n repoNode, err error) Repo {
	return Repo{NameWithOwner: n.NameWithOwner, IsFork: n.IsFork, HeadOID: n.oid(), Err: err.Error()}
}

func ownerOf(nameWithOwner string) string {
	owner, _, _ := strings.Cut(nameWithOwner, "/")
	return owner
}

// Repo returns one repository with its workflow files.
func (c *Client) Repo(ctx context.Context, owner, name string) (Repo, error) {
	var resp struct {
		Repository *repoNode `json:"repository"`
	}
	errs, err := aliasErrors(c.do(ctx, repoQuery, map[string]any{"owner": owner, "name": name}, &resp))
	if err != nil {
		return Repo{}, err
	}
	if resp.Repository == nil {
		if e, ok := errs["repository"]; ok && e.typ != "NOT_FOUND" {
			return Repo{}, fmt.Errorf("%s/%s: %s", owner, name, e.message(owner))
		}
		return Repo{}, fmt.Errorf("repository %s/%s not found", owner, name)
	}
	return c.repo(ctx, *resp.Repository), nil
}

// repo reads n's workflow files. A file that can't be read sets Err; the
// others are still returned.
func (c *Client) repo(ctx context.Context, n repoNode) Repo {
	r := Repo{NameWithOwner: n.NameWithOwner, IsFork: n.IsFork}
	if n.DefaultBranchRef != nil {
		r.HeadOID = n.DefaultBranchRef.Target.OID
	}
	if n.Object == nil {
		return r
	}
	for _, e := range n.Object.Entries {
		// GitHub only runs workflow files directly in .github/workflows.
		if e.Type != "blob" || !(strings.HasSuffix(e.Name, ".yml") || strings.HasSuffix(e.Name, ".yaml")) || e.Object == nil || e.Object.IsBinary {
			continue
		}
		p := ".github/workflows/" + e.Name
		text, err := c.text(ctx, n.NameWithOwner, r.HeadOID, p, e.Object)
		if err != nil {
			if r.Err == "" {
				r.Err = err.Error()
			}
			continue
		}
		r.Files = append(r.Files, scan.File{Path: p, Text: text})
	}
	return r
}

// text returns a blob's text, falling back to REST for blobs GraphQL truncated.
func (c *Client) text(ctx context.Context, repo, commit, p string, b *blob) (string, error) {
	if b.Text != nil && !b.IsTruncated {
		return *b.Text, nil
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	endpoint := fmt.Sprintf("repos/%s/contents/%s?ref=%s", repo, strings.Join(segs, "/"), url.QueryEscape(commit))
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
	type result struct {
		repo string
		refs *fix.RepoRefs
	}
	run := func(chunk []string) ([]result, error) {
		var resp map[string]map[string]json.RawMessage
		if _, err := aliasErrors(c.do(ctx, tagsQuery(chunk, repos), nil, &resp)); err != nil {
			return nil, err
		}
		var out []result
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
			out = append(out, result{r, &rr})
		}
		return out, nil
	}
	out := map[string]fix.RepoRefs{}
	for start := 0; start < len(names); start += BatchSize {
		got, err := inHalves(names[start:min(start+BatchSize, len(names))], run, func(r string, _ error) result { return result{repo: r} })
		if err != nil {
			return nil, err
		}
		for _, g := range got {
			if g.refs != nil {
				out[strings.ToLower(g.repo)] = *g.refs
			}
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

// fetchBatch reads one batch, in halves if GitHub rejects it whole. A
// repository or file that can't be read fails only its own request.
func (c *Client) fetchBatch(ctx context.Context, keys []string, all map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	type result struct {
		key string
		res scan.FileRes
	}
	run := func(keys []string) ([]result, error) {
		reqs := make([]scan.FileReq, len(keys))
		for i, k := range keys {
			reqs[i] = all[k]
		}
		var resp map[string]json.RawMessage
		errs, err := aliasErrors(c.do(ctx, batchQuery(reqs), nil, &resp))
		if err != nil {
			return nil, err
		}
		out := make([]result, len(keys))
		for i, k := range keys {
			req, alias := reqs[i], fmt.Sprintf("r%d", i)
			out[i].key = k
			var objs map[string]json.RawMessage
			if raw := resp[alias]; len(raw) > 0 {
				_ = json.Unmarshal(raw, &objs)
			}
			if objs == nil {
				out[i].res = scan.FileRes{Err: errs[alias].message(req.Owner)}
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
					res = scan.FileRes{Err: err.Error()}
					break
				}
				res = scan.FileRes{Found: true, Path: p, Text: text}
				break
			}
			if req.Resolve {
				var o *object
				_ = json.Unmarshal(objs["c"], &o)
				res.SHA = o.commit()
			}
			out[i].res = res
		}
		return out, nil
	}
	failed := func(k string, err error) result { return result{k, scan.FileRes{Err: err.Error()}} }
	got, err := inHalves(keys, run, failed)
	if err != nil {
		return nil, err
	}
	out := make(map[string]scan.FileRes, len(got))
	for _, g := range got {
		out[g.key] = g.res
	}
	return out, nil
}
