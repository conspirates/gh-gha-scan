// Command gh-gha-scan is a gh extension that finds GitHub Actions references
// that are not pinned to a full commit SHA, including transitive ones.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/cli/go-gh/v2/pkg/term"
	"github.com/spf13/cobra"

	"github.com/conspirates/gh-gha-scan/internal/cache"
	"github.com/conspirates/gh-gha-scan/internal/gh"
	"github.com/conspirates/gh-gha-scan/internal/report"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

type options struct {
	owner           string
	local           bool
	json            bool
	depth           int
	includeArchived bool
	includeForks    bool
	resolve         bool
	exitCode        bool
	noCache         bool
}

// errFindings makes the command exit 1 without printing an error.
var errFindings = errors.New("unpinned references found")

func main() {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "gha-scan [<owner>/<repo> | --owner <login> | --local [<path>]]",
		Short: "Find GitHub Actions references not pinned to a full commit SHA",
		Long: `Find uses: references that are not pinned to a full-length commit SHA, as
required by GitHub's "Require actions to be pinned to a full-length commit SHA"
policy. Composite actions and reusable workflows are followed transitively, so
unpinned references inside pinned third-party actions are reported too.`,
		Example: `  gh gha-scan cli/cli
  gh gha-scan --owner cli
  gh gha-scan --local .
  gh gha-scan --owner my-org --json | jq '.unpinned'`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), opts, args)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.owner, "owner", "", "scan all repositories of an organization or user")
	f.BoolVar(&opts.local, "local", false, "scan a local checkout at <path> (default \".\")")
	f.BoolVar(&opts.json, "json", false, "output JSON")
	f.IntVar(&opts.depth, "depth", 10, "maximum depth of transitive references to follow")
	f.BoolVar(&opts.includeArchived, "include-archived", false, "include archived repositories with --owner")
	f.BoolVar(&opts.includeForks, "include-forks", false, "include forks with --owner")
	f.BoolVar(&opts.resolve, "resolve", false, "look up the commit SHA for each unpinned reference")
	f.BoolVar(&opts.exitCode, "exit-code", false, "exit with status 1 when unpinned references are found")
	f.BoolVar(&opts.noCache, "no-cache", false, "do not use the on-disk cache for pinned references")

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		if !errors.Is(err, errFindings) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, opts *options, args []string) error {
	switch {
	case opts.local && opts.owner != "":
		return errors.New("--local and --owner cannot be combined")
	case opts.owner != "" && len(args) > 0:
		return errors.New("--owner takes no <owner>/<repo> argument")
	case !opts.local && opts.owner == "" && len(args) == 0:
		return errors.New("specify <owner>/<repo>, --owner, or --local")
	}
	if opts.depth < 1 {
		return errors.New("--depth must be at least 1")
	}

	client, err := gh.New()
	if err != nil {
		return err
	}

	var roots []scan.Root
	switch {
	case opts.owner != "":
		repos, err := client.OwnerRepos(ctx, opts.owner, opts.includeArchived, opts.includeForks)
		if err != nil {
			return err
		}
		for _, r := range repos {
			roots = append(roots, remoteRoot(r))
		}
	case opts.local:
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		root, err := localRoot(dir)
		if err != nil {
			return err
		}
		roots = append(roots, root)
	default:
		owner, name, ok := strings.Cut(args[0], "/")
		if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
			return fmt.Errorf("expected <owner>/<repo>, got %q", args[0])
		}
		r, err := client.Repo(ctx, owner, name)
		if err != nil {
			return err
		}
		roots = append(roots, remoteRoot(r))
	}

	var fetcher scan.Fetcher = client
	var cached *cache.Fetcher
	if !opts.noCache {
		if dir, err := cache.DefaultDir(); err == nil {
			cached = &cache.Fetcher{Inner: client, Dir: dir}
			fetcher = cached
		}
	}

	s := &scan.Scanner{Fetcher: fetcher, Depth: opts.depth, Resolve: opts.resolve}
	res, err := s.Scan(ctx, roots)
	if err != nil {
		return err
	}

	stats := client.Stats()
	if opts.json {
		if err := report.JSON(os.Stdout, res, len(roots), stats); err != nil {
			return err
		}
	} else {
		t := term.FromEnv()
		width, _, _ := t.Size()
		if len(res.Findings) > 0 {
			if err := report.Table(t.Out(), res.Findings, t.IsTerminalOutput(), width); err != nil {
				return err
			}
		}
		report.Summary(t.ErrOut(), res, len(roots))
		msg := "\nAPI: no GraphQL queries"
		if stats.Queries > 0 {
			msg = fmt.Sprintf("\nAPI: %d GraphQL queries, %d points used, %d remaining", stats.Queries, stats.Cost, stats.Remaining)
		}
		if cached != nil && cached.Hits > 0 {
			msg += fmt.Sprintf(", %d cached files", cached.Hits)
		}
		fmt.Fprintln(t.ErrOut(), msg)
	}

	if opts.exitCode && len(res.Findings) > 0 {
		return errFindings
	}
	return nil
}

func remoteRoot(r gh.Repo) scan.Root {
	owner, _, _ := strings.Cut(r.NameWithOwner, "/")
	return scan.Root{
		Name:    r.NameWithOwner,
		Owner:   owner,
		Files:   r.Files,
		Repo:    r.NameWithOwner,
		HeadOID: r.HeadOID,
	}
}

// localRoot reads the workflow files of a checkout. The owner comes from the
// origin remote, when there is one.
func localRoot(dir string) (scan.Root, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return scan.Root{}, err
	}
	root := scan.Root{Name: dir}
	if out, err := exec.Command("git", "-C", abs, "remote", "get-url", "origin").Output(); err == nil {
		if r, err := repository.Parse(strings.TrimSpace(string(out))); err == nil {
			root.Owner = r.Owner
		}
	}

	wfDir := filepath.Join(abs, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil && !os.IsNotExist(err) {
		return scan.Root{}, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && (strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml")) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(wfDir, n))
		if err != nil {
			return scan.Root{}, err
		}
		root.Files = append(root.Files, scan.File{Path: ".github/workflows/" + n, Text: string(data)})
	}

	root.ReadLocal = func(p string) ([]byte, error) {
		full := filepath.Join(abs, filepath.FromSlash(p))
		if rel, err := filepath.Rel(abs, full); err != nil || strings.HasPrefix(rel, "..") {
			return nil, fmt.Errorf("%s is outside the checkout", p)
		}
		return os.ReadFile(full)
	}
	return root, nil
}
