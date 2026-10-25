// Package cache keeps fetched files on disk. Content at a full commit SHA
// never changes, so those entries never expire. Files at a tag or branch,
// with the commit it points at, are kept for a short time, since tags and
// branches can move.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/conspirates/gh-gha-scan/internal/ref"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// Fetcher serves requests from Dir when it can and passes the rest to Inner.
type Fetcher struct {
	Inner scan.Fetcher
	Dir   string
	// TTL is how long an entry for a ref that is not a full commit SHA is
	// used. Zero means such refs are never cached.
	TTL time.Duration
	// Hits counts requests served from disk.
	Hits int

	now func() time.Time
}

// entry is what a cache file holds.
type entry struct {
	Stored time.Time    `json:"stored"`
	Res    scan.FileRes `json:"res"`
}

// DefaultDir returns the user cache directory for gh-gha-scan.
func DefaultDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gh-gha-scan"), nil
}

// version is part of every entry's name. Bump it when the meaning of a
// request or the FileRes format changes, so old entries are never read.
const version = "3"

// path names the entry for req. The paths looked up are part of the name,
// so a change in how candidates are chosen can't reuse an old answer.
func (f *Fetcher) path(key string, req scan.FileReq) string {
	id := fmt.Sprintf("%s\x00%s\x00%s\x00%v", version, key, strings.Join(req.Paths, "\x00"), req.Resolve)
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(f.Dir, hex.EncodeToString(sum[:])+".json")
}

// pinned reports whether req's answer can never change.
func pinned(req scan.FileReq) bool {
	return ref.IsFullSHA(req.Ref) && !req.Resolve
}

func (f *Fetcher) cacheable(req scan.FileReq) bool {
	return pinned(req) || f.TTL > 0
}

func (f *Fetcher) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// load returns the entry for req, unless it is missing or has expired.
func (f *Fetcher) load(key string, req scan.FileReq) (scan.FileRes, bool) {
	data, err := os.ReadFile(f.path(key, req))
	if err != nil {
		return scan.FileRes{}, false
	}
	var e entry
	if json.Unmarshal(data, &e) != nil {
		return scan.FileRes{}, false
	}
	if !pinned(req) && f.clock().Sub(e.Stored) >= f.TTL {
		return scan.FileRes{}, false
	}
	return e.Res, true
}

// Fetch implements scan.Fetcher.
func (f *Fetcher) Fetch(ctx context.Context, reqs map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	out := make(map[string]scan.FileRes, len(reqs))
	rest := map[string]scan.FileReq{}
	for k, req := range reqs {
		if f.cacheable(req) {
			if res, ok := f.load(k, req); ok {
				out[k] = res
				f.Hits++
				continue
			}
		}
		rest[k] = req
	}
	if len(rest) == 0 {
		return out, nil
	}

	got, err := f.Inner.Fetch(ctx, rest)
	for k, res := range got {
		out[k] = res
		// Only found files are kept. An inaccessible repository or a missing
		// file may be temporary, so those are asked again next time.
		if f.cacheable(rest[k]) && res.Found && res.Err == "" {
			write(f.Dir, f.path(k, rest[k]), entry{Stored: f.clock(), Res: res})
		}
	}
	return out, err
}

// Roots keeps the top-level workflow files of repositories by commit, for
// gh.Client.Roots. Files at a commit never change, so entries never expire.
type Roots struct {
	Dir string
	// Hits counts repositories served from disk.
	Hits atomic.Int64
}

func (r *Roots) path(repo, commit string) string {
	sum := sha256.Sum256([]byte(version + "\x00roots\x00" + strings.ToLower(repo) + "\x00" + commit))
	return filepath.Join(r.Dir, hex.EncodeToString(sum[:])+".json")
}

// Files returns the workflow files of repo at commit, if they are cached.
func (r *Roots) Files(repo, commit string) ([]scan.File, bool) {
	data, err := os.ReadFile(r.path(repo, commit))
	if err != nil {
		return nil, false
	}
	var files []scan.File
	if json.Unmarshal(data, &files) != nil {
		return nil, false
	}
	r.Hits.Add(1)
	return files, true
}

// StoreFiles caches the workflow files of repo at commit.
func (r *Roots) StoreFiles(repo, commit string, files []scan.File) {
	if files == nil {
		files = []scan.File{}
	}
	write(r.Dir, r.path(repo, commit), files)
}

// write stores v as JSON at path in dir, ignoring failures: the cache is only
// an optimization.
func write(dir, path string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, "tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
	}
}
