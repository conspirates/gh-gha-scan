// Package cache keeps files fetched at a full commit SHA on disk. Content at a
// commit never changes, so these entries never expire.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/conspirates/gh-gha-scan/internal/ref"
	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// Fetcher serves pinned requests from Dir and passes the rest to Inner.
type Fetcher struct {
	Inner scan.Fetcher
	Dir   string
	// Hits counts requests served from disk.
	Hits int
}

// DefaultDir returns the user cache directory for gh-gha-scan.
func DefaultDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gh-gha-scan"), nil
}

func (f *Fetcher) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(f.Dir, hex.EncodeToString(sum[:])+".json")
}

func cacheable(req scan.FileReq) bool {
	return ref.IsFullSHA(req.Ref) && !req.Resolve
}

// Fetch implements scan.Fetcher.
func (f *Fetcher) Fetch(ctx context.Context, reqs map[string]scan.FileReq) (map[string]scan.FileRes, error) {
	out := make(map[string]scan.FileRes, len(reqs))
	rest := map[string]scan.FileReq{}
	for k, req := range reqs {
		if cacheable(req) {
			if data, err := os.ReadFile(f.path(k)); err == nil {
				var res scan.FileRes
				if json.Unmarshal(data, &res) == nil {
					out[k] = res
					f.Hits++
					continue
				}
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
		// Errors such as an inaccessible repository may be temporary.
		if cacheable(rest[k]) && res.Err == "" {
			f.store(k, res)
		}
	}
	return out, err
}

// store writes an entry, ignoring failures: the cache is only an optimization.
func (f *Fetcher) store(key string, res scan.FileRes) {
	data, err := json.Marshal(res)
	if err != nil {
		return
	}
	if err := os.MkdirAll(f.Dir, 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(f.Dir, "tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), f.path(key)); err != nil {
		os.Remove(tmp.Name())
	}
}
