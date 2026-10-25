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
	"strings"

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

// version is part of every entry's name. Bump it when the meaning of a
// request or the FileRes format changes, so old entries are never read.
const version = "2"

// path names the entry for req. The paths looked up are part of the name,
// so a change in how candidates are chosen can't reuse an old answer.
func (f *Fetcher) path(key string, req scan.FileReq) string {
	id := version + "\x00" + key + "\x00" + strings.Join(req.Paths, "\x00")
	sum := sha256.Sum256([]byte(id))
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
			if data, err := os.ReadFile(f.path(k, req)); err == nil {
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
		// Only found files are kept. An inaccessible repository or a missing
		// file may be temporary, so those are asked again next time.
		if cacheable(rest[k]) && res.Found && res.Err == "" {
			f.store(f.path(k, rest[k]), res)
		}
	}
	return out, err
}

// store writes an entry, ignoring failures: the cache is only an optimization.
func (f *Fetcher) store(path string, res scan.FileRes) {
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
	}
}
