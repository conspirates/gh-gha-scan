# gh-gha-scan
Scans for insecure use of GitHub Actions.

`gh gha-scan` finds `uses:` references that are not pinned to a full-length commit SHA, so you can fix them before turning on GitHub's **"Require actions to be pinned to a full-length commit SHA"** policy. Composite actions and reusable workflows are followed transitively. An unpinned reference inside a pinned third-party action is reported too, because the policy breaks those workflows as well.

## Install

There's no release with prebuilt binaries yet, so build it from source. This needs Go 1.26.7 or later, which Go downloads automatically when the toolchain setting allows it.

```sh
git clone https://github.com/conspirates/gh-gha-scan
cd gh-gha-scan
go build -o gh-gha-scan .
gh extension install .
```

Once a release exists, `gh extension install conspirates/gh-gha-scan` will work too.

## Usage

```sh
gh gha-scan cli/cli                 # one repository (default branch)
gh gha-scan --owner cli             # every repository of an organization or user
gh gha-scan --local [path]          # a local checkout (default ".")
gh gha-scan --owner my-org --json | jq '.unpinned'
```

| Flag | |
|---|---|
| `--json` | Output findings, a summary of distinct unpinned refs, warnings and API stats as JSON |
| `--resolve` | Look up the commit SHA each unpinned ref currently points at |
| `--exit-code` | Exit 1 when unpinned refs are found (for CI) |
| `--depth N` | Follow transitive refs at most N levels deep (default 10) |
| `--include-archived`, `--include-forks` | Include archived repositories or forks with `--owner` (excluded by default) |
| `--no-cache` | Don't use the on-disk cache |

Each finding shows the repository, the workflow step the chain starts at, the unpinned ref, whether its owner differs from the repository's, and the chain of refs that led to it.

## What counts

- `owner/repo[/path]@ref` and `owner/repo/.github/workflows/x.yml@ref` are findings unless `ref` is a full 40-character SHA. Short SHAs, tags and branches all count.
- `./local` actions are not findings themselves, but they are read (from the default branch, or from disk with `--local`) and their nested refs are checked.
- `docker://` images are ignored, since the policy covers actions only.
- Only top-level `.github/workflows/*.yml` and `*.yaml` files are scanned, as GitHub only runs those.

## Cost

Everything goes through batched GraphQL. One query per page of 25 repositories returns the repositories together with all their workflow files, and transitive action files are fetched about 50 per query, one query per level of depth. Scanning the whole `cli` organization costs about 4 points of the 5000-per-hour GraphQL budget. Files at a full commit SHA never change, so they are cached on disk (`os.UserCacheDir()/gh-gha-scan`) and later runs reuse them.
