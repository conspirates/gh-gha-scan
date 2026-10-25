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
gh gha-scan --owner my-org --json | jq '.repositories[] | select(.items != [])'
```

| Flag | |
|---|---|
| `--json` | Output every repository with its items, fixes and the underlying findings, plus warnings and API stats, as JSON |
| `--exit-code` | Exit 1 when unpinned refs are found (for CI) |
| `--depth N` | Follow transitive refs at most N levels deep (default 10) |
| `--include-archived`, `--include-forks` | Include archived repositories or forks with `--owner` (excluded by default) |
| `--no-cache` | Don't use the on-disk cache |

## Output

One row per action a repository calls that has to change, and a `None` row for each scanned repository that is already fine:

```
REPOSITORY      UNPINNED ACTION                           FIX
cli/cli         None
cli/gh-webhook  actions/checkout@v5                       Pin to actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
example/app     cli/gh-extension-precompile@ee3e4e5 (v1)  Upgrade to cli/gh-extension-precompile@76961aa3bd1123d0a6fd42d0a41aca0696937c39 # v2.2.0 (major version change from v1)
```

**Unpinned action** is the reference as written in the repository's own workflows or local actions. When the unpinned ref is nested inside a dependency, the row names the dependency, because that's the line the repository can change. **Fix** is one of:

| Fix | When |
|---|---|
| Pin to `<action>@<sha> # <version>` | The ref itself is unpinned and everything it uses is pinned. The SHA is the commit the current version points at, so behavior doesn't change. |
| Upgrade to `<action>@<sha> # <version>` | The dependency uses unpinned refs, and its newest release (by version tag) is fully pinned. Marked when the major version changes. |
| Pin `<ref>` in `<file>`, then update this reference | The dependency belongs to the same owner, so the refs inside it can be pinned directly. |
| No fix upstream yet | Even the newest release still uses unpinned refs: fork it, replace it, or ask upstream to pin. |
| No verified fix | Part of the newest release couldn't be read, so it isn't known to be fully pinned. The warnings say what failed. |

A repository shows `None (incomplete, see warnings)` instead of `None` when some refs couldn't be read or were beyond `--depth`, so it isn't known to be fine. The summary, warnings and API cost go to stderr. When piped, the table is tab-separated without a header. `--json` also gives each item's file and line, and the full chain of findings behind it.

## What counts

- `owner/repo[/path]@ref` and `owner/repo/.github/workflows/x.yml@ref` are findings unless `ref` is a full 40-character SHA. Short SHAs, tags and branches all count.
- `./local` actions are not findings themselves, but they are read (from the default branch, or from disk with `--local`) and their nested refs are checked.
- `docker://` images are ignored, since the policy covers actions only.
- Only top-level `.github/workflows/*.yml` and `*.yaml` files are scanned, as GitHub only runs those.

## Cost

Everything goes through batched GraphQL. One query per page of 25 repositories returns the repositories together with all their workflow files, and transitive action files are fetched about 50 per query, one query per level of depth. Finding upgrades adds one query for the tags of the affected dependencies and a scan of their newest releases. Scanning the whole `cli` organization costs about 4 points of the 5000-per-hour GraphQL budget. Files at a full commit SHA never change, so they are cached on disk (`os.UserCacheDir()/gh-gha-scan`) and later runs reuse them.
