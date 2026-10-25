# gh-gha-scan
Scans for insecure use of GitHub Actions.

`gh gha-scan` finds `uses:` references that are not pinned to a full-length commit SHA, so you can fix them before turning on GitHub's **"Require actions to be pinned to a full-length commit SHA"** policy. Composite actions and reusable workflows are followed transitively. An unpinned reference inside a pinned third-party action is reported too, because the policy breaks those workflows as well.

## Install

```sh
gh extension install conspirates/gh-gha-scan
```

Each release includes prebuilt binaries with signed build provenance. To check one, run `gh attestation verify <binary> -R conspirates/gh-gha-scan`.

To build from source instead, you need Go 1.26.10 or later, which Go downloads automatically when the toolchain setting allows it.

```sh
git clone https://github.com/conspirates/gh-gha-scan
cd gh-gha-scan
go build -o gh-gha-scan .
gh extension install .
```

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
| `--exit-code` | Set the exit status from the result, for CI (see [Exit status](#exit-status)) |
| `--depth N` | Follow transitive refs at most N levels deep (default 10) |
| `--include-archived`, `--include-forks` | Include archived repositories or forks with `--owner` (excluded by default; the summary says how many forks were skipped) |
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
| Upgrade to `<action>@<sha> # <version>` | The dependency uses unpinned refs, and its newest release (by version tag) is fully pinned. This applies to dependencies of the same owner too. Marked when the major version changes. |
| Release `<action>` from `<branch>` at `<sha>`, then upgrade to it | A same-owner dependency's newest release isn't fully pinned, but its default branch is, so it only needs a release. |
| Pin `<ref>` in `<file>:<line> on <branch>`, then update this reference | A same-owner dependency is fully pinned in neither its newest release nor its default branch, so the refs inside it have to be pinned. The locations are on its default branch, where the edit goes. When the unpinned ref is inside a third-party action that the dependency calls, the step is instead to upgrade that action there, or there's no fix upstream yet. |
| No fix upstream yet | Even the newest release still uses unpinned refs: fork it, replace it, or ask upstream to pin. |
| No verified fix | Part of the newest release couldn't be read, so it isn't known to be fully pinned. The warnings say what failed. |

A repository shows `None (incomplete, see warnings)` instead of `None` when some refs couldn't be read, couldn't be parsed or were beyond `--depth`, so it isn't known to be fine. The summary, warnings and API cost go to stderr. When piped, the table is tab-separated without a header. `--json` also gives each item's file and line, and the full chain of findings behind it. For each finding:
- `external` says whether the unpinned action belongs to another owner;
- `source_owner` and `source_external` say who owns the file it's written in;
- `boundary` is the reference to change to fix it, in a file the repository's owner controls.

## Exit status

| Status | Meaning |
|---|---|
| 0 | Success. With `--exit-code`: everything was checked and nothing is unpinned. |
| 1 | With `--exit-code`: unpinned refs were found, whether or not the scan is also incomplete. |
| 2 | With `--exit-code`: nothing unpinned was found, but some repositories are incomplete (see the warnings), so the result isn't known to be clean. |
| 3 | The scan failed, e.g. invalid arguments or an API error. |

Without `--exit-code`, a scan that runs exits 0 whatever it finds.

## Rolling out the policy

1. Scan the organization, including forks whose workflows run:
   ```sh
   gh gha-scan --owner my-org --include-forks --exit-code
   ```
2. Apply the Fix column, and resolve every warning behind a `None (incomplete, see warnings)`. For "No fix upstream yet", fork the action, replace it, or ask upstream to pin.
3. Scan again once the fixes are on the default branches. Continue only when it exits **0**: exit 2 means part of the organization isn't known to be safe.
4. Turn the policy on for a few repositories first. It can be set per repository (Settings → Actions → General) as well as for the organization. Good pilots are repositories whose fixes were inside composite actions or reusable workflows.
5. Turn it on for the organization. To roll back, turn the setting off.

A blocked workflow fails when its run starts. Push and pull request workflows show problems right away, but scheduled, release and `workflow_dispatch` workflows only fail at their next run, so rely on a clean scan rather than on nothing having failed yet. Once the policy is on, GitHub rejects any new unpinned ref by itself.

## What counts

- `owner/repo[/path]@ref` and `owner/repo/.github/workflows/x.yml@ref` are findings unless `ref` is a full 40-character SHA. Short SHAs, tags and branches all count.
- `./local` actions are not findings themselves, but they are read (from the default branch, or from disk with `--local`) and their nested refs are checked.
- `$/path` refs (same repository, at the running commit) aren't findings either. They're read from the repository of the file they're written in: the scanned repository itself, or the dependency at the ref it was called with. A `$/` ref with `@ref` is invalid.
- `docker://` images are ignored, since the policy covers actions only.
- Only top-level `.github/workflows/*.yml` and `*.yaml` files are scanned, as GitHub only runs those.
- Only each repository's default branch is scanned. A workflow that runs from another branch, e.g. a long-lived release branch, may still use unpinned refs; scan that branch's checkout with `--local`.
- A fork used as an action or reusable workflow is always followed, like any other dependency. `--include-forks` only decides whether a fork's own workflows are scanned.
- With `--include-forks`, a fork's workflow files are only scanned if GitHub would run them: their state must be `active`. Files in a fork where Actions was never enabled aren't registered at all and are skipped too. Skipped files are listed with their state, e.g. `disabled_fork` or `not_registered`. This costs one REST call per fork.

## Cost

Everything goes through batched GraphQL. With `--owner`, one query per 100 repositories lists them with their default branch commits. Workflow files are then read 25 repositories per query, only for commits not already cached. Transitive action files are fetched about 50 per query, one query per level of depth, with up to 4 queries running at once. Finding upgrades adds one query for the tags of the affected dependencies and a scan of their newest releases. Scanning the whole `cli` organization costs about 4 points of the 5000-per-hour GraphQL budget. Files at a full commit SHA never change, so they are cached on disk (`os.UserCacheDir()/gh-gha-scan`) and later runs reuse them. That includes each repository's workflow files at its default branch commit, so an unchanged repository costs nothing beyond the listing. Files at a tag or branch are cached with the commit it points at for an hour, so a moved tag is noticed within an hour, or right away with `--no-cache`.
