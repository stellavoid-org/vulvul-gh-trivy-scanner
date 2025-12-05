# Logic Overview (EN)

## Flow
1. Load config (`repos.json`) and build `GHRepository` list (repo token > org token > no token; env var missing => tokenless, no fallback). Branch selection: `all_branches=true` scans all; `all_branches=false` filters remote branches by `branch_regexes` and optionally includes the default branch.
2. Permission check in parallel via `GHAccessWithThrottling.get_permissions` (Tokenless: `git ls-remote`; Token: GitHub API `/repos/{owner}/{repo}`; failures log ERROR and mark repo inaccessible).
3. Clone accessible repos in parallel; set `work_dir`.
4. List branches via `git branch -r` (excluding `origin/HEAD`); fallback to `["main"]`.
5. Scan: repositories run in parallel; within a repo, branches run sequentially (`checkout -> rev-parse -> trivy fs --list-all-pkgs -> parse`).
6. Aggregate into `packages.csv` / `vuls.csv` under `<out>/results`; delete work dirs if `--clear-work-dir`.

## Concurrency Model
- Across repos: clone/scan in parallel (gh_parallelism/trivy_parallelism).
- Within a repo: branches are sequential to avoid git checkout conflicts.

## Components
- `GHAccessWithThrottling`: semaphore-controlled permission/clone hooks; `_request_repo` is overridable for real API calls.
-, `trivy_runner`: thin wrapper over `trivy fs --format json --list-all-pkgs`.
- `parse_trivy_json`: converts Results[].Packages/Vulnerabilities to DTOs; attaches branch/commit info.
- `infra.dump_json/dump_csv`: output helpers.

## DTOs
- `Package`: id, name, version, purl/uid, ecosystem, manager, path, branch, commit_hash, depends_on_ids
- `Vul`: file_path, vulnerability_id, severity, pkg info, installed_version, fixed_version (string), branch, commit_hash, raw
- `GHRepository`: owner/repo, branches, work_dir/out_dir, packages/vulnerabilities, access state

## Cleanup
- `<out>/results` is cleared at start (default base is current directory).
- `--clear-work-dir` deletes cloned work dirs after each repo is processed.
