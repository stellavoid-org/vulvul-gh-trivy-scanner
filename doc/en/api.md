# API / CLI Reference (EN)

## CLI: `vulvul-scan`
Provided via Poetry console_scripts. Calls `vulvul_gh_trivy_scanner.main_portable.main`.

### Arguments
- `--repos` (required): Path to repos JSON (owner -> [repo, ...])
- `--out` (optional, default current dir): Base output directory. `<out>/results` is cleared and used for CSVs/artifacts.
- `--gh-parallelism` (optional, default 4): Parallelism for GitHub permission checks and clones.
- `--trivy-parallelism` (optional, default 2): Parallelism across repositories for scanning (branches within a repo are sequential).
- `--clear-work-dir` (flag): Remove cloned work dirs after processing.

### Config (`repos.json`)
Supports optional tokens via env var names. Repo tokens override org tokens; no fallback is attempted if env vars are missing.

```bash
export ORG_TOKEN="org-pat"
export REPO_TOKEN="repo-pat"
```

```json
{
  "repos": {
    "owner_name": {
      "org_token_name": "ORG_TOKEN",         // optional
      "repos": [
        "public_repo",
        { "repo_name": "private_repo", "repo_token_name": "REPO_TOKEN" } // optional
      ]
    }
  }
}
```
Legacy form (`"owner": ["repo1", ...]`) is still accepted.

Tokenless runs: permission check is done via `git ls-remote` (no REST). If your credential helper/SSH has access, clone will work; otherwise ls-remote fails fast and the repo is skipped.

### Outputs
- `packages.csv`: `owner,repo,branch,commit_hash,package,version`
- `vuls.csv`: `owner,repo,branch,commit_hash,file_path,vulnerability,package,version,fixed_version`

### Example
```bash
vulvul-scan \
  --repos config/repos.json \
  --out out_dir \
  --gh-parallelism 5 \
  --trivy-parallelism 5 \
  --clear-work-dir
```

## Python Modules
- `vulvul_gh_trivy_scanner.get_vuls.get_vuls(repos, gh_parallelism, trivy_parallelism, out_root, clear_work_dir)`  
  Returns (success_repos, failed_repos) after scanning.
- DTOs: `models_repo.GHRepository`, `models_vuln.Package`, `models_vuln.Vul`
- Runner: `trivy_runner.run_trivy_fs(target_dir, output_json)`
- GitHub Access: `api.GHAccessWithThrottling` (semaphore-controlled permission check and clone hooks)
