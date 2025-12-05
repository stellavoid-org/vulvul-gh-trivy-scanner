# vulvul-gh-trivy-scanner

Scan multiple GitHub repositories with Trivy and flatten all packages/vulnerabilities to CSV. Supports local runs and GitHub Actions.

- Docs: see `doc/en/` (API, logic, ops). Japanese docs are in `doc/jp/`.
- Package: `src/vulvul_gh_trivy_scanner/`
- CLI: `vulvul-scan` (Poetry console_scripts)

## Quickstart
```bash
pip install .
# Tokens (optional, repo token overrides org token, no fallback if missing)
# export ORG_TOKEN="xxx"   # org token
# export REPO_TOKEN="yyy"  # repo token (overrides org token)
vulvul-scan \
  --repos config/repos.json \
  --gh-parallelism 4 --trivy-parallelism 2 --clear-work-dir
```
By default outputs land in `./results`; override with `--out <dir>` to use `<dir>/results`.

## Structure
- `src/vulvul_gh_trivy_scanner/`: implementation (DTOs, Trivy runner, GitHub access, CLI)
- `config/repos.json`: target repos (owner → [repo, ...])
- `doc/en/`, `doc/jp/`: usage, API, logic, ops
- `test/unit/`: unit tests
- Default output path: `./results` (not tracked)

## Outputs
- `packages.csv`: owner, repo, branch, commit_hash, package, version
- `vuls.csv`: owner, repo, branch, commit_hash, file_path, vulnerability, package, version, fixed_version

## Config with optional tokens
```json
{
  "repos": {
    "your-org": {
      "org_token_name": "ORG_TOKEN",   // optional
      "repos": [
        "public-repo",
        {
          "repo_name": "private-repo",
          "repo_token_name": "REPO_TOKEN",  // optional, overrides org token
          "all_branches": false,
          "branch_regexes": ["main", "release/.*"], // required if all_branches=false
          "scan_default_branch": true               // ensure default branch is included
        }
      ]
    }
  }
}
```
Legacy form (`"owner": ["repo1", ...]`) still works.

Tokenless runs: permission check uses `git ls-remote` (no REST). If your credential helper/SSH has access, clone will work; missing access will fail fast with stderr logged. Tokens are the only time non-interactive (`GIT_TERMINAL_PROMPT=0`) is enforced.

## License
See LICENSE.
