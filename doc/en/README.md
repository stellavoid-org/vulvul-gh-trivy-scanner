# vulvul-gh-trivy-scanner docs (EN)

High-level documentation index. See other files in this directory for details.

## Purpose
Scan multiple GitHub repositories with `trivy fs --list-all-pkgs`, then aggregate packages and vulnerabilities into CSV outputs. Designed for both local (portable) execution and GitHub Actions.

## Key documents
- `api.md`: CLI interface, arguments, outputs, config format.
- `logic.md`: Processing flow, concurrency model, component roles.
- `ops.md`: Operational tips (performance, logs, cleanup).

## Quick usage
```bash
pip install .
vulvul-scan --repos config/repos.json --out results --gh-parallelism 4 --trivy-parallelism 2 --clear-work-dir
```
If `--out` is omitted, outputs go to `./results`. Any path given to `--out` will contain the `results/` subdir for CSVs and artifacts.

## Outputs
- `packages.csv`: owner, repo, branch, commit_hash, package, version
- `vuls.csv`: owner, repo, branch, commit_hash, file_path, vulnerability, package, version, fixed_version

## Config example
```json
{
  "repos": {
    "owner1": {
      "org_token_name": "ORG_TOKEN", // optional
      "repos": [
        "repoA",
        { "repo_name": "private-repo", "repo_token_name": "REPO_TOKEN" } // optional
      ]
    },
    "owner2": ["repoC"]
  }
}
```
