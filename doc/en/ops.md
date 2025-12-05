# Ops Notes (EN)

## Performance
- `--gh-parallelism` controls clone/permission parallelism.
- `--trivy-parallelism` controls repo-level scan parallelism (branches are sequential).
- Many branches per repo can be slow; consider future extension to limit target branches.

## Disk
- `--clear-work-dir` removes clone dirs after each repo. `<out>/results` is wiped at start (default base: current directory).

## Logs
- If Trivy logs are too verbose, consider future flags in `trivy_runner` (e.g., `--quiet`, `--scanners vuln`).
- Permission/clone/checkout failures mark repos as failed and emit warnings.

## Troubleshooting
- `index.lock` conflicts: avoided by sequential branch processing; if it persists, manually remove `.git/index.lock`.
- `repository not found`: check `repos.json` names or credentials.
- Permission check failures:
  - Tokenless: `git ls-remote --heads` is used. Missing access returns stderr (e.g., `Repository not found` / `Invalid username or token`) and the repo is skipped; other repos continue.
  - Token: GitHub REST `/repos/{owner}/{repo}` with Authorization header. 401/403/404 are logged as `ERROR`; repo is skipped; processing continues.
- Trivy missing: ensure `trivy` command is available before running.
