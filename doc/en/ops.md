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
- Permission check failures with tokens: GitHub returns 401 (`Bad credentials`), 403 (`Resource not accessible by personal access token`), or 404 (`Not Found` for private/unknown repos). They are logged as `ERROR` and processing continues for other repos.
- Trivy missing: ensure `trivy` command is available before running.
