# Ops Notes (EN)

## Performance
- `--gh-parallelism` controls clone/permission parallelism.
- `--trivy-parallelism` controls repo-level scan parallelism (branches are sequential).
- Many branches per repo can be slow; consider future extension to limit target branches.

## Disk
- `--clear-work-dir` removes clone dirs after each repo. `--out` is wiped at start.

## Logs
- If Trivy logs are too verbose, consider future flags in `trivy_runner` (e.g., `--quiet`, `--scanners vuln`).
- Permission/clone/checkout failures mark repos as failed and emit warnings.

## Troubleshooting
- `index.lock` conflicts: avoided by sequential branch processing; if it persists, manually remove `.git/index.lock`.
- `repository not found`: check `repos.json` names or credentials.
- Trivy missing: ensure `trivy` command is available before running.
