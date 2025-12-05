# vulvul-gh-trivy-scanner

Scan multiple GitHub repositories with Trivy and flatten all packages/vulnerabilities to CSV. Supports local runs and GitHub Actions.

- Docs: see `doc/en/` (API, logic, ops). Japanese docs are in `doc/jp/`.
- Package: `src/vulvul_gh_trivy_scanner/`
- CLI: `vulvul-scan` (Poetry console_scripts)

## Quickstart
```bash
pip install .
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

## License
See LICENSE.
