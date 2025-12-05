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
  --out results \
  --gh-parallelism 4 \
  --trivy-parallelism 2 \
  --clear-work-dir
```

## Structure
- `src/vulvul_gh_trivy_scanner/`: implementation (DTOs, Trivy runner, GitHub access, CLI)
- `config/repos.json`: target repos (owner → [repo, ...])
- `doc/en/`, `doc/jp/`: usage, API, logic, ops
- `test/unit/`: unit tests
- `results/`: outputs (not tracked)

## Outputs
- `packages.csv`: owner, repo, branch, commit_hash, package, version
- `vuls.csv`: owner, repo, branch, commit_hash, file_path, vulnerability, package, version, fixed_version

## License
See LICENSE.
