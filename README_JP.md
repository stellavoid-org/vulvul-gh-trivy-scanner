# vulvul-gh-trivy-scanner

GitHub上の複数リポをTrivyでスキャンし、全パッケージ/脆弱性をCSVにまとめるツールです。ローカル実行とGitHub Actions実行を想定しています。

- ドキュメント: 詳細は `doc/jp/` を参照（API、ロジック概要、運用メモ）。
- パッケージ: `src/vulvul_gh_trivy_scanner/`
- CLI: `vulvul-scan`（Poetryのconsole_scripts）

## クイックスタート
```bash
pip install .
vulvul-scan \
  --repos config/repos.json \
  --gh-parallelism 4 --trivy-parallelism 2 --clear-work-dir
```
`--out` 未指定時はカレント直下の `./results` に出力されます。指定した場合は `<out>/results` 配下に成果物が置かれます。

## リポ構成
- `src/vulvul_gh_trivy_scanner/` : 実装（DTO、Trivyラッパ、GitHubアクセス、CLIエントリ）
- `config/repos.json` : スキャン対象リポ一覧（owner → [repo, ...]）
- `doc/` : 利用方法、API、ロジック、運用メモ
- `test/unit/` : ユニットテスト
- デフォルト出力先: `./results`（git管理外）

## 出力
- `packages.csv` : owner, repo, branch, commit_hash, package, version
- `vuls.csv` : owner, repo, branch, commit_hash, file_path, vulnerability, package, version, fixed_version

## ライセンス
同梱の LICENSE を参照。
