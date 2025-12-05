# vulvul-gh-trivy-scanner docs

このツールの概要とドキュメント一覧です。詳細は各ファイルを参照してください。

## 目的
GitHub上の複数リポを `trivy fs --list-all-pkgs` で走査し、全パッケージと脆弱性をCSVへ集約します。ローカル実行とGitHub Actions実行の両方を想定しています。

## 主要ドキュメント
- `api.md` : CLIインタフェース、引数、出力ファイル仕様、設定ファイル形式。
- `logic.md` : 処理フロー、並列モデル、主要コンポーネントの役割。
- `ops.md` : 運用ヒント（パフォーマンス、ログ抑制、クリーンアップ）。

## 手早い使い方
```bash
pip install .
vulvul-scan --repos config/repos.json --out results --gh-parallelism 4 --trivy-parallelism 2 --clear-work-dir
```
`--out` を省略すると `./results` に出力されます。指定した場合は `<out>/results` 配下に成果物が置かれます。

## 出力
- `results/packages.csv` : owner/repo/branch/commit/パッケージ/バージョン
- `results/vuls.csv` : owner/repo/branch/commit/対象ファイル/脆弱性ID/パッケージ/バージョン/fixed_version

## 設定ファイル例
```json
{
  "repos": {
    "owner1": {
      "org_token_name": "ORG_TOKEN", // optional
      "repos": [
        "repoA",
        {
          "repo_name": "private-repo",
          "repo_token_name": "REPO_TOKEN", // optional
          "all_branches": false,           // optional (default true)
          "branch_regexes": ["main", "release/.*"], // all_branches=false なら必須
          "scan_default_branch": true      // optional (default true)
        }
      ]
    },
    "owner2": ["repoC"]
  }
}
```
