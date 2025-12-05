# API / CLI リファレンス

## CLI: `vulvul-scan`
Poetryのコンソールスクリプト設定で提供されるエントリ。内部で `vulvul_gh_trivy_scanner.main_portable.main` を呼び出します。

### 引数
- `--repos` (必須): リポ一覧JSONへのパス（owner→reposマップ）
- `--out` (省略可, default カレントディレクトリ): ベース出力ディレクトリ。`<out>/results` をクリアして利用。
- `--gh-parallelism` (省略可, default 4): 権限確認とcloneの並列度。
- `--trivy-parallelism` (省略可, default 2): リポ単位スキャンの並列度（リポ内ブランチは逐次）。
- `--clear-work-dir` (flag): 各リポ処理後に作業ツリーを削除。

### 設定ファイル (`repos.json`)
トークンは環境変数名で指定（リポトークンがorgトークンより優先。環境変数が空でもフォールバックしない）。

```bash
export ORG_TOKEN="org-pat"
export REPO_TOKEN="repo-pat"
```

```json
{
  "repos": {
    "owner_name": {
      "org_token_name": "ORG_TOKEN",     // optional
      "repos": [
        "public_repo",
        {
          "repo_name": "private_repo",
          "repo_token_name": "REPO_TOKEN",    // optional
          "all_branches": false,              // optional, default true
          "branch_regexes": ["main", "release/.*"], // all_branches=false の場合必須
          "scan_default_branch": true         // optional, default true
        }
      ]
    }
  }
}
```
レガシー形式（`"owner": ["repo1", ...]`）も受け付ける。

トークンなしの場合: RESTは叩かず `git ls-remote` で存在/権限を確認。クレデンシャルヘルパーやSSHでアクセス可能ならそのままclone。権限が無ければstderrを出しつつ該当リポをスキップ。

### 出力ファイル
- `packages.csv`: `owner,repo,branch,commit_hash,package,version`
- `vuls.csv`: `owner,repo,branch,commit_hash,file_path,vulnerability,package,version,fixed_version`

### 実行例
```bash
vulvul-scan \
  --repos config/repos.json \
  --out out_dir \
  --gh-parallelism 5 \
  --trivy-parallelism 5 \
  --clear-work-dir
```

## Pythonモジュール
- `vulvul_gh_trivy_scanner.get_vuls.get_vuls(repos, gh_parallelism, trivy_parallelism, out_root, clear_work_dir)`
  - GHRepositoryのリストを受け取り、成功リポ/失敗リポを返す。
- DTO: `models_repo.GHRepository`, `models_vuln.Package`, `models_vuln.Vul`
- 実行ラッパ: `trivy_runner.run_trivy_fs(target_dir, output_json)`
- GitHubアクセス: `api.GHAccessWithThrottling`（権限確認とcloneの並列制御フック）
