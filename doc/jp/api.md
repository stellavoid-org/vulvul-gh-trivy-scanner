# API / CLI リファレンス

## CLI: `vulvul-scan`
Poetryのコンソールスクリプト設定で提供されるエントリ。内部で `vulvul_gh_trivy_scanner.main_portable.main` を呼び出します。

### 引数
- `--repos` (必須): リポ一覧JSONへのパス（owner→reposマップ）
- `--out` (必須): 出力ディレクトリ。存在すれば中身をクリアしてから使用。
- `--gh-parallelism` (省略可, default 4): 権限確認とcloneの並列度。
- `--trivy-parallelism` (省略可, default 2): リポ単位スキャンの並列度（リポ内ブランチは逐次）。
- `--clear-work-dir` (flag): 各リポ処理後に作業ツリーを削除。

### 設定ファイル (`repos.json`)
```json
{
  "repos": {
    "owner_name": ["repo1", "repo2"]
  }
}
```
今後tokenやbranchesフィールド拡張を許容する設計。

### 出力ファイル
- `packages.csv`: `owner,repo,branch,commit_hash,package,version`
- `vuls.csv`: `owner,repo,branch,commit_hash,file_path,vulnerability,package,version,fixed_version`

### 実行例
```bash
vulvul-scan \
  --repos config/repos.json \
  --out results \
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
