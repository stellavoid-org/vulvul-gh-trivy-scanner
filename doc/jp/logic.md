# ロジック概要

## 全体フロー
1. 設定読み込み: `repos.json` から owner→repo のリストを生成し、`GHRepository` に変換。
2. 権限確認: `GHAccessWithThrottling.get_permissions` を並列で実行。
3. clone: 権限OKなリポだけ `git clone`（並列）。`work_dir` を設定。
4. ブランチ列挙: `git branch -r` でリモートブランチ一覧取得（`origin/HEAD` 除外）。未取得なら `["main"]` フォールバック。
5. スキャン: リポ単位で並列実行。リポ内はブランチ逐次で `checkout → rev-parse → trivy fs --list-all-pkgs → parse`。
6. 集約: `<out>/results` 配下に `packages.csv` と `vuls.csv` をフラット出力。`--clear-work-dir` 指定時は処理後に作業ツリー削除。

## 並列モデル
- リポ間: clone/スキャンを ThreadPool で並列（gh_parallelism / trivy_parallelism）。
- リポ内: ブランチは逐次実行（同一ワークツリーでの checkout 競合回避）。

## 主要コンポーネント
- `GHAccessWithThrottling`: 権限確認/cloneのセマフォ制御。実API呼び出しは差し替え可能フック `_request_repo`。
- `trivy_runner`: `trivy fs --format json --list-all-pkgs` を叩く薄いラッパ。
- `get_vuls.parse_trivy_json`: Results[].Packages/Vulnerabilities を DTO に変換し、branch/commit情報を付与。
- `infra.dump_json/dump_csv`: 出力ユーティリティ。

## DTO
- `Package`: id, name, version, purl/uid, ecosystem, manager, path, branch, commit_hash, depends_on_ids
- `Vul`: file_path, vulnerability_id, severityなど、pkg_id/pkg_name、installed_version、fixed_version（文字列）、branch, commit_hash, raw
- `GHRepository`: owner/repo、branches、work_dir/out_dir、packages/vulnerabilities、アクセス状態

## クリア動作
- `<out>/results` は開始時に中身をクリア（デフォルトの base はカレントディレクトリ）。
- `--clear-work-dir` 指定時、各リポ処理完了後に clone ディレクトリを削除。
