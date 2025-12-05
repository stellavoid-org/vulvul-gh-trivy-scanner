# 運用メモ

## パフォーマンス
- `--gh-parallelism` で clone/権限確認の並列度を制御。
- `--trivy-parallelism` でリポ間スキャンの並列度を制御（ブランチ内は逐次）。
- ブランチ数が多いリポは時間がかかるため、必要に応じて対象ブランチを絞る拡張を検討。

## ディスク使用
- `--clear-work-dir` で処理後に clone ディレクトリを削除。`<out>/results` は毎回クリーンアップ済み（デフォルト base はカレントディレクトリ）。

## ログ
- Trivy標準ログが多い場合は、将来的に `trivy_runner` へ `--quiet` や `--scanners vuln` などを渡す拡張が可能。
- 権限/clone/checkout失敗時はリポを failed として扱い、標準出力に警告を出す。

## トラブルシュート
- `index.lock` 競合: ブランチ逐次処理で回避済み。残る場合は手動で `.git/index.lock` を削除。
- `repository not found`: `repos.json` のスペルや権限（トークン）を確認。
- トークン利用時の権限エラー: GitHub は 401 (`Bad credentials`), 403 (`Resource not accessible by personal access token`), 404 (`Not Found`/非公開) を返す場合がある。`ERROR` ログを出しつつ他リポは継続。
- Trivy 未インストール: 実行前に `trivy` コマンドが利用可能か確認。
