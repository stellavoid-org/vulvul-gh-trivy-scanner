import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from .get_vuls import get_vuls
from .infra import dump_csv
from .models_repo import GHRepository


def load_repos_from_json(path: Path) -> list[GHRepository]:
    data = json.loads(path.read_text(encoding="utf-8"))
    repos_conf = data.get("repos") if isinstance(data, dict) and "repos" in data else data
    if not isinstance(repos_conf, dict):
        raise ValueError(
            "repos config must be an object mapping owner -> [repo, ...] "
            "or owner -> {org_token_name?, repos: [...]}"
        )

    repos: list[GHRepository] = []
    for owner, value in repos_conf.items():
        org_token_name: str | None = None
        repo_entries = value

        if isinstance(value, dict):
            repo_entries = value.get("repos")
            org_token_name = value.get("org_token_name")

        if not isinstance(repo_entries, list):
            raise ValueError(f"repos for owner '{owner}' must be a list")

        org_token_loaded = False
        org_token: str | None = None

        for entry in repo_entries:
            repo_name, repo_token_name = _parse_repo_entry(entry, owner)

            token_env_name = repo_token_name or org_token_name
            token = None
            if repo_token_name:
                token = _load_token_from_env(repo_token_name)
            elif org_token_name:
                if not org_token_loaded:
                    org_token = _load_token_from_env(org_token_name)
                    org_token_loaded = True
                token = org_token

            repos.append(
                GHRepository(
                    owner=owner,
                    repo=repo_name,
                    token=token,
                    token_env_name=token_env_name,
                )
            )
    return repos


def _parse_repo_entry(entry: object, owner: str) -> tuple[str, str | None]:
    if isinstance(entry, str):
        return entry, None

    if isinstance(entry, dict):
        repo_name = (
            entry.get("repo_name")
            or entry.get("repo")
            or entry.get("name")
        )
        if not repo_name or not isinstance(repo_name, str):
            raise ValueError(f"repo entry for owner '{owner}' is missing repo_name")
        repo_token_name = entry.get("repo_token_name")
        if repo_token_name and not isinstance(repo_token_name, str):
            raise ValueError(f"repo_token_name for '{owner}/{repo_name}' must be a string")
        return repo_name, repo_token_name

    raise ValueError(f"repo entry for owner '{owner}' must be string or object")


def _load_token_from_env(env_name: str | None) -> str | None:
    if not env_name:
        return None
    value = os.getenv(env_name)
    if value:
        return value
    # トークン名が指定されたが環境変数が未設定の場合は素通り（fallback しない）。
    print(f"WARN: env var '{env_name}' not set; continuing without token", file=sys.stderr)
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", required=True, help="Path to repos.json")
    parser.add_argument(
        "--out",
        default="",
        help="Base output directory (default: current working directory). Results are written under <out>/results",
    )
    parser.add_argument("--gh-parallelism", type=int, default=4)
    parser.add_argument("--trivy-parallelism", type=int, default=2)
    parser.add_argument(
        "--clear-work-dir",
        action="store_true",
        help="Remove each repo work dir after processing to save disk space.",
    )
    args = parser.parse_args()

    repos_conf_path = Path(args.repos)
    out_base = Path(args.out) if args.out else Path.cwd()
    results_root = out_base / "results"

    out_base.mkdir(parents=True, exist_ok=True)
    # <out>/results ディレクトリ準備（存在すれば中身クリア、なければ作成）
    if results_root.exists():
        for child in results_root.iterdir():
            if child.is_file():
                child.unlink()
            else:
                shutil.rmtree(child)
    else:
        results_root.mkdir(parents=True, exist_ok=True)

    repos = load_repos_from_json(repos_conf_path)

    success_repos, failed_repos = get_vuls(
        repos=repos,
        gh_parallelism=args.gh_parallelism,
        trivy_parallelism=args.trivy_parallelism,
        out_root=results_root,
        clear_work_dir=args.clear_work_dir,
    )

    packages_rows = []
    for r in success_repos:
        for p in r.packages:
            packages_rows.append(
                {
                    "owner": r.owner,
                    "repo": r.repo,
                    "branch": p.branch or "",
                    "commit_hash": p.commit_hash or "",
                    "package": p.name,
                    "version": p.version,
                }
            )
    dump_csv(packages_rows, results_root / "packages.csv")

    vuls_rows = []
    for r in success_repos:
        for v in r.vulnerabilities:
            vuls_rows.append(
                {
                    "owner": r.owner,
                    "repo": r.repo,
                    "branch": v.branch or "",
                    "commit_hash": v.commit_hash or "",
                    "file_path": v.file_path,
                    "vulnerability": v.vulnerability_id,
                    "package": v.package.name if v.package else (v.pkg_name or ""),
                    "version": v.installed_version
                    or (v.package.version if v.package else ""),
                    "fixed_version": v.fixed_version or "",
                }
            )
    dump_csv(vuls_rows, results_root / "vuls.csv")

    if failed_repos:
        print("WARN: some repositories failed:")
        for r in failed_repos:
            print(f" - {r.owner}/{r.repo}: {r.access_error or 'unknown error'}")


if __name__ == "__main__":
    main()
