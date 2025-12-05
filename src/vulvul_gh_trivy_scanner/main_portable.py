import argparse
import json
import shutil
from pathlib import Path

from .get_vuls import get_vuls
from .infra import dump_csv
from .models_repo import GHRepository


def load_repos_from_json(path: Path) -> list[GHRepository]:
    data = json.loads(path.read_text(encoding="utf-8"))
    repos_conf = data.get("repos") if isinstance(data, dict) and "repos" in data else data
    if not isinstance(repos_conf, dict):
        raise ValueError("repos config must be an object mapping owner -> [repo, ...]")

    repos: list[GHRepository] = []
    for owner, repo_list in repos_conf.items():
        for repo in repo_list:
            repos.append(GHRepository(owner=owner, repo=repo))
    return repos


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", required=True, help="Path to repos.json")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--gh-parallelism", type=int, default=4)
    parser.add_argument("--trivy-parallelism", type=int, default=2)
    parser.add_argument(
        "--clear-work-dir",
        action="store_true",
        help="Remove each repo work dir after processing to save disk space.",
    )
    args = parser.parse_args()

    repos_conf_path = Path(args.repos)
    out_root = Path(args.out)

    # outディレクトリ準備（存在すれば中身クリア、なければ作成）
    if out_root.exists():
        for child in out_root.iterdir():
            if child.is_file():
                child.unlink()
            else:
                shutil.rmtree(child)
    else:
        out_root.mkdir(parents=True, exist_ok=True)

    repos = load_repos_from_json(repos_conf_path)

    success_repos, failed_repos = get_vuls(
        repos=repos,
        gh_parallelism=args.gh_parallelism,
        trivy_parallelism=args.trivy_parallelism,
        out_root=out_root,
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
    dump_csv(packages_rows, out_root / "packages.csv")

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
    dump_csv(vuls_rows, out_root / "vuls.csv")

    if failed_repos:
        print("WARN: some repositories failed:")
        for r in failed_repos:
            print(f" - {r.owner}/{r.repo}: {r.access_error or 'unknown error'}")


if __name__ == "__main__":
    main()
