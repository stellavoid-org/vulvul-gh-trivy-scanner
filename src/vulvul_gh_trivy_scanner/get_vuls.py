import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

from .api import GHAccessWithThrottling
from .models_repo import GHRepository
from .models_vuln import Package, Vul
from .trivy_runner import run_trivy_fs


async def _process_permissions(
    repos: List[GHRepository],
    gh_access: GHAccessWithThrottling,
) -> None:
    await asyncio.gather(*(gh_access.get_permissions(r) for r in repos))


async def _process_clone(
    repos: List[GHRepository],
    gh_access: GHAccessWithThrottling,
    base_work_dir: Path,
) -> None:
    await asyncio.gather(*(gh_access.clone(r, base_work_dir) for r in repos if r.is_accessible))


def parse_trivy_json(
    json_path: Path,
    branch: str | None = None,
    commit_hash: str | None = None,
) -> tuple[list[Vul], list[Package]]:
    data = json.loads(json_path.read_text(encoding="utf-8"))

    all_vuls: list[Vul] = []
    all_packages: list[Package] = []

    for result in data.get("Results", []):
        target = result.get("Target")
        manager = result.get("Type")

        pkg_map: Dict[str, Package] = {}
        for entry in result.get("Packages", []) or []:
            pkg = _parse_package_entry(entry, target, manager, branch, commit_hash)
            all_packages.append(pkg)
            if pkg.id:
                pkg_map[pkg.id] = pkg

        for entry in result.get("Vulnerabilities", []) or []:
            vul = _parse_vuln_entry(entry, target, pkg_map, branch, commit_hash)
            all_vuls.append(vul)

    return all_vuls, all_packages


def _parse_package_entry(
    entry: dict,
    target: str | None,
    manager: str | None,
    branch: str | None,
    commit_hash: str | None,
) -> Package:
    identifier = entry.get("Identifier") or {}
    purl = identifier.get("PURL")
    uid = identifier.get("UID")

    ecosystem = None
    if purl and purl.startswith("pkg:"):
        try:
            ecosystem = purl.split(":", 1)[1].split("/", 1)[0]
        except Exception:
            ecosystem = None

    return Package(
        id=entry.get("ID"),
        name=entry.get("Name") or "",
        version=entry.get("Version") or "",
        purl=purl,
        uid=uid,
        ecosystem=ecosystem,
        manager=manager,
        path=target,
        branch=branch,
        commit_hash=commit_hash,
        depends_on_ids=entry.get("DependsOn", []) or [],
    )


def _parse_vuln_entry(
    entry: dict,
    target: str | None,
    pkg_map: Dict[str, Package],
    branch: str | None,
    commit_hash: str | None,
) -> Vul:
    vuln_id = entry.get("VulnerabilityID", "")
    pkg_id = entry.get("PkgID")
    pkg_name = entry.get("PkgName")
    installed_version = entry.get("InstalledVersion")

    fixed_version = entry.get("FixedVersion")
    if not isinstance(fixed_version, str):
        fixed_version = None

    cvss_field = entry.get("CVSS") or {}
    cvss: Dict[str, Dict[str, float | str | None]] = {}
    for source, cv in cvss_field.items():
        cvss[source] = {
            "v3_score": cv.get("V3Score"),
            "v3_vector": cv.get("V3Vector"),
        }

    vul = Vul(
        file_path=target or "",
        vulnerability_id=vuln_id,
        title=entry.get("Title"),
        description=entry.get("Description"),
        severity=entry.get("Severity"),
        status=entry.get("Status"),
        severity_source=entry.get("SeveritySource"),
        primary_url=entry.get("PrimaryURL"),
        cwe_ids=entry.get("CweIDs", []) or [],
        references=entry.get("References", []) or [],
        cvss=cvss,
        published_date=entry.get("PublishedDate"),
        last_modified_date=entry.get("LastModifiedDate"),
        pkg_id=pkg_id,
        pkg_name=pkg_name,
        installed_version=installed_version,
        fixed_version=fixed_version,
        branch=branch,
        commit_hash=commit_hash,
        raw=entry,
    )

    if pkg_id and pkg_id in pkg_map:
        vul.package = pkg_map[pkg_id]

    return vul


def get_vuls(
    repos: List[GHRepository],
    gh_parallelism: int,
    trivy_parallelism: int,  # reserved
    out_root: Path,
    clear_work_dir: bool = False,
) -> Tuple[List[GHRepository], List[GHRepository]]:
    gh_access = GHAccessWithThrottling(
        max_parallelism_clone=gh_parallelism,
        max_parallelism_get_permissions=gh_parallelism,
    )

    base_work_dir = out_root / "work"
    base_work_dir.mkdir(parents=True, exist_ok=True)

    asyncio.run(_process_permissions(repos, gh_access))

    accessible = [r for r in repos if r.is_accessible]
    failed: List[GHRepository] = [r for r in repos if not r.is_accessible]

    asyncio.run(_process_clone(accessible, gh_access, base_work_dir))

    cloned_accessible = [r for r in accessible if r.is_accessible and r.work_dir]
    failed.extend([r for r in accessible if not r.is_accessible or not r.work_dir])

    results: list[GHRepository] = []
    with ThreadPoolExecutor(max_workers=trivy_parallelism or 1) as executor:
        future_map = {
            executor.submit(_scan_repo_sync, repo, out_root, clear_work_dir): repo
            for repo in cloned_accessible
        }
        for future in as_completed(future_map):
            repo = future.result()
            results.append(repo)

    for repo in results:
        if repo.is_accessible:
            continue
        failed.append(repo)

    success = [r for r in results if r.is_accessible]
    return success, failed


def _scan_repo_sync(repo: GHRepository, out_root: Path, clear_work_dir: bool) -> GHRepository:
    if not repo.work_dir:
        repo.mark_inaccessible("clone failed")
        return repo

    print(f"INFO: start scanning {repo.owner}/{repo.repo}", file=sys.stderr)

    if not repo.branches:
        repo.branches = _get_remote_branches(repo)
        if not repo.branches:
            repo.mark_inaccessible("no branches to scan")
            return repo

    repo.out_dir = out_root / "repos" / f"{repo.owner}__{repo.repo}"
    repo.out_dir.mkdir(parents=True, exist_ok=True)

    repo.vulnerabilities = []
    repo.packages = []

    branches = repo.branches or ["main"]
    _scan_branches_sync(repo, branches)

    if clear_work_dir and repo.work_dir:
        shutil.rmtree(repo.work_dir, ignore_errors=True)
        repo.work_dir = None

    print(f"INFO: finished scanning {repo.owner}/{repo.repo}", file=sys.stderr)

    return repo


def _scan_branches_sync(repo: GHRepository, branches: List[str]) -> None:
    for branch in branches:
        try:
            vuls, pkgs = _process_branch_sync(repo, branch)
            repo.vulnerabilities.extend(vuls)
            repo.packages.extend(pkgs)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            repo.mark_inaccessible(f"branch checkout failed: {branch}: {exc}")
            break


def _process_branch_sync(repo: GHRepository, branch: str) -> tuple[list[Vul], list[Package]]:
    _checkout_branch(repo.work_dir, branch)
    commit_hash = _get_commit_hash(repo.work_dir)

    trivy_json = repo.out_dir / f"{branch}_trivy.json"
    run_trivy_fs(repo.work_dir, trivy_json)

    return parse_trivy_json(trivy_json, branch=branch, commit_hash=commit_hash)


def _checkout_branch(work_dir: Path, branch: str) -> None:
    subprocess.run(
        ["git", "-C", str(work_dir), "checkout", branch],
        check=True,
        env=_git_env(),
        timeout=120,
    )


def _get_commit_hash(work_dir: Path) -> str:
    return (
        subprocess.check_output(
            ["git", "-C", str(work_dir), "rev-parse", "HEAD"],
            text=True,
            env=_git_env(),
            timeout=30,
        ).strip()
    )


def _get_remote_branches(repo: GHRepository) -> List[str]:
    work_dir = repo.work_dir
    if not work_dir:
        return ["main"]
    try:
        output = subprocess.check_output(
            ["git", "-C", str(work_dir), "branch", "-r"],
            text=True,
            env=_git_env(),
            timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ["main"]

    branches: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "->" in line:
            continue
        if line.startswith("origin/"):
            name = line.split("/", 1)[1]
        else:
            name = line
        if name and name not in branches:
            branches.append(name)

    if repo.all_branches:
        return branches or ["main"]

    filtered: set[str] = set()
    regexes = [re.compile(p) for p in (repo.branch_regexes or [])]
    for b in branches:
        if any(rgx.search(b) for rgx in regexes):
            filtered.add(b)

    if repo.scan_default_branch:
        default_branch = _get_default_branch(work_dir)
        if default_branch:
            filtered.add(default_branch)

    if not filtered:
        return []

    return list(filtered)


def _get_default_branch(work_dir: Path) -> str | None:
    try:
        ref = subprocess.check_output(
            ["git", "-C", str(work_dir), "symbolic-ref", "refs/remotes/origin/HEAD"],
            text=True,
            env=_git_env(),
            timeout=10,
        ).strip()
        if ref.startswith("refs/remotes/origin/"):
            return ref.split("/")[-1]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return None


def _git_env() -> dict[str, str]:
    env = dict(**os.environ)
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    return env
