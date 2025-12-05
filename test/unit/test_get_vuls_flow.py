import json
from pathlib import Path
import time

from vulvul_gh_trivy_scanner.get_vuls import get_vuls
from vulvul_gh_trivy_scanner.models_repo import GHRepository


class _StubGHAccess:
    def __init__(self, *_, **__):
        self.perm_calls = 0
        self.clone_calls = 0

    async def get_permissions(self, repo: GHRepository):
        self.perm_calls += 1
        repo.mark_accessible()

    async def clone(self, repo: GHRepository, base_work_dir: Path):
        self.clone_calls += 1
        repo.work_dir = base_work_dir / f"{repo.owner}__{repo.repo}"
        repo.work_dir.mkdir(parents=True, exist_ok=True)


def _write_sample_trivy_json(path: Path):
    sample = {
        "Results": [
            {
                "Target": "poetry.lock",
                "Type": "poetry",
                "Packages": [
                    {
                        "ID": "pkg@1",
                        "Name": "pkg",
                        "Version": "1",
                        "Identifier": {"PURL": "pkg:pypi/pkg@1", "UID": "u"},
                    }
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgID": "pkg@1",
                        "PkgName": "pkg",
                        "InstalledVersion": "1",
                    }
                ],
            }
        ]
    }
    path.write_text(json.dumps(sample), encoding="utf-8")


def test_get_vuls_flow(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.GHAccessWithThrottling", _StubGHAccess)

    def fake_run_trivy_fs(target_dir: Path, output_json: Path):
        _write_sample_trivy_json(output_json)

    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.run_trivy_fs", fake_run_trivy_fs)

    # mock git checkout, branch -r, and rev-parse
    git_calls = []
    check_output_calls = []

    def fake_run(cmd, check, capture_output=False, text=False):
        git_calls.append(cmd)
        if "rev-parse" in cmd:
            return type("R", (), {"stdout": "abc123\n"})()
        return type("R", (), {"stdout": ""})()

    def fake_check_output(cmd, text=False):
        check_output_calls.append(cmd)
        if "branch" in cmd:
            return "  origin/main\n  origin/feature\n  origin/HEAD -> origin/main\n"
        if "rev-parse" in cmd:
            return "abc123\n"
        return ""

    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.subprocess.run", fake_run)
    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.subprocess.check_output", fake_check_output)

    repos = [
        GHRepository(owner="alice", repo="demo"),
        GHRepository(owner="bob", repo="repo2"),
    ]
    success, failed = get_vuls(
        repos=repos,
        gh_parallelism=2,
        trivy_parallelism=1,
        out_root=tmp_path,
        clear_work_dir=True,
    )

    assert failed == []
    assert len(success) == 2

    for repo in success:
        assert repo.is_accessible is True
        assert repo.out_dir == tmp_path / "repos" / f"{repo.owner}__{repo.repo}"
        assert (repo.out_dir / "main_trivy.json").exists()
        assert (repo.out_dir / "feature_trivy.json").exists()
        assert repo.packages and repo.vulnerabilities
        assert repo.work_dir is None  # cleared when clear_work_dir=True
        assert len(repo.packages) == 2  # two branches
        assert len(repo.vulnerabilities) == 2
        # branch info propagated
        branches = {p.branch for p in repo.packages}
        assert branches == {"main", "feature"}
        assert all(v.branch in {"main", "feature"} for v in repo.vulnerabilities)
        assert all(p.commit_hash == "abc123" for p in repo.packages)
        assert all(v.commit_hash == "abc123" for v in repo.vulnerabilities)

    # checkout was invoked per branch and remote branches fetched
    assert any("branch" in cmd for cmd in check_output_calls)
    assert len([c for c in git_calls if "checkout" in c]) == 4
