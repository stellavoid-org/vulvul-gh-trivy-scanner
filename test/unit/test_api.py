import asyncio
from pathlib import Path

from vulvul_gh_trivy_scanner.api import GHAccessWithThrottling
from vulvul_gh_trivy_scanner.models_repo import GHRepository


def test_get_permissions_success(monkeypatch):
    access = GHAccessWithThrottling(1, 1)
    repo = GHRepository(owner="alice", repo="demo")

    async def fake_request(self, repo):
        return True, None

    monkeypatch.setattr(GHAccessWithThrottling, "_request_repo", fake_request, raising=False)

    asyncio.run(access.get_permissions(repo))
    assert repo.is_accessible is True
    assert repo.access_error is None


def test_get_permissions_failure(monkeypatch):
    access = GHAccessWithThrottling(1, 1)
    repo = GHRepository(owner="alice", repo="demo")

    async def fake_request(self, repo):
        return False, "forbidden"

    monkeypatch.setattr(GHAccessWithThrottling, "_request_repo", fake_request, raising=False)

    asyncio.run(access.get_permissions(repo))
    assert repo.is_accessible is False
    assert repo.access_error == "forbidden"


def test_clone_sets_workdir(monkeypatch, tmp_path: Path):
    access = GHAccessWithThrottling(1, 1)
    repo = GHRepository(owner="alice", repo="demo")

    calls = []

    def fake_run(cmd, check):
        calls.append(cmd)

    monkeypatch.setattr("vulvul_gh_trivy_scanner.api.subprocess.run", fake_run)

    asyncio.run(access.clone(repo, tmp_path))

    assert repo.work_dir == tmp_path / "alice__demo"
    assert repo.work_dir.exists()
    assert calls, "git clone should be called"
    assert calls[0][0:2] == ["git", "clone"]
    assert str(repo.work_dir) in calls[0]
