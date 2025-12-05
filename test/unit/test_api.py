import asyncio
import io
import subprocess
from pathlib import Path
from urllib import error

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

    def fake_run(cmd, check, env=None, timeout=None, capture_output=None, text=None):
        calls.append((cmd, env))
        assert env.get("GIT_TERMINAL_PROMPT") is None

    monkeypatch.setattr("vulvul_gh_trivy_scanner.api.subprocess.run", fake_run)

    asyncio.run(access.clone(repo, tmp_path))

    assert repo.work_dir == tmp_path / "alice__demo"
    assert repo.work_dir.exists()
    assert calls, "git clone should be called"
    cmd, env = calls[0]
    assert cmd[0:2] == ["git", "clone"]
    assert str(repo.work_dir) in cmd
    assert env.get("GIT_TERMINAL_PROMPT") is None


def test_clone_sets_workdir_with_token(monkeypatch, tmp_path: Path):
    access = GHAccessWithThrottling(1, 1)
    repo = GHRepository(owner="alice", repo="demo", token="token")

    calls = []

    def fake_run(cmd, check, env=None, timeout=None, capture_output=None, text=None):
        calls.append((cmd, env))
        assert env.get("GIT_TERMINAL_PROMPT") == "0"

    monkeypatch.setattr("vulvul_gh_trivy_scanner.api.subprocess.run", fake_run)

    asyncio.run(access.clone(repo, tmp_path))

    cmd, env = calls[0]
    assert cmd[0:2] == ["git", "clone"]
    assert env.get("GIT_TERMINAL_PROMPT") == "0"


def test_get_permissions_handles_github_errors(monkeypatch):
    access = GHAccessWithThrottling(1, 1)
    repo = GHRepository(owner="alice", repo="demo", token="secret")

    http_error = error.HTTPError(
        "https://api.github.com/repos/alice/demo",
        401,
        "Unauthorized",
        hdrs=None,
        fp=io.BytesIO(b'{"message": "Bad credentials"}'),
    )

    def fake_urlopen(req, timeout):
        raise http_error

    monkeypatch.setattr("vulvul_gh_trivy_scanner.api.request.urlopen", fake_urlopen)

    asyncio.run(access.get_permissions(repo))

    assert repo.is_accessible is False
    assert "GitHub API 401" in (repo.access_error or "")
    assert "Bad credentials" in (repo.access_error or "")


def test_get_permissions_skips_rest_when_no_token(monkeypatch):
    access = GHAccessWithThrottling(1, 1)
    repo = GHRepository(owner="alice", repo="demo", token=None)

    def fake_run(cmd, check, env=None, timeout=None, capture_output=None, text=None):
        assert "ls-remote" in cmd
        assert env.get("GIT_TERMINAL_PROMPT") is None
        return

    monkeypatch.setattr("vulvul_gh_trivy_scanner.api.subprocess.run", fake_run)

    asyncio.run(access.get_permissions(repo))

    assert repo.is_accessible is True
    assert repo.access_error is None


def test_get_permissions_ls_remote_timeout_marks_failed(monkeypatch):
    access = GHAccessWithThrottling(1, 1)
    repo = GHRepository(owner="alice", repo="demo", token=None)

    def fake_run(cmd, check, env=None, timeout=None, capture_output=None, text=None):
        raise subprocess.TimeoutExpired(cmd="git", timeout=timeout)

    monkeypatch.setattr("vulvul_gh_trivy_scanner.api.subprocess.run", fake_run)

    asyncio.run(access.get_permissions(repo))

    assert repo.is_accessible is False
    assert repo.access_error == "git ls-remote timed out"
