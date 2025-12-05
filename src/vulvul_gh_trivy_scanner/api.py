import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple
from urllib import error, parse, request

from .models_repo import GHRepository


class GHAccessWithThrottling:
    def __init__(
        self,
        max_parallelism_clone: int,
        max_parallelism_get_permissions: int,
    ) -> None:
        self._sem_clone = asyncio.Semaphore(max_parallelism_clone)
        self._sem_perm = asyncio.Semaphore(max_parallelism_get_permissions)

    async def get_permissions(self, repo: GHRepository) -> None:
        """
        GitHub API を叩いてリポが存在するか / アクセス権があるか確認。
        デフォルト実装は実 API を叩き、テストや本番で _request_repo を差し替え可能にする。
        """
        async with self._sem_perm:
            ok, reason = await self._request_repo(repo)
            if ok:
                repo.mark_accessible()
            else:
                repo.mark_inaccessible(reason or "access denied")

    async def _request_repo(self, repo: GHRepository) -> Tuple[bool, str | None]:
        """
        実際の GitHub API 叩きを行うためのフック。
        トークンが無い場合は REST を叩かず、git ls-remote で事前確認する。
        """
        if not repo.token:
            return await asyncio.to_thread(self._check_via_git, repo)
        return await asyncio.to_thread(self._request_repo_sync, repo)

    def _request_repo_sync(self, repo: GHRepository) -> Tuple[bool, str | None]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "vulvul-gh-trivy-scanner",
        }
        if repo.token:
            headers["Authorization"] = f"Bearer {repo.token}"

        url = f"{repo.api_base_url.rstrip('/')}/repos/{repo.owner}/{repo.repo}"
        req = request.Request(url, headers=headers, method="GET")

        try:
            with request.urlopen(req, timeout=10):
                return True, None
        except error.HTTPError as exc:
            message = _extract_github_error_message(exc)
            # GitHub examples:
            # - 401 + {"message": "Bad credentials"}
            # - 403 + {"message": "Resource not accessible by personal access token"}
            # - 404 + {"message": "Not Found"} (private or missing)
            reason = f"GitHub API {exc.code}: {message or exc.reason or 'unknown error'}"
            _log_error(f"permission check failed for {repo.owner}/{repo.repo}: {reason}")
            return False, reason
        except Exception as exc:  # pragma: no cover - defensive
            _log_error(f"permission check error for {repo.owner}/{repo.repo}: {exc}")
            return False, str(exc)

    def _check_via_git(self, repo: GHRepository) -> Tuple[bool, str | None]:
        """
        Tokenless では REST を叩かず、git ls-remote でリポ存在/認可を確認。
        """
        url = f"{repo.base_url.rstrip('/')}/{repo.owner}/{repo.repo}.git"
        cmd = ["git", "ls-remote", "--heads", url]
        _log_info(f"git ls-remote check: {url}")
        try:
            subprocess.run(
                cmd,
                check=True,
                env=_clone_env(repo.token),
                timeout=30,
                capture_output=True,
                text=True,
            )
            return True, None
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if isinstance(exc.stderr, str) else ""
            reason = f"git ls-remote failed: {stderr or exc}"
            _log_error(f"{repo.owner}/{repo.repo}: {reason}")
            return False, reason
        except subprocess.TimeoutExpired:
            reason = "git ls-remote timed out"
            _log_error(f"{repo.owner}/{repo.repo}: {reason}")
            return False, reason

    async def clone(self, repo: GHRepository, base_work_dir: Path) -> None:
        """
        git clone を実行して repo.work_dir を設定。
        """
        async with self._sem_clone:
            repo_dir = base_work_dir / f"{repo.owner}__{repo.repo}"
            repo_dir.mkdir(parents=True, exist_ok=True)
            url = f"{repo.base_url.rstrip('/')}/{repo.owner}/{repo.repo}.git"
            cmd = [
                "git",
                "clone",
                _inject_token_into_url(url, repo.token),
                str(repo_dir),
            ]

            try:
                await asyncio.to_thread(
                    subprocess.run,
                    cmd,
                    True,
                    env=_clone_env(repo.token),
                    timeout=300,
                    capture_output=True,
                    text=True,
                )
                repo.work_dir = repo_dir
            except subprocess.CalledProcessError:
                repo.mark_inaccessible("clone failed")
            except subprocess.TimeoutExpired:
                repo.mark_inaccessible("clone timed out")


def _extract_github_error_message(exc: error.HTTPError) -> str | None:
    try:
        body = exc.read().decode("utf-8")
    except Exception:
        return None

    try:
        data = json.loads(body)
    except Exception:
        return body or None

    message = data.get("message")
    doc_url = data.get("documentation_url")
    if message and doc_url:
        return f"{message} ({doc_url})"
    return message


def _log_error(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def _log_warn(message: str) -> None:
    print(f"WARN: {message}", file=sys.stderr)


def _log_info(message: str) -> None:
    print(f"INFO: {message}", file=sys.stderr)

def _inject_token_into_url(url: str, token: str | None) -> str:
    """
    Embed PAT into https URL if supplied. Git keeps the token in the remote URL,
    so callers should manage work dirs carefully when tokens are used.
    """
    if not token:
        return url

    parsed = parse.urlsplit(url)
    netloc = f"{parse.quote(token, safe='')}@{parsed.netloc}"
    return parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def _clone_env(token: str | None) -> dict[str, str]:
    """
    Build environment for git operations. Tokenありのときのみプロンプトを止める。
    """
    env = dict(**os.environ)
    if token:
        env.setdefault("GIT_TERMINAL_PROMPT", "0")
    return env
