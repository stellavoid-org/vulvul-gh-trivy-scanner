import asyncio
import subprocess
from pathlib import Path
from typing import Tuple

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
        デフォルト実装は許可し、テストや本番で _request_repo を差し替え可能にする。
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
        デフォルトは成功扱いとし、テストや実運用で上書きする想定。
        """
        return True, None

    async def clone(self, repo: GHRepository, base_work_dir: Path) -> None:
        """
        git clone を実行して repo.work_dir を設定。
        """
        async with self._sem_clone:
            repo_dir = base_work_dir / f"{repo.owner}__{repo.repo}"
            repo_dir.mkdir(parents=True, exist_ok=True)
            url = f"{repo.base_url}/{repo.owner}/{repo.repo}.git"
            cmd = ["git", "clone", url, str(repo_dir)]

            try:
                await asyncio.to_thread(subprocess.run, cmd, True)
                repo.work_dir = repo_dir
            except subprocess.CalledProcessError as exc:
                repo.mark_inaccessible(f"clone failed: {exc}")
