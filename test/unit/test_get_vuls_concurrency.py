import time
from pathlib import Path

from vulvul_gh_trivy_scanner.get_vuls import get_vuls
from vulvul_gh_trivy_scanner.models_repo import GHRepository


class _StubGHAccess:
    def __init__(self, *_, **__):
        self.clone_calls = 0
        self.perm_calls = 0

    async def get_permissions(self, repo: GHRepository):
        self.perm_calls += 1
        repo.mark_accessible()

    async def clone(self, repo: GHRepository, base_work_dir: Path):
        self.clone_calls += 1
        repo.work_dir = base_work_dir / f"{repo.owner}__{repo.repo}"
        repo.work_dir.mkdir(parents=True, exist_ok=True)


def test_clone_runs_concurrently(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.GHAccessWithThrottling", _StubGHAccess)

    def fake_run_trivy_fs(target_dir: Path, output_json: Path):
        output_json.write_text('{"Results":[]}', encoding="utf-8")

    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.run_trivy_fs", fake_run_trivy_fs)

    sleep_calls = []

    def fake_run(cmd, check, capture_output=False, text=False):
        # simulate slow checkout to test concurrency
        if "checkout" in cmd:
            sleep_calls.append(cmd)
            time.sleep(0.2)
        return type("R", (), {"stdout": ""})()

    def fake_check_output(cmd, text=False):
        if "branch" in cmd:
            return "  origin/main\n  origin/feature\n"
        if "rev-parse" in cmd:
            return "abc\n"
        return ""

    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.subprocess.run", fake_run)
    monkeypatch.setattr("vulvul_gh_trivy_scanner.get_vuls.subprocess.check_output", fake_check_output)

    repos = [GHRepository(owner="o", repo=f"r{i}") for i in range(2)]

    start = time.time()
    success, failed = get_vuls(
        repos=repos,
        gh_parallelism=2,
        trivy_parallelism=2,
        out_root=tmp_path,
        clear_work_dir=False,
    )
    elapsed = time.time() - start

    assert failed == []
    assert len(success) == 2
    # two 0.2s sleep checkouts per repo, sequential per repo; repos run in parallel
    assert elapsed < 0.6
