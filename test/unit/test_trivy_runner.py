from pathlib import Path

import pytest

from vulvul_gh_trivy_scanner import trivy_runner


def test_run_trivy_fs_builds_command(monkeypatch, tmp_path: Path):
    calls = []

    def fake_run(cmd, check):
        calls.append((cmd, check))

    monkeypatch.setattr(trivy_runner.subprocess, "run", fake_run)

    target = tmp_path / "repo"
    target.mkdir()
    out = tmp_path / "out" / "trivy.json"

    trivy_runner.run_trivy_fs(target, out)

    assert out.parent.exists()
    assert calls, "subprocess.run should be called"
    cmd, check = calls[0]
    assert check is True
    assert cmd[:3] == ["trivy", "fs", "--format"]
    assert "--list-all-pkgs" in cmd
    assert str(target) in cmd


def test_run_trivy_fs_raises_on_failure(monkeypatch, tmp_path: Path):
    def fake_run(cmd, check):
        raise trivy_runner.subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(trivy_runner.subprocess, "run", fake_run)

    with pytest.raises(trivy_runner.subprocess.CalledProcessError):
        trivy_runner.run_trivy_fs(tmp_path, tmp_path / "out.json")
