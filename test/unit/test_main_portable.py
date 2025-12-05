import json
import sys
from pathlib import Path

from vulvul_gh_trivy_scanner import main_portable
from vulvul_gh_trivy_scanner.models_repo import GHRepository
from vulvul_gh_trivy_scanner.models_vuln import Package, Vul


def test_main_portable_outputs_csv(monkeypatch, tmp_path: Path, capsys):
    config_path = tmp_path / "repos.json"
    config_path.write_text(
        json.dumps({"alice": ["demo", "bad"], "bob": ["repo2"]}), encoding="utf-8"
    )

    pkg = Package(name="pkg", version="1.0.0", branch="main", commit_hash="abc")
    vul = Vul(
        file_path="poetry.lock",
        vulnerability_id="CVE-1",
        package=pkg,
        branch="main",
        commit_hash="abc",
    )
    vul.installed_version = "1.0.0"
    vul.fixed_version = "1.1.0"

    success_repo1 = GHRepository(owner="alice", repo="demo")
    success_repo1.packages = [pkg]
    success_repo1.vulnerabilities = [vul]

    success_repo2 = GHRepository(owner="bob", repo="repo2")
    success_repo2.packages = [Package(name="pkg2", version="2.0.0", branch="feature", commit_hash="def")]
    success_repo2.vulnerabilities = []

    failed_repo = GHRepository(owner="alice", repo="bad")
    failed_repo.mark_inaccessible("missing")

    def fake_get_vuls(*_, **__):
        return [success_repo1, success_repo2], [failed_repo]

    monkeypatch.setattr(main_portable, "get_vuls", fake_get_vuls)

    out_dir = tmp_path / "out_base"
    results_dir = out_dir / "results"
    # 事前にゴミを置き、クリアされることを確認する（results配下のみクリア）
    results_dir.mkdir(parents=True, exist_ok=True)
    junk = results_dir / "old.txt"
    junk.write_text("old", encoding="utf-8")

    argv = [
        "prog",
        "--repos",
        str(config_path),
        "--out",
        str(out_dir),
        "--clear-work-dir",
    ]
    monkeypatch.setattr(sys, "argv", argv)

    main_portable.main()

    packages_csv = (results_dir / "packages.csv").read_text(encoding="utf-8").splitlines()
    assert packages_csv[0].startswith("owner,repo,branch,commit_hash,package,version")
    assert any("alice,demo,main,abc,pkg,1.0.0" in line for line in packages_csv[1:])
    assert any("bob,repo2,feature,def,pkg2,2.0.0" in line for line in packages_csv[1:])

    vuls_csv = (results_dir / "vuls.csv").read_text(encoding="utf-8").splitlines()
    assert vuls_csv[0].startswith("owner,repo,branch,commit_hash,file_path")
    assert "fixed_version" in vuls_csv[0]
    assert "CVE-1" in vuls_csv[1]
    assert "main,abc" in vuls_csv[1]
    assert "1.1.0" in vuls_csv[1]

    captured = capsys.readouterr().out
    assert "WARN" in captured
    assert "bad" in captured


def test_main_portable_outputs_csv_default_out(monkeypatch, tmp_path: Path):
    config_path = tmp_path / "repos.json"
    config_path.write_text(json.dumps({"alice": ["demo"]}), encoding="utf-8")

    pkg = Package(name="pkg", version="1.0.0", branch="main", commit_hash="abc")
    success_repo = GHRepository(owner="alice", repo="demo")
    success_repo.packages = [pkg]
    success_repo.vulnerabilities = []

    def fake_get_vuls(*_, **__):
        return [success_repo], []

    monkeypatch.setattr(main_portable, "get_vuls", fake_get_vuls)

    monkeypatch.chdir(tmp_path)
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "old.txt").write_text("old", encoding="utf-8")

    argv = [
        "prog",
        "--repos",
        str(config_path),
    ]
    monkeypatch.setattr(sys, "argv", argv)

    main_portable.main()

    packages_csv = (results_dir / "packages.csv").read_text(encoding="utf-8").splitlines()
    assert any("alice,demo,main,abc,pkg,1.0.0" in line for line in packages_csv[1:])
    assert not (results_dir / "old.txt").exists()
