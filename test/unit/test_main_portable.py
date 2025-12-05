import json
import sys
from pathlib import Path

import pytest

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


def test_load_repos_with_tokens(monkeypatch, tmp_path: Path):
    config_path = tmp_path / "repos.json"
    config_path.write_text(
        json.dumps(
            {
                "repos": {
                    "alice": {
                        "org_token_name": "ORG_TOKEN",
                        "repos": [
                            "repo1",
                            {"repo_name": "repo2", "repo_token_name": "REPO_TOKEN"},
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ORG_TOKEN", "org-secret")
    monkeypatch.setenv("REPO_TOKEN", "repo-secret")

    repos = main_portable.load_repos_from_json(config_path)

    assert len(repos) == 2
    repo1 = repos[0]
    repo2 = repos[1]
    assert repo1.repo == "repo1"
    assert repo1.token == "org-secret"
    assert repo1.token_env_name == "ORG_TOKEN"
    assert repo2.repo == "repo2"
    assert repo2.token == "repo-secret"
    assert repo2.token_env_name == "REPO_TOKEN"
    assert repo1.all_branches is True
    assert repo2.all_branches is True


def test_repo_token_overrides_org(monkeypatch, tmp_path: Path, capsys):
    config_path = tmp_path / "repos.json"
    config_path.write_text(
        json.dumps(
            {
                "repos": {
                    "alice": {
                        "org_token_name": "ORG_TOKEN",
                        "repos": [{"repo_name": "repo1", "repo_token_name": "REPO_TOKEN"}],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("REPO_TOKEN", "repo-secret")
    # org token intentionally missing to ensure no fallback

    repos = main_portable.load_repos_from_json(config_path)
    repo = repos[0]
    assert repo.token == "repo-secret"
    assert repo.token_env_name == "REPO_TOKEN"
    captured = capsys.readouterr()
    assert "ORG_TOKEN" not in captured.err


def test_branch_config_parsing(monkeypatch, tmp_path: Path):
    config_path = tmp_path / "repos.json"
    config_path.write_text(
        json.dumps(
            {
                "repos": {
                    "alice": {
                        "all_branches": False,
                        "branch_regexes": ["feature/.*"],
                        "scan_default_branch": False,
                        "repos": [
                            {"repo_name": "repo1", "all_branches": False, "branch_regexes": ["hotfix/.*"]},
                            "repo2",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    repos = main_portable.load_repos_from_json(config_path)
    repo1, repo2 = repos
    assert repo1.all_branches is False
    assert repo1.branch_regexes == ["hotfix/.*"]
    assert repo1.scan_default_branch is False
    assert repo2.all_branches is False  # inherited from org level
    assert repo2.branch_regexes == ["feature/.*"]
    assert repo2.scan_default_branch is False


def test_branch_regex_required_when_all_branches_false(tmp_path: Path):
    config_path = tmp_path / "repos.json"
    config_path.write_text(
        json.dumps({"repos": {"alice": {"all_branches": False, "repos": ["repo1"]}}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        main_portable.load_repos_from_json(config_path)
