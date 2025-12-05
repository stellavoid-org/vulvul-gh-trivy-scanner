from vulvul_gh_trivy_scanner.models_repo import GHRepository


def test_mark_accessible_and_inaccessible():
    repo = GHRepository(owner="alice", repo="sample")

    repo.mark_accessible()
    assert repo.is_accessible is True
    assert repo.access_error is None

    repo.mark_inaccessible("no access")
    assert repo.is_accessible is False
    assert repo.access_error == "no access"
