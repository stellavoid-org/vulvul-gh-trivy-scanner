import pytest

from vulvul_gh_trivy_scanner import main_actions


def test_main_actions_not_implemented(monkeypatch):
    monkeypatch.setattr(main_actions, "__name__", "src.main_actions")
    with pytest.raises(NotImplementedError):
        main_actions.main()
