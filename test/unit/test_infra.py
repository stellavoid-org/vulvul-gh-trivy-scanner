import json
from pathlib import Path

from vulvul_gh_trivy_scanner.infra import dump_csv, dump_json


def test_dump_json_creates_file(tmp_path: Path):
    out = tmp_path / "out.json"
    dump_json({"x": 1}, out)

    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data == {"x": 1}


def test_dump_csv_writes_header_and_rows(tmp_path: Path):
    out = tmp_path / "out.csv"
    dump_csv([{"a": 1, "b": 2}, {"a": 3, "b": 4}], out)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert lines[0] == "a,b"
    assert "1,2" in lines[1]
    assert "3,4" in lines[2]


def test_dump_csv_with_no_rows(tmp_path: Path):
    out = tmp_path / "empty.csv"
    dump_csv([], out)
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""
