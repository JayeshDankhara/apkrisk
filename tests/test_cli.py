import json
import os

import pytest

from apkrisk.cli import build_parser, main

TEST_APK = os.environ.get("APKRISK_TEST_APK")


def test_missing_path_returns_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing.apk")]) == 2


def test_empty_folder_returns_2(tmp_path):
    assert main(["scan", str(tmp_path)]) == 2


def test_corrupt_apk_reported(tmp_path, capsys):
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"not a zip")
    assert main(["scan", str(bad)]) == 2
    assert "bad.apk" in capsys.readouterr().err


def test_parser_defaults():
    args = build_parser().parse_args(["scan", "a.apk"])
    assert args.model == "svm" and args.top == 10 and not args.json


@pytest.mark.skipif(not TEST_APK, reason="set APKRISK_TEST_APK to a real APK")
def test_scan_real_apk_json(capsys):
    assert main(["scan", TEST_APK, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["label"] in {"benign", "malware"}
    assert len(out["sha256"]) == 64


@pytest.mark.skipif(not TEST_APK, reason="set APKRISK_TEST_APK to a real APK")
def test_features_csv(tmp_path):
    out = tmp_path / "f.csv"
    assert main(["features", TEST_APK, "-o", str(out)]) == 0
    header, row = out.read_text().splitlines()[:2]
    assert len(header.split(",")) == 810  # sha256 + package_name + 808 features
