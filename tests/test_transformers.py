from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_XMI = REPO_ROOT / "tests" / "data" / "Løsningsmodelleksempel.xml"


def test_pygeoapi_transformer(tmp_path):
    output_path = tmp_path / "resources.yaml"

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "transform_xmi_to_pygeoapiconfig.py"),
            "--xmi",
            str(SAMPLE_XMI),
            "--output",
            str(output_path),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "resources:" in content
    assert "providers:" in content


def test_jsonschema_transformer(tmp_path):
    output_dir = tmp_path / "schemas"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "transform_xmi_to_jsonschema.py"),
            "--xmi",
            str(SAMPLE_XMI),
            "--output-dir",
            str(output_dir),
            "--package",
            "Løsningsmodellnavn",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    schema_file = output_dir / "lsningsmodellnavn.schema.json"
    assert schema_file.exists()
    data = json.loads(schema_file.read_text(encoding="utf-8"))
    assert "$schema" in data
    assert "resources" not in data
