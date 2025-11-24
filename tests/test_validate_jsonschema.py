from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest
from jsonschema import exceptions as jsonschema_exceptions

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from validate_jsonschema import validate_json


def _write_json(path: Path, content: dict) -> Path:
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def test_validate_json_accepts_valid_document(tmp_path: Path):
    json_file = _write_json(
        tmp_path / "valid.json",
        {
            "identifikatorForSkjema": "http://schema.brreg.no/skjemanavn.xsd",
            "versjonsnummerForSkjema": "1.0.0",
            "statusForSkjema": "fullfoert",
            "rotelementnavn": {},
        },
    )

    validate_json(json_file, "loesningsmodellnavn.schema.json")


def test_validate_json_rejects_invalid_document(tmp_path: Path):
    json_file = _write_json(
        tmp_path / "invalid.json",
        {
            "identifikatorForSkjema": "http://schema.brreg.no/skjemanavn.xsd",
            "versjonsnummerForSkjema": "1.0.0",
            # Missing required field "rotelementnavn"
        },
    )

    with pytest.raises(jsonschema_exceptions.ValidationError):
        validate_json(json_file, "loesningsmodellnavn.schema.json")


def test_validate_json_requires_known_schema(tmp_path: Path):
    json_file = _write_json(tmp_path / "valid.json", {})

    with pytest.raises(FileNotFoundError):
        validate_json(json_file, "does-not-exist.schema.json")
