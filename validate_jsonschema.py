#!/usr/bin/env python3
"""Validate a JSON document against one of the generated JSON Schema files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft6Validator, RefResolver, exceptions

DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parent / "jsonschemas"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse JSON file {path}: {exc}") from exc


def _available_schema_names(schema_dir: Path) -> list[str]:
    return sorted(p.name for p in schema_dir.glob("*.schema.json"))


def validate_json(json_path: Path, schema_filename: str, schema_dir: Path = DEFAULT_SCHEMA_DIR) -> None:
    """Validate ``json_path`` using the schema ``schema_filename`` in ``schema_dir``."""
    if Path(schema_filename).name != schema_filename:
        raise ValueError("Schema name must be a file name (no path separators).")
    if not json_path.exists():
        raise FileNotFoundError(f"JSON file not found: {json_path}")
    if not schema_dir.exists():
        raise FileNotFoundError(f"Schema directory not found: {schema_dir}")

    schema_path = schema_dir / schema_filename
    if not schema_path.exists():
        available = _available_schema_names(schema_dir)
        hint = f" Available schemas: {', '.join(available)}" if available else ""
        raise FileNotFoundError(f"Schema file '{schema_filename}' not found in {schema_dir}.{hint}")

    schema = _load_json(schema_path)
    instance = _load_json(json_path)

    resolver = RefResolver(base_uri=schema_path.as_uri(), referrer=schema)
    validator = Draft6Validator(schema, resolver=resolver)
    validator.validate(instance)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        required=True,
        type=Path,
        help="Path to the JSON document to validate.",
    )
    parser.add_argument(
        "--schema-file",
        required=True,
        help="File name of the schema inside the jsonschemas directory (e.g. loesningsmodellnavn.schema.json).",
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=DEFAULT_SCHEMA_DIR,
        help=f"Directory containing schema files (default: {DEFAULT_SCHEMA_DIR}).",
    )
    args = parser.parse_args(argv)

    try:
        validate_json(args.json, args.schema_file, args.schema_dir)
    except (exceptions.ValidationError, FileNotFoundError, ValueError) as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 1

    print(f"{args.json} is valid according to {args.schema_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
