from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


class DocumentValidationError(ValueError):
    def __init__(self, schema_name: str, errors: list[str]):
        self.schema_name = schema_name
        self.errors = errors
        super().__init__(f"invalid {schema_name}: " + "; ".join(errors[:20]))


def load_schema(schema_name: str) -> dict[str, Any]:
    resource = files("proofaudit.schemas").joinpath(schema_name)
    return json.loads(resource.read_text(encoding="utf-8"))


def validate_document(payload: Any, schema_name: str) -> None:
    validator = Draft202012Validator(load_schema(schema_name), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    if errors:
        rendered = [
            f"${''.join(f'[{part!r}]' for part in error.absolute_path)}: {error.message}"
            for error in errors
        ]
        raise DocumentValidationError(schema_name, rendered)

