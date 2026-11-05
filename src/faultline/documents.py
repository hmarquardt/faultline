"""Strict JSON parsing shared by imports, provider evidence and structured checks."""

import json
from typing import Any


def unique_mapping(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise ValueError("Document mapping keys must be strings")
        if key in result:
            raise ValueError("Duplicate document keys require human clarification")
        result[key] = value
    return result


def _reject_constant(value: str):
    raise ValueError("Non-finite numbers are not valid JSON")


def load_json(text: str | bytes | bytearray) -> Any:
    return json.loads(text, object_pairs_hook=unique_mapping, parse_constant=_reject_constant)
