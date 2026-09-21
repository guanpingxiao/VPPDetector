"""Serialization helpers kept outside the in-process analysis API."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any


def to_data(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: to_data(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [to_data(item) for item in value]
    if isinstance(value, list):
        return [to_data(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_data(item) for key, item in value.items()}
    return value
