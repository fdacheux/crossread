"""Shared pytest fixtures and lightweight fakes for deterministic offline TNR.

All tests in `pipeline/tests/` run with zero live internet access, zero live
Supabase calls, and zero live LLM API calls so they can gate every PR at $0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class FakeQueryResult:
    data: list[dict[str, Any]] = field(default_factory=list)


class FakeTableQuery:
    """Minimal fluent mock mimicking supabase-py table query chaining."""

    def __init__(self, store: dict[str, list[dict[str, Any]]], table_name: str) -> None:
        self._store = store
        self._table = table_name
        self._op = "select"
        self._payload: Any = None
        self._filters: list[tuple[str, str, Any]] = []
        self._limit: int | None = None

    def select(self, *_args: Any, **_kwargs: Any) -> "FakeTableQuery":
        self._op = "select"
        return self

    def insert(self, payload: Any) -> "FakeTableQuery":
        self._op = "insert"
        self._payload = payload
        return self

    def eq(self, col: str, val: Any) -> "FakeTableQuery":
        self._filters.append(("eq", col, val))
        return self

    def gte(self, col: str, val: Any) -> "FakeTableQuery":
        self._filters.append(("gte", col, val))
        return self

    def in_(self, col: str, vals: list[Any]) -> "FakeTableQuery":
        self._filters.append(("in", col, set(vals)))
        return self

    def limit(self, count: int) -> "FakeTableQuery":
        self._limit = count
        return self

    def execute(self) -> FakeQueryResult:
        rows = self._store.setdefault(self._table, [])
        if self._op == "insert":
            items = self._payload if isinstance(self._payload, list) else [self._payload]
            rows.extend(items)
            return FakeQueryResult(data=list(items))

        matched = []
        for row in rows:
            ok = True
            for kind, col, target in self._filters:
                val = row.get(col)
                if kind == "eq" and val != target:
                    ok = False
                elif kind == "in" and val not in target:
                    ok = False
                elif kind == "gte" and (val is None or str(val) < str(target)):
                    ok = False
            if ok:
                matched.append(row)

        if self._limit is not None:
            matched = matched[: self._limit]
        return FakeQueryResult(data=matched)


class FakeSupabaseClient:
    """In-memory stand-in for `supabase.Client` used in deterministic TNR tests."""

    def __init__(self, initial: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.store: dict[str, list[dict[str, Any]]] = initial or {}

    def table(self, name: str) -> FakeTableQuery:
        return FakeTableQuery(self.store, name)


@pytest.fixture
def context() -> dict[str, Any]:
    """Per-scenario mutable state dictionary shared across BDD Given/When/Then steps."""
    return {}
