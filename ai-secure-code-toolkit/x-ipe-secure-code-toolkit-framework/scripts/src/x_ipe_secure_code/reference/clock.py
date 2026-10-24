"""UTC clock of Reference knowledge; tests patch `utc_now` (never reachable from CLI, request or env)."""

from __future__ import annotations

from datetime import UTC, datetime

FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(at: datetime) -> str:
    return at.astimezone(UTC).strftime(FORMAT)


def parse(text: str) -> datetime:
    """Strict `YYYY-MM-DDTHH:MM:SSZ`; ValueError otherwise."""
    return datetime.strptime(text, FORMAT).replace(tzinfo=UTC)
