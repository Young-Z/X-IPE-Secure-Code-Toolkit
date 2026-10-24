"""Reference knowledge (FEATURE-001-E): Maintainer-registered pointers to external sources, a private
7-day cache and fetching only inside a Guard verification through the toolkit egress gate.

v1.0 fetches only `http://127.0.0.1[:port]` fixture servers (human item P-01 parks real domains).
"""

from __future__ import annotations

PARSER_VERSION = "reference-parse/1"
MAX_BYTES = 2 * 1024 * 1024
MAX_TEXT = 256 * 1024
TIMEOUT = 30.0
MAX_FETCHES = 20
CACHE_CAPACITY = 64 * 1024 * 1024
MIN_CACHE_CAPACITY = 1024 * 1024
TTL_DAYS = 7
REGISTRY_REL = "x-ipe-docs/secure-code/knowledge/reference"
CACHE_REL = ".x-ipe/private/secure-code/reference-cache"
CACHE_LOCK_REL = ".x-ipe/private/secure-code/locks/reference-cache.lock"
FETCH_LOCK_REL = ".x-ipe/private/secure-code/locks/reference-fetch.lock"
