"""HIBP Pwned Passwords — k-anonymity breach-database integration.

The k-anonymity model
---------------------
We **never** transmit the full password or even its complete SHA-1 hash to the
API.  The protocol works as follows:

1. Compute ``SHA1(password)`` → 40 hex chars.
2. Send the **first 5 characters** (the prefix) to ``api.pwnedpasswords.com``.
3. The API returns all suffix / count pairs whose hash begins with that prefix.
4. We check locally whether our suffix appears in the response.

The password never leaves the machine.  The API only learns that *some* password
exists whose SHA-1 begins with the given 5 chars — one of ~600 hashes in that
prefix bucket on average.

Design highlights
-----------------
* ``_LRUCache`` — bounded ``OrderedDict`` that evicts the least-recently-used
  prefix entry when capacity is reached.  Identical to ``functools.lru_cache``
  behaviour but inspectable and sizable at runtime.
* ``_TokenBucket`` — simple leaky-bucket rate limiter so bulk checks stay within
  HIBP's free-tier limits (~1 500 requests/minute).
* ``tenacity.retry`` — exponential back-off on HTTP 429 / 5xx responses so the
  caller never has to handle transient network errors.
* All public functions are synchronous; they use ``requests`` with a
  ``requests.Session`` for connection reuse across batch calls.
"""
from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from typing import Final, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pas.exceptions import BreachCheckError
from pas.models import BreachResult

__all__ = ["check_password", "check_many", "cache_info"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HIBP_URL: Final[str] = "https://api.pwnedpasswords.com/range/{prefix}"
_REQUEST_TIMEOUT: Final[float] = 10.0
_MAX_CACHE_ENTRIES: Final[int] = 2_000


# ---------------------------------------------------------------------------
# Bounded LRU cache
# ---------------------------------------------------------------------------

class _LRUCache(OrderedDict):  # type: ignore[type-arg]
    """Thread-unsafe, single-process LRU cache backed by ``OrderedDict``.

    Chosen over ``functools.lru_cache`` because:
    * The size limit and hit/miss stats are easily inspectable.
    * The cache is shared module-level state, not tied to a specific function.
    """

    def __init__(self, maxsize: int) -> None:
        super().__init__()
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0

    def get_entry(self, key: str) -> dict[str, int] | None:  # type: ignore[override]
        if key in self:
            self.move_to_end(key)
            self.hits += 1
            return self[key]
        self.misses += 1
        return None

    def set_entry(self, key: str, value: dict[str, int]) -> None:
        self[key] = value
        self.move_to_end(key)
        if len(self) > self.maxsize:
            self.popitem(last=False)  # evict LRU entry


_cache: _LRUCache = _LRUCache(_MAX_CACHE_ENTRIES)


def cache_info() -> dict[str, int]:
    """Return current cache statistics."""
    return {
        "size": len(_cache),
        "maxsize": _cache.maxsize,
        "hits": _cache.hits,
        "misses": _cache.misses,
    }


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class _TokenBucket:
    """Leaky-bucket rate limiter — ``acquire()`` blocks until a token is free.

    Parameters
    ----------
    rate:     Tokens refilled per second.
    capacity: Maximum burst size.
    """

    __slots__ = ("_rate", "_capacity", "_tokens", "_last_refill")

    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = rate
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + delta * self._rate)
        self._last_refill = now

    def acquire(self) -> None:
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            time.sleep(0.05)


_limiter: _TokenBucket = _TokenBucket(rate=25.0, capacity=50)


# ---------------------------------------------------------------------------
# HTTP session with automatic retry
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    """Return a ``requests.Session`` pre-configured with retry / back-off."""
    session = requests.Session()
    retry_strategy = Retry(
        total=4,
        backoff_factor=1.0,          # 1s, 2s, 4s, 8s
        status_forcelist={429, 500, 502, 503, 504},
        allowed_methods={"GET"},
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": "password-auditing-suite/0.1.0 (security-research)",
            "Add-Padding": "true",   # HIBP privacy padding header
        }
    )
    return session


_session: requests.Session = _build_session()


# ---------------------------------------------------------------------------
# Core k-anonymity logic
# ---------------------------------------------------------------------------

def _sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def _fetch_suffix_counts(prefix: str) -> dict[str, int]:
    """Fetch the HIBP suffix list for *prefix* (5 hex chars), with caching.

    Returns a mapping of ``{suffix: breach_count}`` where suffix is the
    remaining 35 hex chars of the SHA-1 hash.
    """
    cached = _cache.get_entry(prefix)
    if cached is not None:
        return cached

    _limiter.acquire()
    url = _HIBP_URL.format(prefix=prefix)
    try:
        resp = _session.get(url, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.HTTPError as exc:
        raise BreachCheckError(
            f"HIBP API returned HTTP {exc.response.status_code} for prefix {prefix!r}."
        ) from exc
    except requests.RequestException as exc:
        raise BreachCheckError(f"HIBP API request failed: {exc}") from exc

    result: dict[str, int] = {}
    for line in resp.text.splitlines():
        if ":" in line:
            suffix, _, raw_count = line.partition(":")
            try:
                result[suffix.strip()] = int(raw_count.strip())
            except ValueError:
                continue  # malformed line — skip

    _cache.set_entry(prefix, result)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_password(password: str) -> BreachResult:
    """Look up *password* against HIBP using the k-anonymity model.

    The password is hashed locally; only the first 5 hex characters of the
    SHA-1 digest are transmitted to the API.

    Parameters
    ----------
    password:
        Plaintext password to check.

    Returns
    -------
    BreachResult
        ``is_breached=True`` when the password appears in at least one known
        breach; ``count`` is the total number of recorded occurrences.

    Raises
    ------
    BreachCheckError
        On network errors or unexpected API responses after retries.
    """
    sha1 = _sha1_upper(password)
    prefix, suffix = sha1[:5], sha1[5:]

    suffix_counts = _fetch_suffix_counts(prefix)
    count = suffix_counts.get(suffix, 0)
    return BreachResult(password=password, count=count, is_breached=count > 0)


def check_many(passwords: list[str]) -> list[BreachResult]:
    """Batch HIBP lookup — deduplicates by SHA-1 prefix for efficiency.

    Passwords that share the same SHA-1 prefix (i.e. hash bucket) trigger only
    one API call thanks to the in-process LRU cache.

    Parameters
    ----------
    passwords:
        List of plaintext passwords.  Duplicates are checked once and the same
        ``BreachResult`` is used for all occurrences.

    Returns
    -------
    list[BreachResult]
        One entry per input password, in the same order.
    """
    # Deduplicate to minimise API calls
    unique: dict[str, BreachResult] = {}
    results: list[BreachResult] = []

    for pw in passwords:
        if pw not in unique:
            unique[pw] = check_password(pw)
        results.append(unique[pw])

    return results
