"""Heuristic hash-type identification.

Identification strategy
-----------------------
1. **Prefix matching** (highest confidence) — salted/KDF schemes embed their
   algorithm in a ``$...$`` prefix that is unambiguous.
2. **Length + charset matching** — unsalted hex digests have a fixed length per
   algorithm; a pure-hex string of the right length gets a high base confidence.
3. **Contextual scoring adjustments** — e.g. a 32-char hex string is more
   likely MD5 than NTLM in most real-world dumps, so MD5 gets a slight boost.

The result is a list of :class:`~pas.models.HashCandidate` sorted by
descending confidence (the ``order=True`` frozen-dataclass sort handles this
automatically).  The caller drives downstream cracking with ``candidates[0]``.

Design notes
------------
* The algorithm catalogue is a module-level ``tuple[HashSignature, ...]`` —
  immutable, iterable, defined once, no heap allocation on repeated calls.
* ``bisect`` provides O(log n) lookup into the length-sorted sub-catalogue for
  unsalted hex hashes, though in practice the catalogue is tiny.
* No I/O, no state, no side effects — every function is pure.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Final, Pattern

from pas.exceptions import HashIdentificationError
from pas.models import HashAlgorithm, HashCandidate

__all__ = ["identify", "identify_many"]


# ---------------------------------------------------------------------------
# Hash signature catalogue
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HashSignature:
    """Structural description of one hash format.

    ``hex_length`` is -1 for variable-length or non-hex formats.
    ``pattern`` is used for prefix-based detection; ``None`` means length-only.
    ``base_confidence`` reflects how uniquely the signature identifies this algo.
    ``hashcat_id`` is provided for reference / downstream tooling.
    """
    algorithm: HashAlgorithm
    hex_length: int                      # -1 = variable / non-hex
    pattern: Pattern[str] | None         # compiled regex; None = length-only
    base_confidence: float
    hashcat_id: int | None = None
    description: str = ""

    def matches_prefix(self, hash_str: str) -> bool:
        return self.pattern is not None and bool(self.pattern.match(hash_str))


_CATALOGUE: Final[tuple[HashSignature, ...]] = (
    # --- Salted / KDF --- (prefix-based; high confidence)
    HashSignature(
        algorithm=HashAlgorithm.BCRYPT,
        hex_length=-1,
        pattern=re.compile(r"^\$2[abxy]\$\d{2}\$.{53}$"),
        base_confidence=0.99,
        hashcat_id=3200,
        description="bcrypt — $2x$cost$salt+hash",
    ),
    HashSignature(
        algorithm=HashAlgorithm.ARGON2,
        hex_length=-1,
        pattern=re.compile(r"^\$argon2(i|d|id)\$"),
        base_confidence=0.99,
        hashcat_id=None,
        description="Argon2 — $argon2id$... prefix",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SCRYPT,
        hex_length=-1,
        pattern=re.compile(r"^\$scrypt\$"),
        base_confidence=0.99,
        hashcat_id=8900,
        description="scrypt — $scrypt$ prefix",
    ),
    HashSignature(
        algorithm=HashAlgorithm.PBKDF2_SHA256,
        hex_length=-1,
        pattern=re.compile(r"^\$pbkdf2-sha256\$|^pbkdf2_sha256\$"),
        base_confidence=0.99,
        hashcat_id=10900,
        description="PBKDF2-SHA256 — Django / passlib format",
    ),
    HashSignature(
        algorithm=HashAlgorithm.PBKDF2_SHA512,
        hex_length=-1,
        pattern=re.compile(r"^\$pbkdf2-sha512\$|^pbkdf2_sha512\$"),
        base_confidence=0.99,
        hashcat_id=12000,
        description="PBKDF2-SHA512",
    ),
    # --- Unsalted hex --- (length-based)
    HashSignature(
        algorithm=HashAlgorithm.MD5,
        hex_length=32,
        pattern=None,
        base_confidence=0.80,
        hashcat_id=0,
        description="MD5 — 32-char hex",
    ),
    HashSignature(
        algorithm=HashAlgorithm.NTLM,
        hex_length=32,
        pattern=None,
        base_confidence=0.60,
        hashcat_id=1000,
        description="NTLM (MD4/UTF-16LE) — 32-char hex; same length as MD5",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SHA1,
        hex_length=40,
        pattern=None,
        base_confidence=0.90,
        hashcat_id=100,
        description="SHA-1 — 40-char hex",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SHA224,
        hex_length=56,
        pattern=None,
        base_confidence=0.92,
        hashcat_id=1300,
        description="SHA-224 — 56-char hex",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SHA256,
        hex_length=64,
        pattern=None,
        base_confidence=0.78,
        hashcat_id=1400,
        description="SHA-256 — 64-char hex",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SHA3_256,
        hex_length=64,
        pattern=None,
        base_confidence=0.50,
        hashcat_id=17300,
        description="SHA3-256 — 64-char hex; same length as SHA-256",
    ),
    HashSignature(
        algorithm=HashAlgorithm.BLAKE2B,
        hex_length=64,
        pattern=None,
        base_confidence=0.35,
        hashcat_id=600,
        description="BLAKE2b-256 — 64-char hex (less common than SHA-256)",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SHA384,
        hex_length=96,
        pattern=None,
        base_confidence=0.93,
        hashcat_id=10800,
        description="SHA-384 — 96-char hex",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SHA512,
        hex_length=128,
        pattern=None,
        base_confidence=0.85,
        hashcat_id=1700,
        description="SHA-512 — 128-char hex",
    ),
    HashSignature(
        algorithm=HashAlgorithm.SHA3_512,
        hex_length=128,
        pattern=None,
        base_confidence=0.55,
        hashcat_id=17500,
        description="SHA3-512 — 128-char hex; same length as SHA-512",
    ),
)

# Pre-built length → signatures index for fast bisect lookups
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")
_LENGTH_INDEX: Final[dict[int, list[HashSignature]]] = {}
for _sig in _CATALOGUE:
    if _sig.hex_length > 0 and _sig.pattern is None:
        _LENGTH_INDEX.setdefault(_sig.hex_length, []).append(_sig)

# Prefix-based signatures (pattern is not None), sorted for sequential scan
_PREFIX_SIGS: Final[tuple[HashSignature, ...]] = tuple(
    sig for sig in _CATALOGUE if sig.pattern is not None
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def identify(hash_string: str) -> list[HashCandidate]:
    """Return candidates sorted by descending confidence for *hash_string*.

    Parameters
    ----------
    hash_string:
        Raw hash value — may include ``$``-prefixed scheme strings.

    Returns
    -------
    list[HashCandidate]
        At least one entry; falls back to ``HashAlgorithm.UNKNOWN`` with 0 %
        confidence when nothing matches.

    Raises
    ------
    HashIdentificationError
        When *hash_string* is empty.
    """
    h = hash_string.strip()
    if not h:
        raise HashIdentificationError("Empty hash string provided.")

    candidates: list[HashCandidate] = []

    # --- Pass 1: prefix-based detection (unambiguous) ---
    for sig in _PREFIX_SIGS:
        if sig.matches_prefix(h):
            candidates.append(
                HashCandidate(
                    algorithm=sig.algorithm,
                    confidence=sig.base_confidence,
                    rationale=sig.description,
                )
            )

    if candidates:
        return sorted(candidates)

    # --- Pass 2: hex-length detection ---
    if _HEX_RE.match(h):
        length = len(h)
        for sig in _LENGTH_INDEX.get(length, []):
            candidates.append(
                HashCandidate(
                    algorithm=sig.algorithm,
                    confidence=sig.base_confidence,
                    rationale=sig.description,
                )
            )

    if not candidates:
        candidates.append(
            HashCandidate(
                algorithm=HashAlgorithm.UNKNOWN,
                confidence=0.0,
                rationale="No structural pattern matched.",
            )
        )

    return sorted(candidates)


def identify_many(hashes: list[str]) -> dict[str, list[HashCandidate]]:
    """Batch-identify a collection of hash strings.

    Returns a mapping from the original hash string to its ranked candidate
    list.  Strings that raise :class:`~pas.exceptions.HashIdentificationError`
    are mapped to a single UNKNOWN candidate.
    """
    result: dict[str, list[HashCandidate]] = {}
    for h in hashes:
        try:
            result[h] = identify(h)
        except HashIdentificationError:
            result[h] = [
                HashCandidate(
                    algorithm=HashAlgorithm.UNKNOWN,
                    confidence=0.0,
                    rationale="Empty or invalid input.",
                )
            ]
    return result
