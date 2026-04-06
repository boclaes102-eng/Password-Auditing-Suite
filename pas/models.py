"""Immutable data models shared across the suite.

Design notes
------------
* All result types are frozen dataclasses — they are value objects that should
  never be mutated after construction.
* ``HashAlgorithm`` inherits from ``str`` so values can be used directly as
  ``hashlib.new()`` names for the algorithms that overlap.
* ``CharacterPool`` is an ``enum.Flag`` so pools compose with bitwise OR and
  the total pool size for any combination is always computable.
* ``StrengthLabel`` stores a display-ready string as its value so formatters
  never need a separate look-up table.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Hash algorithm catalogue
# ---------------------------------------------------------------------------

class HashAlgorithm(str, enum.Enum):
    """Known hash algorithms.  The string value matches hashlib's naming where
    applicable, enabling direct use as ``hashlib.new(algo.value, ...)``.
    """
    MD5          = "md5"
    SHA1         = "sha1"
    SHA224       = "sha224"
    SHA256       = "sha256"
    SHA384       = "sha384"
    SHA512       = "sha512"
    SHA3_256     = "sha3_256"
    SHA3_512     = "sha3_512"
    BLAKE2B      = "blake2b"
    NTLM         = "ntlm"         # MD4 of UTF-16LE — not a hashlib name
    BCRYPT       = "bcrypt"
    ARGON2       = "argon2"
    SCRYPT       = "scrypt"
    PBKDF2_SHA256 = "pbkdf2_sha256"
    PBKDF2_SHA512 = "pbkdf2_sha512"
    UNKNOWN      = "unknown"

    @property
    def is_salted(self) -> bool:
        """True for KDF-based algorithms that embed a salt in the hash string."""
        return self in {
            HashAlgorithm.BCRYPT,
            HashAlgorithm.ARGON2,
            HashAlgorithm.SCRYPT,
            HashAlgorithm.PBKDF2_SHA256,
            HashAlgorithm.PBKDF2_SHA512,
        }

    @property
    def is_hashlib_native(self) -> bool:
        """True when ``hashlib.new(self.value)`` is a valid call."""
        return self in {
            HashAlgorithm.MD5,
            HashAlgorithm.SHA1,
            HashAlgorithm.SHA224,
            HashAlgorithm.SHA256,
            HashAlgorithm.SHA384,
            HashAlgorithm.SHA512,
            HashAlgorithm.SHA3_256,
            HashAlgorithm.SHA3_512,
            HashAlgorithm.BLAKE2B,
        }


# ---------------------------------------------------------------------------
# Hash identification result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, order=True)
class HashCandidate:
    """A proposed algorithm match with a confidence score in [0, 1].

    The ``order=True`` flag makes sorting work out-of-the-box; because we want
    descending confidence, the comparison key negates the confidence value.
    """
    # Sort key comes first so dataclass ordering works correctly (higher confidence = "less")
    _sort_key: float = field(init=False, repr=False, compare=True)
    algorithm: HashAlgorithm = field(compare=False)
    confidence: float        = field(compare=False)
    rationale: str           = field(compare=False)

    def __post_init__(self) -> None:
        # Bypass frozen restriction for the derived sort key
        object.__setattr__(self, "_sort_key", -self.confidence)

    def __repr__(self) -> str:
        return (
            f"HashCandidate(algorithm={self.algorithm.value!r}, "
            f"confidence={self.confidence:.0%}, rationale={self.rationale!r})"
        )


# ---------------------------------------------------------------------------
# Cracking result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CrackResult:
    """A successfully cracked hash."""
    hash_value: str
    algorithm: HashAlgorithm
    plaintext: str
    attempts: int
    elapsed: float          # seconds wall-clock
    method: str             # "dictionary" | "mutation" | "hybrid"


# ---------------------------------------------------------------------------
# Breach check result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BreachResult:
    """HIBP lookup outcome for a single password."""
    password: str
    count: int              # 0 = not found in any known breach
    is_breached: bool

    @classmethod
    def not_found(cls, password: str) -> BreachResult:
        return cls(password=password, count=0, is_breached=False)


# ---------------------------------------------------------------------------
# Password scoring
# ---------------------------------------------------------------------------

class CharacterPool(enum.Flag):
    """Bitfield of character classes present in a password.

    Using ``enum.Flag`` allows pools to be combined with ``|`` and the total
    pool size for any combination computed with a single ``sum()`` call.
    """
    NONE      = 0
    LOWERCASE = enum.auto()   # a-z  (26)
    UPPERCASE = enum.auto()   # A-Z  (26)
    DIGITS    = enum.auto()   # 0-9  (10)
    SYMBOLS   = enum.auto()   # printable non-alnum (32)
    EXTENDED  = enum.auto()   # non-ASCII codepoints (approx. 64)

    @property
    def size(self) -> int:
        """Total number of characters in this pool combination."""
        _SIZES = {
            CharacterPool.LOWERCASE: 26,
            CharacterPool.UPPERCASE: 26,
            CharacterPool.DIGITS:    10,
            CharacterPool.SYMBOLS:   32,
            CharacterPool.EXTENDED:  64,
        }
        return sum(v for flag, v in _SIZES.items() if flag in self)


class StrengthLabel(str, enum.Enum):
    VERY_WEAK   = "Very Weak"
    WEAK        = "Weak"
    FAIR        = "Fair"
    STRONG      = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass
class ScoreResult:
    """Entropy analysis and policy compliance for a single password."""
    password: str
    shannon_entropy: float          # bits per character (observed frequency)
    search_space_bits: float        # log2(pool_size ** length)
    pool: CharacterPool
    length: int
    patterns_found: list[str]       = field(default_factory=list)
    score: int                      = 0     # 0–100
    strength: StrengthLabel         = StrengthLabel.VERY_WEAK
    policy_violations: list[str]    = field(default_factory=list)
    recommendations: list[str]      = field(default_factory=list)


# ---------------------------------------------------------------------------
# Audit report (aggregated pipeline output)
# ---------------------------------------------------------------------------

@dataclass
class AuditReport:
    """Full aggregated results from an audit run."""
    total_hashes: int
    cracked: int
    crack_rate: float
    crack_results: list[CrackResult]        = field(default_factory=list)
    score_results: list[ScoreResult]        = field(default_factory=list)
    breach_results: list[BreachResult]      = field(default_factory=list)
    pattern_tally: dict[str, int]           = field(default_factory=dict)
    algorithm_tally: dict[str, int]         = field(default_factory=dict)
    elapsed: float                          = 0.0
    recommendations: list[str]             = field(default_factory=list)
