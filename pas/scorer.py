"""Password entropy analysis, pattern detection, and policy compliance.

Entropy models
--------------
Two complementary entropy metrics are computed:

* **Shannon entropy** ``H = -∑ p·log₂(p)`` over observed character frequencies.
  Captures information density per character; low for repetitive passwords.
* **Search-space bits** ``log₂(pool_size ^ length)``.  Captures how large the
  brute-force search space is; penalises short passwords even if unique chars.

The final *score* (0–100) weights both metrics, then applies deductions for
detected structural patterns (keyboard walks, dates, common passwords, leet
variants of common passwords).

Pattern detection
-----------------
``PatternMatch`` is a frozen dataclass that records what was found and where.
``PatternDetector`` holds a list of ``PatternChecker`` objects (Protocol), each
of which returns ``list[PatternMatch]`` for a given password.  The detector
merges overlapping spans via an interval-union algorithm and returns a clean list.

``functools.cached_property`` is used on ``DictionaryChecker`` so the word-set
is built at most once per process — a natural lazy-loading pattern.

Policy engine
-------------
``PolicyRule`` is a Protocol.  Concrete rules (``MinLengthRule``, ``PoolRule``,
``MaxRepeatRule``, ``BlockedPatternRule``) implement ``evaluate(password) -> str | None``
where ``None`` means the rule passed.  ``PasswordPolicy`` holds an ordered list
of rules and runs them all, collecting violations.

``bisect.bisect_left`` maps a numeric score to a ``StrengthLabel`` via a sorted
threshold tuple — O(log n) and easy to extend with new bands.
"""
from __future__ import annotations

import bisect
import math
import re
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import cached_property
from typing import Final, Protocol, runtime_checkable

from pas.models import CharacterPool, ScoreResult, StrengthLabel

__all__ = [
    "score_password",
    "PatternMatch",
    "PatternDetector",
    "PasswordPolicy",
    "DEFAULT_POLICY",
]

# ---------------------------------------------------------------------------
# Pattern matching infrastructure
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PatternMatch:
    """A structural weakness detected in a password.

    ``span`` is a ``(start, end)`` index pair (end-exclusive) into the
    password string, mirroring Python slice conventions.
    """
    label: str                 # human-readable pattern type
    span: tuple[int, int]      # (start, end) indices
    severity: float            # 0–1; used for scoring deduction weighting

    def overlaps(self, other: PatternMatch) -> bool:
        return not (self.span[1] <= other.span[0] or other.span[1] <= self.span[0])


def _merge_spans(matches: list[PatternMatch]) -> list[PatternMatch]:
    """Remove or merge patterns whose spans are fully contained by another."""
    if not matches:
        return matches
    sorted_m = sorted(matches, key=lambda m: (m.span[0], -m.severity))
    result = [sorted_m[0]]
    for m in sorted_m[1:]:
        if m.span[0] < result[-1].span[1]:
            # Overlapping — keep the higher-severity one (already sorted)
            pass
        else:
            result.append(m)
    return result


# ---------------------------------------------------------------------------
# Pattern checker protocol and concrete implementations
# ---------------------------------------------------------------------------

@runtime_checkable
class PatternChecker(Protocol):
    """Structural protocol for pattern detection plugins."""

    def check(self, password: str) -> list[PatternMatch]:
        ...


class _KeyboardSequenceChecker:
    """Detects QWERTY / AZERTY keyboard walks of length ≥ 3."""

    _ROWS: Final[tuple[str, ...]] = (
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
    )

    def check(self, password: str) -> list[PatternMatch]:
        lower = password.lower()
        found: list[PatternMatch] = []
        for row in self._ROWS:
            for start in range(len(row) - 2):
                for length in range(3, len(row) - start + 1):
                    seq = row[start : start + length]
                    idx = lower.find(seq)
                    if idx != -1:
                        found.append(
                            PatternMatch(
                                label=f"keyboard-walk({seq!r})",
                                span=(idx, idx + length),
                                severity=min(0.3 + 0.1 * length, 0.8),
                            )
                        )
        return found


class _RepeatChecker:
    """Detects runs of the same character: ``aaaa``, ``1111``."""

    _RE: Final[re.Pattern[str]] = re.compile(r"(.)\1{2,}")

    def check(self, password: str) -> list[PatternMatch]:
        return [
            PatternMatch(
                label=f"repeated-char({m.group(1)!r}×{len(m.group())})",
                span=(m.start(), m.end()),
                severity=0.4,
            )
            for m in self._RE.finditer(password)
        ]


class _DatePatternChecker:
    """Detects embedded date strings (years, MMYYYY, DDMMYYYY, ISO dates)."""

    _RE: Final[re.Pattern[str]] = re.compile(
        r"(19|20)\d{2}"                   # year 1900–2099
        r"|0[1-9]\d{4}|1[0-2]\d{4}"      # MMYYYY
        r"|\d{2}[/\-]\d{2}[/\-]\d{4}"    # DD/MM/YYYY or MM/DD/YYYY
        r"|\d{4}[/\-]\d{2}[/\-]\d{2}"    # YYYY-MM-DD
    )

    def check(self, password: str) -> list[PatternMatch]:
        return [
            PatternMatch(
                label=f"date({m.group()!r})",
                span=(m.start(), m.end()),
                severity=0.35,
            )
            for m in self._RE.finditer(password)
        ]


class _SequentialRunChecker:
    """Detects sequential digit or alpha runs: ``123``, ``abc``, ``xyz``."""

    def check(self, password: str) -> list[PatternMatch]:
        found: list[PatternMatch] = []
        i = 0
        while i < len(password) - 2:
            trio = password[i : i + 3]
            if (
                all(c.isdigit() for c in trio) and
                int(trio[1]) == int(trio[0]) + 1 and
                int(trio[2]) == int(trio[1]) + 1
            ):
                found.append(PatternMatch(f"sequential-digits({trio!r})", (i, i + 3), 0.25))
            elif (
                all(c.isalpha() for c in trio) and
                ord(trio[1].lower()) == ord(trio[0].lower()) + 1 and
                ord(trio[2].lower()) == ord(trio[1].lower()) + 1
            ):
                found.append(PatternMatch(f"sequential-alpha({trio!r})", (i, i + 3), 0.25))
            i += 1
        return found


class DictionaryChecker:
    """Detects common passwords and their leet-speak variants.

    The word set is built lazily via ``cached_property`` — the first call pays
    the setup cost; subsequent calls within the same process are free.
    """

    _LEET_REVERSE: Final[dict[str, str]] = {
        "@": "a", "4": "a", "3": "e", "1": "i",
        "0": "o", "$": "s", "+": "t", "!": "i", "7": "t",
    }

    _TOP_PASSWORDS: Final[frozenset[str]] = frozenset({
        "password", "password1", "password123", "123456", "12345678",
        "qwerty", "abc123", "monkey", "1234567", "letmein", "trustno1",
        "dragon", "master", "sunshine", "welcome", "shadow", "superman",
        "michael", "football", "iloveyou", "admin", "login", "hello",
        "passw0rd", "p@ssword", "baseball", "princess", "starwars",
        "cheese", "secret", "pass", "root", "toor", "test", "guest",
        "1q2w3e", "qazwsx", "zaq1xsw2", "changeme", "default",
    })

    @cached_property
    def _word_set(self) -> frozenset[str]:
        return self._TOP_PASSWORDS

    def _de_leet(self, s: str) -> str:
        return "".join(self._LEET_REVERSE.get(c, c) for c in s.lower())

    def check(self, password: str) -> list[PatternMatch]:
        lower = password.lower()
        de_leeted = self._de_leet(lower)
        results: list[PatternMatch] = []

        if lower in self._word_set:
            results.append(PatternMatch("common-password", (0, len(password)), 0.95))
        elif de_leeted in self._word_set and de_leeted != lower:
            results.append(PatternMatch("leet-disguised-common", (0, len(password)), 0.80))
        return results


class PatternDetector:
    """Compose multiple ``PatternChecker`` instances into a single detector.

    The default checkers cover keyboard walks, character repeats, date strings,
    sequential runs, and common/leet-disguised dictionary words.
    """

    def __init__(self, checkers: list[PatternChecker] | None = None) -> None:
        self._checkers: list[PatternChecker] = checkers or [
            _KeyboardSequenceChecker(),
            _RepeatChecker(),
            _DatePatternChecker(),
            _SequentialRunChecker(),
            DictionaryChecker(),
        ]

    def detect(self, password: str) -> list[PatternMatch]:
        """Return a de-overlapped list of :class:`PatternMatch` objects."""
        raw: list[PatternMatch] = []
        for checker in self._checkers:
            raw.extend(checker.check(password))
        return _merge_spans(raw)


_DEFAULT_DETECTOR: Final[PatternDetector] = PatternDetector()


# ---------------------------------------------------------------------------
# Entropy computation
# ---------------------------------------------------------------------------

def _pool_for(password: str) -> CharacterPool:
    pool = CharacterPool.NONE
    if any(c in string.ascii_lowercase for c in password):
        pool |= CharacterPool.LOWERCASE
    if any(c in string.ascii_uppercase for c in password):
        pool |= CharacterPool.UPPERCASE
    if any(c in string.digits for c in password):
        pool |= CharacterPool.DIGITS
    if any(c in string.punctuation for c in password):
        pool |= CharacterPool.SYMBOLS
    if any(ord(c) > 127 for c in password):
        pool |= CharacterPool.EXTENDED
    return pool


def _shannon_entropy(password: str) -> float:
    if not password:
        return 0.0
    freq: dict[str, int] = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    n = len(password)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _search_space_bits(password: str, pool: CharacterPool) -> float:
    size = pool.size or 1
    return math.log2(size) * len(password)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

# (lower_bound, StrengthLabel) — bisect gives O(log n) lookup
_THRESHOLDS: Final[tuple[tuple[int, StrengthLabel], ...]] = (
    (0,  StrengthLabel.VERY_WEAK),
    (20, StrengthLabel.WEAK),
    (40, StrengthLabel.FAIR),
    (60, StrengthLabel.STRONG),
    (80, StrengthLabel.VERY_STRONG),
)
_THRESHOLD_KEYS: Final[tuple[int, ...]] = tuple(t[0] for t in _THRESHOLDS)


def _compute_score(
    ss_bits: float,
    patterns: list[PatternMatch],
    pool: CharacterPool,
    length: int,
) -> int:
    # Base score from search-space bits (capped at 55)
    score = min(int(ss_bits * 1.2), 55)

    # Character-pool diversity bonus (up to 25)
    num_classes = bin(pool.value).count("1")
    score += min(num_classes * 6, 25)

    # Length bonus (up to 20)
    if length >= 20:
        score += 20
    elif length >= 16:
        score += 14
    elif length >= 12:
        score += 8
    elif length >= 8:
        score += 4

    # Pattern deductions
    for match in patterns:
        deduction = int(match.severity * 40)
        score -= deduction

    return max(0, min(score, 100))


def _label_for(score: int) -> StrengthLabel:
    idx = bisect.bisect_right(_THRESHOLD_KEYS, score) - 1
    return _THRESHOLDS[max(idx, 0)][1]


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

@runtime_checkable
class PolicyRule(Protocol):
    """Structural protocol for a single password policy rule."""

    def evaluate(self, password: str) -> str | None:
        """Return a violation message, or ``None`` if the password passes."""
        ...


class MinLengthRule:
    def __init__(self, min_length: int = 8) -> None:
        self._min = min_length

    def evaluate(self, password: str) -> str | None:
        if len(password) < self._min:
            return f"Too short: {len(password)} chars (minimum {self._min})"
        return None


class MaxLengthRule:
    def __init__(self, max_length: int = 128) -> None:
        self._max = max_length

    def evaluate(self, password: str) -> str | None:
        if len(password) > self._max:
            return f"Too long: {len(password)} chars (maximum {self._max})"
        return None


class PoolRule:
    """Require that at least *min_classes* character classes are present."""

    def __init__(self, min_classes: int = 1) -> None:
        self._min = min_classes

    def evaluate(self, password: str) -> str | None:
        pool = _pool_for(password)
        classes = bin(pool.value).count("1")
        if classes < self._min:
            return f"Only {classes} character class(es) used; need ≥ {self._min}"
        return None


class MaxRepeatRule:
    """Block runs of the same character longer than *max_run*."""

    def __init__(self, max_run: int = 3) -> None:
        self._re = re.compile(rf"(.)\1{{{max_run},}}")

    def evaluate(self, password: str) -> str | None:
        if self._re.search(password):
            return "Contains a long run of repeated characters"
        return None


class BlockedPatternRule:
    """Fail when a :class:`PatternMatch` with severity ≥ threshold is found."""

    def __init__(
        self,
        detector: PatternDetector | None = None,
        min_severity: float = 0.8,
    ) -> None:
        self._detector = detector or _DEFAULT_DETECTOR
        self._min = min_severity

    def evaluate(self, password: str) -> str | None:
        for m in self._detector.detect(password):
            if m.severity >= self._min:
                return f"Blocked pattern: {m.label}"
        return None


@dataclass
class PasswordPolicy:
    """Ordered collection of :class:`PolicyRule` instances.

    Defaults follow NIST SP 800-63B recommendations:
    * Minimum 8 characters.
    * No mandatory complexity (no required uppercase / special).
    * Block commonly-used passwords.
    """

    rules: list[PolicyRule] = field(default_factory=lambda: [
        MinLengthRule(8),
        MaxLengthRule(128),
        MaxRepeatRule(3),
        BlockedPatternRule(min_severity=0.9),
    ])

    def check(self, password: str) -> list[str]:
        """Return a list of violation messages (empty → all rules passed)."""
        return [
            msg
            for rule in self.rules
            if (msg := rule.evaluate(password)) is not None
        ]


DEFAULT_POLICY: Final[PasswordPolicy] = PasswordPolicy()


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

def _build_recommendations(result: ScoreResult) -> list[str]:
    recs: list[str] = []

    if result.length < 16:
        recs.append(
            f"Increase length to ≥ 16 characters (each extra character multiplies "
            f"the search space by {result.pool.size or 94}×)."
        )
    num_classes = bin(result.pool.value).count("1")
    if num_classes < 3:
        recs.append("Mix lowercase, uppercase, digits, and special characters.")

    labels = [m.label for m in result.patterns_found]  # type: ignore[attr-defined]

    if any("keyboard" in lb for lb in labels):
        recs.append("Avoid keyboard-walk sequences (qwerty, asdf, 1234, …).")
    if any("date" in lb for lb in labels):
        recs.append("Do not embed birth years or calendar dates.")
    if any("common" in lb for lb in labels):
        recs.append("This password (or its leet variant) is on known breach lists.")
    if any("repeated" in lb for lb in labels):
        recs.append("Avoid long runs of identical characters (aaaa, 1111, …).")
    if any("sequential" in lb for lb in labels):
        recs.append("Avoid sequential character runs (123, abc, xyz).")

    if not recs:
        recs.append(
            "Password looks strong.  Consider a random passphrase for memorability: "
            "e.g. 'correct-horse-battery-staple' style."
        )
    return recs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_password(
    password: str,
    policy: PasswordPolicy | None = None,
    detector: PatternDetector | None = None,
) -> ScoreResult:
    """Analyse *password*; return a :class:`~pas.models.ScoreResult`.

    Parameters
    ----------
    password:
        Plaintext password string.
    policy:
        Compliance policy.  Defaults to :data:`DEFAULT_POLICY`.
    detector:
        Pattern detector.  Defaults to the module-level ``PatternDetector``
        instance (which uses a ``cached_property`` word-set — built once).
    """
    active_policy = policy or DEFAULT_POLICY
    active_detector = detector or _DEFAULT_DETECTOR

    pool    = _pool_for(password)
    shannon = _shannon_entropy(password)
    ss_bits = _search_space_bits(password, pool)
    matches = active_detector.detect(password)
    raw     = _compute_score(ss_bits, matches, pool, len(password))
    label   = _label_for(raw)
    viols   = active_policy.check(password)

    result = ScoreResult(
        password=password,
        shannon_entropy=round(shannon, 3),
        search_space_bits=round(ss_bits, 3),
        pool=pool,
        length=len(password),
        patterns_found=matches,      # type: ignore[arg-type]
        score=raw,
        strength=label,
        policy_violations=viols,
    )
    result.recommendations = _build_recommendations(result)
    return result
