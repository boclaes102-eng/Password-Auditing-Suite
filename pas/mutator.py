"""Rule-based wordlist mutation engine.

Architecture
------------
``MutationRule`` is an Abstract Base Class.  Every concrete rule implements a
single ``apply(word) -> Iterator[str]`` generator method.  This design means:

* Rules are trivially composable and independently testable.
* The entire mutation pipeline is *lazy* — a 10 million-word wordlist is
  processed one line at a time without materialising expansions in memory.
* New rule types can be added without touching existing code (open/closed).

``MutationPipeline`` chains rules with ``itertools.chain.from_iterable`` and
de-duplicates on-the-fly using a bounded ``set`` (approximate; clears at cap).

Leet substitutions use ``itertools.product`` to enumerate all 2ⁿ combinations
for a word, capped at ``max_combinations`` to prevent exponential blow-up.
"""
from __future__ import annotations

import itertools
import re
from abc import ABC, abstractmethod
from collections.abc import Generator, Iterator
from dataclasses import dataclass, field
from typing import ClassVar, Final, Sequence

from pas.exceptions import WordlistError

__all__ = [
    "MutationRule",
    "LeetRule",
    "CaseRule",
    "SuffixRule",
    "PrefixRule",
    "DateAppendRule",
    "ReverseRule",
    "DoubleRule",
    "KeyboardWalkRule",
    "MutationConfig",
    "MutationPipeline",
    "DEFAULT_PIPELINE",
    "mutate_wordlist",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LEET_MAP: Final[dict[str, tuple[str, ...]]] = {
    "a": ("@", "4"),
    "e": ("3",),
    "i": ("1", "!"),
    "o": ("0",),
    "s": ("$", "5"),
    "t": ("+", "7"),
    "b": ("8",),
    "g": ("9",),
    "l": ("1",),
}

_COMMON_SUFFIXES: Final[tuple[str, ...]] = (
    "!", "!!", "123", "1234", "12345", "123456",
    "1!", "1!!", "99", "00", "007", "!@#", "@",
    "2022", "2023", "2024", "2025",
    "@1", "#1", "$1", "1", "12",
)

_COMMON_PREFIXES: Final[tuple[str, ...]] = (
    "!", "@", "#", "1", "123", "the", "The",
)

# Keyboard adjacency rows — used for suffix appending
_QWERTY_ROWS: Final[tuple[str, ...]] = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
)

KEYBOARD_WALKS: Final[tuple[str, ...]] = tuple(
    row[start : start + length]
    for row in _QWERTY_ROWS
    for start in range(len(row))
    for length in range(4, min(8, len(row) - start + 1))
)

# Date tokens: years, month+year combos, day+month combos
_YEARS: Final[tuple[str, ...]] = tuple(str(y) for y in range(1970, 2026))
_MONTHS: Final[tuple[str, ...]] = tuple(f"{m:02d}" for m in range(1, 13))
_DAYS: Final[tuple[str, ...]] = tuple(f"{d:02d}" for d in range(1, 32))

DATE_TOKENS: Final[tuple[str, ...]] = (
    *_YEARS,
    *(f"{m}{y}" for y in ("2022", "2023", "2024", "2025") for m in _MONTHS),
    *(f"{d}{m}" for m in _MONTHS for d in _DAYS[:28]),  # cap at 28 to avoid nonsense dates
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MutationConfig:
    """Immutable configuration knobs shared across all rules in a pipeline."""
    max_leet_combinations: int = 64
    max_date_tokens: int = 200
    max_walk_suffixes: int = 30
    max_seen: int = 500_000


# ---------------------------------------------------------------------------
# Abstract base rule
# ---------------------------------------------------------------------------

class MutationRule(ABC):
    """Contract for all mutation rules.

    Subclasses implement ``apply`` as a *generator* so the pipeline stays lazy
    end-to-end.  The ``config`` attribute gives rules access to shared limits.
    """

    #: Subclasses may override this for display purposes.
    name: ClassVar[str] = "unnamed"

    def __init__(self, config: MutationConfig | None = None) -> None:
        self.config = config or MutationConfig()

    @abstractmethod
    def apply(self, word: str) -> Iterator[str]:
        """Yield zero or more mutations of *word*."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


# ---------------------------------------------------------------------------
# Concrete rules
# ---------------------------------------------------------------------------

class LeetRule(MutationRule):
    """Enumerate leet-speak substitutions via ``itertools.product``.

    For a word with *n* substitutable characters, at most
    ``min(2ⁿ, config.max_leet_combinations)`` variants are yielded.
    """

    name = "leet"

    def apply(self, word: str) -> Iterator[str]:
        lower = word.lower()
        positions = [
            (i, _LEET_MAP[c]) for i, c in enumerate(lower) if c in _LEET_MAP
        ]
        if not positions:
            return

        indices, variants = zip(*positions)
        count = 0
        for combo in itertools.product(*variants):
            if count >= self.config.max_leet_combinations:
                return
            chars = list(lower)
            for idx, sub in zip(indices, combo):
                chars[idx] = sub
            yield "".join(chars)
            count += 1


class CaseRule(MutationRule):
    """Yield common case variants: lower, UPPER, Title, Sentence, aLtErNaTe."""

    name = "case"

    def apply(self, word: str) -> Iterator[str]:
        yield word.lower()
        upper = word.upper()
        if upper != word:
            yield upper
        title = word.title()
        if title not in (word, word.lower()):
            yield title
        # Sentence case (first char upper, rest lower)
        sentence = word[0].upper() + word[1:].lower() if word else word
        if sentence not in (word, title):
            yield sentence
        # Alternating case
        alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
        if alt not in (word, upper, title, sentence):
            yield alt


class SuffixRule(MutationRule):
    """Append common suffix tokens (numbers, symbols, years)."""

    name = "suffix"

    def apply(self, word: str) -> Iterator[str]:
        for sfx in _COMMON_SUFFIXES:
            yield word + sfx


class PrefixRule(MutationRule):
    """Prepend common prefix tokens."""

    name = "prefix"

    def apply(self, word: str) -> Iterator[str]:
        for pfx in _COMMON_PREFIXES:
            yield pfx + word


class DateAppendRule(MutationRule):
    """Append date-style tokens (years, month-year combos, day-month combos)."""

    name = "date"

    def apply(self, word: str) -> Iterator[str]:
        for token in DATE_TOKENS[: self.config.max_date_tokens]:
            yield word + token


class ReverseRule(MutationRule):
    """Yield the character-reversed word."""

    name = "reverse"

    def apply(self, word: str) -> Iterator[str]:
        rev = word[::-1]
        if rev != word:
            yield rev


class DoubleRule(MutationRule):
    """Yield the word concatenated with itself."""

    name = "double"

    def apply(self, word: str) -> Iterator[str]:
        yield word + word


class KeyboardWalkRule(MutationRule):
    """Append common keyboard-walk fragments to the word."""

    name = "keyboard"

    def apply(self, word: str) -> Iterator[str]:
        for walk in KEYBOARD_WALKS[: self.config.max_walk_suffixes]:
            yield word + walk


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

@dataclass
class MutationPipeline:
    """Chains ``MutationRule`` instances and streams de-duplicated mutations.

    The pipeline applies every rule to the *original* word (breadth-first).
    De-duplication uses a bounded ``set``; when the set exceeds ``config.max_seen``
    it is pruned to its newest half to keep memory usage predictable.

    Example
    -------
    >>> pipe = MutationPipeline(rules=[CaseRule(), LeetRule(), SuffixRule()])
    >>> list(pipe.mutate("password"))[:5]
    ['password', 'PASSWORD', 'Password', 'p@ssword', 'pa55word']
    """

    rules: Sequence[MutationRule] = field(default_factory=list)
    config: MutationConfig = field(default_factory=MutationConfig)

    def __post_init__(self) -> None:
        if not self.rules:
            cfg = self.config
            self.rules = [
                LeetRule(cfg),
                CaseRule(cfg),
                SuffixRule(cfg),
                PrefixRule(cfg),
                DateAppendRule(cfg),
                ReverseRule(cfg),
                DoubleRule(cfg),
            ]

    # ------------------------------------------------------------------

    def mutate(self, word: str) -> Generator[str, None, None]:
        """Yield all unique mutations for a single *word*."""
        seen: set[str] = {word}
        yield word  # always yield the original first

        for variant in itertools.chain.from_iterable(
            rule.apply(word) for rule in self.rules
        ):
            if variant not in seen:
                seen.add(variant)
                if len(seen) > self.config.max_seen:
                    # Discard oldest half to keep memory bounded
                    pruned = set(list(seen)[len(seen) // 2 :])
                    seen.clear()
                    seen.update(pruned)
                yield variant

    def mutate_many(self, words: Iterator[str]) -> Generator[str, None, None]:
        """Stream mutations for an iterable of base words."""
        for word in words:
            yield from self.mutate(word)

    # ------------------------------------------------------------------
    # Alternative constructor

    @classmethod
    def from_names(
        cls,
        rule_names: Sequence[str],
        config: MutationConfig | None = None,
    ) -> MutationPipeline:
        """Build a pipeline from a list of rule name strings.

        Valid names: ``"leet"``, ``"case"``, ``"suffix"``, ``"prefix"``,
        ``"date"``, ``"reverse"``, ``"double"``, ``"keyboard"``.
        """
        cfg = config or MutationConfig()
        _MAP: dict[str, type[MutationRule]] = {
            "leet":     LeetRule,
            "case":     CaseRule,
            "suffix":   SuffixRule,
            "prefix":   PrefixRule,
            "date":     DateAppendRule,
            "reverse":  ReverseRule,
            "double":   DoubleRule,
            "keyboard": KeyboardWalkRule,
        }
        rules = []
        for name in rule_names:
            try:
                rules.append(_MAP[name](cfg))
            except KeyError:
                raise ValueError(f"Unknown rule name: {name!r}. Valid: {sorted(_MAP)}")
        return cls(rules=rules, config=cfg)


# ---------------------------------------------------------------------------
# Module-level defaults and convenience function
# ---------------------------------------------------------------------------

DEFAULT_PIPELINE: Final[MutationPipeline] = MutationPipeline()


def mutate_wordlist(
    path: str,
    pipeline: MutationPipeline | None = None,
) -> Generator[str, None, None]:
    """Open *path* and stream mutations for every line.

    Parameters
    ----------
    path:
        Absolute or relative path to a UTF-8 wordlist (one entry per line).
    pipeline:
        Mutation pipeline to apply.  Defaults to :data:`DEFAULT_PIPELINE`.
    """
    active = pipeline if pipeline is not None else DEFAULT_PIPELINE
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            yield from active.mutate_many(line.rstrip("\n") for line in fh)
    except OSError as exc:
        raise WordlistError(f"Cannot open wordlist {path!r}: {exc}") from exc
