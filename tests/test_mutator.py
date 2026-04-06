"""Tests for the wordlist mutation engine."""
from __future__ import annotations

import pytest

from pas.mutator import (
    CaseRule,
    DateAppendRule,
    DoubleRule,
    LeetRule,
    MutationConfig,
    MutationPipeline,
    PrefixRule,
    ReverseRule,
    SuffixRule,
)


class TestLeetRule:
    def test_basic_substitution(self) -> None:
        # LeetRule replaces ALL substitutable chars simultaneously via itertools.product.
        # "password" has a→@/4, s→$/5, s→$/5, o→0
        # First combo: p@$$w0rd (a→@, s→$, s→$, o→0)
        rule = LeetRule()
        results = list(rule.apply("password"))
        assert any("0" in r and ("$" in r or "5" in r) for r in results)
        assert len(results) > 0

    def test_no_leet_chars(self) -> None:
        rule = LeetRule()
        results = list(rule.apply("bbb"))  # 'b' maps to '8'
        assert any("888" in r for r in results)

    def test_respects_max_combinations(self) -> None:
        # "aaaaaa" has 6 substitutable 'a' chars → 2^6 = 64 combos; cap=16
        config = MutationConfig(max_leet_combinations=16)
        rule = LeetRule(config)
        results = list(rule.apply("aaaaaa"))
        assert len(results) <= 16

    def test_empty_word_yields_nothing(self) -> None:
        rule = LeetRule()
        assert list(rule.apply("xyz")) == []  # no leet chars in xyz


class TestCaseRule:
    def test_yields_lower_and_upper(self) -> None:
        variants = list(CaseRule().apply("hello"))
        assert "hello" in variants
        assert "HELLO" in variants

    def test_title_case(self) -> None:
        variants = list(CaseRule().apply("hello"))
        assert "Hello" in variants

    def test_no_duplicates_for_already_upper(self) -> None:
        variants = list(CaseRule().apply("ABC"))
        # Should not contain "ABC" twice (upper == original, deduplicated by pipeline)
        assert variants.count("ABC") <= 1


class TestReverseRule:
    def test_reverses(self) -> None:
        assert list(ReverseRule().apply("abc")) == ["cba"]

    def test_palindrome_yields_nothing(self) -> None:
        assert list(ReverseRule().apply("racecar")) == []


class TestDoubleRule:
    def test_doubles(self) -> None:
        assert list(DoubleRule().apply("pass")) == ["passpass"]


class TestSuffixRule:
    def test_yields_suffixed_words(self) -> None:
        results = list(SuffixRule().apply("pass"))
        assert "pass!" in results
        assert "pass123" in results


class TestPrefixRule:
    def test_yields_prefixed_words(self) -> None:
        results = list(PrefixRule().apply("word"))
        assert "!word" in results
        assert "1word" in results


class TestMutationPipeline:
    def test_always_yields_original(self) -> None:
        pipeline = MutationPipeline(rules=[LeetRule()])
        results = list(pipeline.mutate("abc"))
        assert "abc" in results

    def test_deduplication(self) -> None:
        # Applying suffix "!" twice should not produce duplicates
        pipeline = MutationPipeline(rules=[SuffixRule(), SuffixRule()])
        results = list(pipeline.mutate("pass"))
        assert len(results) == len(set(results))

    def test_from_names(self) -> None:
        pipeline = MutationPipeline.from_names(["leet", "reverse"])
        assert len(pipeline.rules) == 2

    def test_from_names_invalid(self) -> None:
        with pytest.raises(ValueError, match="Unknown rule name"):
            MutationPipeline.from_names(["nonexistent"])

    def test_mutate_many(self) -> None:
        pipeline = MutationPipeline(rules=[ReverseRule()])
        words = iter(["abc", "xyz"])
        results = list(pipeline.mutate_many(words))
        assert "cba" in results
        assert "zyx" in results
