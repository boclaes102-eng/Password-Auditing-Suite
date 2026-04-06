"""Tests for the entropy scorer and pattern detector."""
from __future__ import annotations

import pytest

from pas.models import StrengthLabel
from pas.scorer import (
    DictionaryChecker,
    PatternDetector,
    PasswordPolicy,
    _KeyboardSequenceChecker,
    _RepeatChecker,
    _DatePatternChecker,
    score_password,
)


class TestPatternDetection:
    def test_keyboard_walk_detected(self) -> None:
        checker = _KeyboardSequenceChecker()
        matches = checker.check("myqwerty123")
        assert any("keyboard" in m.label for m in matches)

    def test_repeat_chars_detected(self) -> None:
        checker = _RepeatChecker()
        matches = checker.check("paaaaassword")
        assert any("repeated" in m.label for m in matches)

    def test_date_detected(self) -> None:
        checker = _DatePatternChecker()
        matches = checker.check("password2024")
        assert any("date" in m.label for m in matches)

    def test_common_password_detected(self) -> None:
        checker = DictionaryChecker()
        matches = checker.check("password")
        assert any("common" in m.label for m in matches)

    def test_leet_disguised_common_detected(self) -> None:
        checker = DictionaryChecker()
        matches = checker.check("p@ssw0rd")
        assert any("leet" in m.label for m in matches)

    def test_no_false_positive_on_strong_password(self) -> None:
        detector = PatternDetector()
        matches = detector.detect("Xk#9mPqL2@vNrT5!")
        # No common or keyboard patterns
        assert not any("common" in m.label for m in matches)


class TestScorePassword:
    def test_very_weak_common_password(self) -> None:
        result = score_password("password")
        assert result.strength in (StrengthLabel.VERY_WEAK, StrengthLabel.WEAK)
        assert result.score < 40

    def test_strong_random_password(self) -> None:
        result = score_password("Xk#9mPqL2@vNrT5!")
        assert result.strength in (StrengthLabel.STRONG, StrengthLabel.VERY_STRONG)
        assert result.score >= 60

    def test_entropy_is_positive(self) -> None:
        result = score_password("hello")
        assert result.shannon_entropy > 0
        assert result.search_space_bits > 0

    def test_length_captured(self) -> None:
        result = score_password("test")
        assert result.length == 4

    def test_pool_detected(self) -> None:
        from pas.models import CharacterPool
        result = score_password("Password1!")
        assert CharacterPool.LOWERCASE in result.pool
        assert CharacterPool.UPPERCASE in result.pool
        assert CharacterPool.DIGITS in result.pool
        assert CharacterPool.SYMBOLS in result.pool

    def test_recommendations_not_empty(self) -> None:
        result = score_password("abc")
        assert len(result.recommendations) > 0


class TestPasswordPolicy:
    def test_too_short_violation(self) -> None:
        from pas.scorer import MinLengthRule
        policy = PasswordPolicy(rules=[MinLengthRule(12)])
        violations = policy.check("short")
        assert len(violations) == 1
        assert "short" in violations[0].lower()

    def test_passes_when_compliant(self) -> None:
        from pas.scorer import MinLengthRule, MaxLengthRule
        policy = PasswordPolicy(rules=[MinLengthRule(8), MaxLengthRule(128)])
        violations = policy.check("longenoughpassword!")
        assert violations == []

    def test_max_repeat_violation(self) -> None:
        from pas.scorer import MaxRepeatRule
        policy = PasswordPolicy(rules=[MaxRepeatRule(3)])
        violations = policy.check("aaaapassword")
        assert len(violations) == 1
