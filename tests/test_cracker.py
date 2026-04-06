"""Tests for the offline cracker module."""
from __future__ import annotations

import hashlib
import os
import tempfile

import pytest

from pas.cracker import (
    Cracker,
    CrackProgress,
    DictionaryAttack,
    HashlibBackend,
    NTLMBackend,
)
from pas.models import CrackResult, HashAlgorithm


class TestHashlibBackend:
    def test_md5_correct(self) -> None:
        backend = HashlibBackend(HashAlgorithm.MD5)
        expected = hashlib.md5(b"password").hexdigest()
        assert backend.verify("password", expected)

    def test_md5_wrong_plaintext(self) -> None:
        backend = HashlibBackend(HashAlgorithm.MD5)
        expected = hashlib.md5(b"password").hexdigest()
        assert not backend.verify("wrong", expected)

    def test_sha256_correct(self) -> None:
        backend = HashlibBackend(HashAlgorithm.SHA256)
        expected = hashlib.sha256(b"hello").hexdigest()
        assert backend.verify("hello", expected)

    def test_sha1_correct(self) -> None:
        backend = HashlibBackend(HashAlgorithm.SHA1)
        expected = hashlib.sha1(b"abc").hexdigest()
        assert backend.verify("abc", expected)

    def test_case_insensitive_hash(self) -> None:
        """Hash comparison must be case-insensitive."""
        backend = HashlibBackend(HashAlgorithm.MD5)
        expected = hashlib.md5(b"test").hexdigest().upper()
        assert backend.verify("test", expected)


class TestCrackProgress:
    def test_increment(self) -> None:
        p = CrackProgress(total_hashes=10)
        p.increment(5)
        assert p.attempts == 5

    def test_record_crack(self) -> None:
        p = CrackProgress(total_hashes=10)
        p.record_crack()
        assert p.cracked == 1

    def test_snapshot_is_atomic(self) -> None:
        p = CrackProgress(total_hashes=10)
        p.increment(7)
        p.record_crack()
        attempts, cracked = p.snapshot
        assert attempts == 7
        assert cracked == 1


class TestDictionaryAttack:
    def test_yields_lines(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("alpha\nbeta\ngamma\n")
            path = f.name
        try:
            attack = DictionaryAttack(path)
            words = list(attack.candidates())
            assert words == ["alpha", "beta", "gamma"]
        finally:
            os.unlink(path)

    def test_missing_file_raises(self) -> None:
        from pas.exceptions import WordlistError
        attack = DictionaryAttack("/nonexistent/path.txt")
        with pytest.raises(WordlistError):
            list(attack.candidates())


class TestCracker:
    def _make_wordlist(self, words: list[str]) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        f.write("\n".join(words) + "\n")
        f.close()
        return f.name

    def test_cracks_md5(self) -> None:
        target = hashlib.md5(b"apple").hexdigest()
        wl = self._make_wordlist(["banana", "cherry", "apple", "grape"])
        try:
            cracker = Cracker(
                hashes={target: HashAlgorithm.MD5},
                strategies=[DictionaryAttack(wl)],
            )
            results = cracker.run()
            assert len(results) == 1
            assert results[0].plaintext == "apple"
            assert results[0].algorithm == HashAlgorithm.MD5
            assert results[0].method == "dictionary"
        finally:
            os.unlink(wl)

    def test_cracks_sha256(self) -> None:
        target = hashlib.sha256(b"secret").hexdigest()
        wl = self._make_wordlist(["wrong", "secret", "other"])
        try:
            cracker = Cracker(
                hashes={target: HashAlgorithm.SHA256},
                strategies=[DictionaryAttack(wl)],
            )
            results = cracker.run()
            assert results[0].plaintext == "secret"
        finally:
            os.unlink(wl)

    def test_uncracked_returns_empty(self) -> None:
        target = hashlib.md5(b"notinlist").hexdigest()
        wl = self._make_wordlist(["alpha", "beta"])
        try:
            cracker = Cracker(
                hashes={target: HashAlgorithm.MD5},
                strategies=[DictionaryAttack(wl)],
            )
            results = cracker.run()
            assert results == []
        finally:
            os.unlink(wl)

    def test_cracks_multiple_hashes(self) -> None:
        h1 = hashlib.md5(b"cat").hexdigest()
        h2 = hashlib.md5(b"dog").hexdigest()
        wl = self._make_wordlist(["cat", "dog", "bird"])
        try:
            cracker = Cracker(
                hashes={h1: HashAlgorithm.MD5, h2: HashAlgorithm.MD5},
                strategies=[DictionaryAttack(wl)],
            )
            results = cracker.run()
            plaintexts = {r.plaintext for r in results}
            assert plaintexts == {"cat", "dog"}
        finally:
            os.unlink(wl)
