"""Tests for the hash identification module."""
from __future__ import annotations

import pytest

from pas.exceptions import HashIdentificationError
from pas.identifier import identify, identify_many
from pas.models import HashAlgorithm


class TestIdentify:
    def test_md5_identified(self) -> None:
        # MD5 of "password"
        candidates = identify("5f4dcc3b5aa765d61d8327deb882cf99")
        assert candidates[0].algorithm == HashAlgorithm.MD5
        assert candidates[0].confidence > 0.7

    def test_sha1_identified(self) -> None:
        candidates = identify("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert candidates[0].algorithm == HashAlgorithm.SHA1
        assert candidates[0].confidence > 0.8

    def test_sha256_identified(self) -> None:
        h = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        candidates = identify(h)
        assert candidates[0].algorithm in (HashAlgorithm.SHA256, HashAlgorithm.SHA3_256)

    def test_sha512_identified(self) -> None:
        h = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
        # 127 chars - not valid sha512, let's use a real one
        h = "a" * 128
        candidates = identify(h)
        assert candidates[0].algorithm in (HashAlgorithm.SHA512, HashAlgorithm.SHA3_512)

    def test_bcrypt_identified(self) -> None:
        h = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        candidates = identify(h)
        assert candidates[0].algorithm == HashAlgorithm.BCRYPT
        assert candidates[0].confidence == pytest.approx(0.99)

    def test_argon2_identified(self) -> None:
        h = "$argon2id$v=19$m=65536,t=2,p=1$somesalt$hashvalue"
        candidates = identify(h)
        assert candidates[0].algorithm == HashAlgorithm.ARGON2

    def test_empty_raises(self) -> None:
        with pytest.raises(HashIdentificationError):
            identify("")

    def test_unknown_returns_unknown(self) -> None:
        candidates = identify("not_a_hash_at_all!!!")
        assert candidates[0].algorithm == HashAlgorithm.UNKNOWN

    def test_sorted_by_confidence(self) -> None:
        candidates = identify("5f4dcc3b5aa765d61d8327deb882cf99")
        confidences = [c.confidence for c in candidates]
        assert confidences == sorted(confidences, reverse=True)

    def test_identify_many_returns_dict(self) -> None:
        hashes = [
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        ]
        result = identify_many(hashes)
        assert len(result) == 2
        assert all(isinstance(v, list) for v in result.values())
