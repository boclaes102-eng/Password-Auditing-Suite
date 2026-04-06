"""Custom exception hierarchy for the Password Auditing Suite.

Every public-facing error inherits from ``PASError`` so callers can catch
the entire family with a single ``except PASError`` clause while still being
able to discriminate on subclass when they need to.
"""
from __future__ import annotations


class PASError(Exception):
    """Root exception for all Password Auditing Suite errors."""


class HashIdentificationError(PASError):
    """Raised when a hash string cannot be classified with any confidence."""


class CrackingError(PASError):
    """Raised on fatal errors during an offline cracking run."""


class BreachCheckError(PASError):
    """Raised when the HIBP k-anonymity API is unreachable or returns an error."""


class WordlistError(PASError):
    """Raised for unreadable or malformed wordlist files."""


class UnsupportedAlgorithmError(PASError):
    """Raised when a requested hash algorithm has no available backend."""
