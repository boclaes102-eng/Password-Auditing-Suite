"""
Password Auditing Suite
=======================
Expert-grade offline credential analysis toolkit.

Modules
-------
mutator    — Rule-based wordlist mutation engine (leet, dates, keyboard walks)
identifier — Heuristic hash-type identification
cracker    — Offline dictionary / mutation attack (hashlib + passlib)
breach     — HIBP k-anonymity breach-database integration
scorer     — Shannon entropy, pattern detection, and policy compliance
reporter   — Rich-powered terminal reporting
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("password-auditing-suite")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = [
    "mutator",
    "identifier",
    "cracker",
    "breach",
    "scorer",
    "reporter",
]
