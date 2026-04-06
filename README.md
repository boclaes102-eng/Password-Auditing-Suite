# Password Auditing Suite

> Expert-grade offline credential analysis toolkit — mutation engine, hash identification, HIBP breach checks, Shannon entropy scoring, and Rich-powered statistical reports.

---

## Features

| Module | Capability |
|---|---|
| **Mutation engine** | Rule-based wordlist expansion: leetspeak (all 2ⁿ combos via `itertools.product`), date appending, keyboard walks, case variants, suffix/prefix injection |
| **Hash identifier** | Heuristic + regex catalogue; prefix-based detection for bcrypt/Argon2/PBKDF2; confidence-ranked candidate list |
| **Offline cracker** | `hashlib` for MD5/SHA-*/BLAKE2b/NTLM; `passlib` for bcrypt/Argon2/scrypt/PBKDF2; `ThreadPoolExecutor` for KDF parallelism |
| **Breach check** | HIBP k-anonymity API — only 5 hex chars transmitted; LRU cache; token-bucket rate limiter; automatic retry with exponential back-off |
| **Entropy scorer** | Shannon entropy + search-space bits; `CharacterPool` as `enum.Flag`; `bisect`-based strength labelling; pattern detection pipeline |
| **Reporter** | `Formatter` Protocol → `RichFormatter` / `JsonFormatter`; `ReportBuilder` (Builder pattern); bar-chart pattern tally |

---

## Installation

```bash
# Clone
git clone https://github.com/boclaes/password-auditing-suite.git
cd password-auditing-suite

# Install (editable, with dev extras)
pip install -e ".[dev]"

# Or minimal install
pip install -r requirements.txt
pip install -e .
```

**Python ≥ 3.11 required** (uses `tomllib`, `match`, `str | None` union syntax).

---

## Usage

### Identify a hash algorithm
```bash
pas identify 5f4dcc3b5aa765d61d8327deb882cf99
pas identify --top 5 <hash1> <hash2>
```

### Score a password
```bash
pas score 'P@ssw0rd!' 'correct-horse-battery-staple'
pas score 'hunter2' --min-length 12 --min-classes 3
```

### Check breach database (HIBP k-anonymity)
```bash
pas breach 'password' 'hunter2' 'Tr0ub4dor&3'
```
*Only the first 5 SHA-1 hex chars leave your machine.*

### Crack hashes (offline)
```bash
# Dictionary attack
pas crack hashes.txt --wordlist rockyou.txt

# With mutation rules (leet + dates + suffixes applied to wordlist)
pas crack hashes.txt --wordlist rockyou.txt --mutate

# Force algorithm, user:hash format
pas crack shadow.txt --wordlist rockyou.txt --algorithm sha512 --format user:hash
```

### Stream wordlist mutations
```bash
# All rules → stdout
pas mutate rockyou.txt

# Specific rules → file
pas mutate rockyou.txt --rules leet --rules suffix --output mutated.txt

# Cap leet explosion
pas mutate rockyou.txt --rules leet --max-leet 16
```

### Full audit pipeline
```bash
pas audit hashes.txt --wordlist rockyou.txt
pas audit hashes.txt --wordlist rockyou.txt --no-breach-check   # offline only
pas audit hashes.txt --wordlist rockyou.txt --json              # JSON output
```

---

## Architecture

```
pas/
├── __init__.py       version metadata
├── exceptions.py     PASError hierarchy
├── models.py         HashAlgorithm (str+Enum), CharacterPool (Flag),
│                     frozen dataclasses: HashCandidate, CrackResult,
│                     BreachResult, ScoreResult, AuditReport
├── mutator.py        MutationRule (ABC) → LeetRule, CaseRule, DateAppendRule …
│                     MutationPipeline (itertools.chain, bounded dedup set)
├── identifier.py     HashSignature catalogue, prefix + length matching,
│                     confidence-ranked HashCandidate list
├── cracker.py        CrackerBackend (Protocol) → HashlibBackend, NTLMBackend,
│                     PasslibBackend; ThreadPoolExecutor for KDF work;
│                     CrackProgress (thread-safe counters)
├── breach.py         _LRUCache (OrderedDict), _TokenBucket rate limiter,
│                     requests.Session + urllib3.Retry, HIBP k-anonymity
├── scorer.py         PatternChecker (Protocol), PatternDetector, DictionaryChecker
│                     (cached_property), bisect strength lookup, PasswordPolicy
└── reporter.py       Formatter (Protocol) → RichFormatter, JsonFormatter;
                      ReportBuilder (Builder pattern); Rich tables/panels/progress
cli.py                Click group + commands; AppContext dataclass via pass_context
```

### Key Python patterns showcased

| Pattern | Where |
|---|---|
| **Abstract Base Class** | `MutationRule` — forces `apply()` on all rule subclasses |
| **`typing.Protocol` + `@runtime_checkable`** | `CrackerBackend`, `PatternChecker`, `Formatter` |
| **`enum.Flag` (bitfield enum)** | `CharacterPool` — pools compose with `\|`, `.size` derived from flags |
| **`@dataclass(frozen=True)` value objects** | `HashCandidate`, `CrackResult`, `BreachResult`, `PatternMatch` |
| **Generator pipelines** | `MutationPipeline.mutate()` + `mutate_many()` — lazy end-to-end |
| **`itertools.product`** | `LeetRule` — enumerates all 2ⁿ substitution combos |
| **`itertools.chain.from_iterable`** | `MutationPipeline` — flattens rule outputs without buffering |
| **`functools.cached_property`** | `DictionaryChecker._word_set` — built once, cached forever |
| **`bisect.bisect_right`** | `_label_for()` — O(log n) threshold lookup for strength label |
| **Builder pattern** | `ReportBuilder` — fluent API for assembling `AuditReport` |
| **`ThreadPoolExecutor` + `as_completed`** | `Cracker._run_threaded()` — parallel bcrypt verification |
| **`hmac.compare_digest`** | `HashlibBackend` — constant-time comparison prevents timing attacks |
| **`OrderedDict` LRU cache** | `_LRUCache` in `breach.py` — inspectable, bounded prefix cache |
| **Token-bucket rate limiter** | `_TokenBucket` — prevents HIBP API rate limiting |
| **`urllib3.Retry` + `HTTPAdapter`** | `breach.py` — exponential back-off on 429/5xx |

---

## Development

```bash
# Run tests
pytest

# Type check (strict)
mypy pas/ cli.py

# Lint + format
ruff check pas/ cli.py
ruff format pas/ cli.py

# Coverage
pytest --cov=pas --cov-report=term-missing
```

---

## Security Notes

- This tool is intended for **authorised security auditing** of credentials you own or have explicit written permission to test.
- The HIBP breach check is read-only and uses the k-anonymity model — passwords never leave your machine.
- Mutation-expanded wordlists can be large; use `--max-leet` and `--max-dates` to cap memory usage.

---

## License

MIT — see `LICENSE`.
