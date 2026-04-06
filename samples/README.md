# Sample Files — Test Commands

Run all commands from the **project root** (`Password-Auditing-Suite/`).

---

## 1. Hash Identification

Identify what algorithm a hash is, with confidence scores.

```bash
# Single hash
python cli.py identify 5f4dcc3b5aa765d61d8327deb882cf99

# Multiple hashes at once
python cli.py identify \
  5f4dcc3b5aa765d61d8327deb882cf99 \
  5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  "$2b$04$r7jVAvEs0QQScpr4N3Zhh.E9Ar4g2EewTUhEN73jCEUSQzN7qQCvW"

# Show top 5 candidates instead of top 3
python cli.py identify --top 5 5f4dcc3b5aa765d61d8327deb882cf99
```

---

## 2. Password Scoring

Analyse entropy, detect patterns, and check policy compliance.

```bash
# Score a few passwords
python cli.py score "password" "sunshine" "correct-horse-battery-staple"

# Score with a stricter policy
python cli.py score "Password1!" --min-length 12 --min-classes 3

# Multiple passwords at once
python cli.py score "qwerty" "Tr0ub4dor3" "X9#mPqL2@vN" "iloveyou2024"
```

---

## 3. Breach Check (HIBP)

Checks your passwords against the Have I Been Pwned database.
Only 5 hex chars of the SHA-1 hash are sent — your password stays local.

```bash
python cli.py breach "password" "hunter2" "correct-horse-battery-staple"
```

> Requires an internet connection.

---

## 4. Cracking — tiny wordlist (instant)

Uses the included `tiny_wordlist.txt` — cracks in under a second.

```bash
# Crack MD5 hashes
python cli.py crack samples/md5_hashes.txt --wordlist samples/tiny_wordlist.txt

# Crack SHA-1 hashes
python cli.py crack samples/sha1_hashes.txt --wordlist samples/tiny_wordlist.txt

# Crack SHA-256 hashes
python cli.py crack samples/sha256_hashes.txt --wordlist samples/tiny_wordlist.txt

# Crack user:hash format
python cli.py crack samples/user_hashes.txt --wordlist samples/tiny_wordlist.txt --format user:hash

# Crack mixed algorithm file (auto-detects each hash type)
python cli.py crack samples/mixed_hashes.txt --wordlist samples/tiny_wordlist.txt
```

---

## 5. Cracking — rockyou.txt (thorough)

Replace `tiny_wordlist.txt` with `rockyou.txt` for a full run.

```bash
# Dictionary attack only
python cli.py crack samples/md5_hashes.txt --wordlist rockyou.txt --no-mutate

# Dictionary + mutation rules (leet, dates, suffixes applied to every word)
python cli.py crack samples/md5_hashes.txt --wordlist rockyou.txt --mutate

# Force algorithm (skips auto-detection)
python cli.py crack samples/sha256_hashes.txt --wordlist rockyou.txt --algorithm sha256

# Bcrypt (slow by design — uses threads to parallelise)
python cli.py crack samples/bcrypt_hashes.txt --wordlist samples/tiny_wordlist.txt --workers 4
```

---

## 6. Wordlist Mutation

Stream all mutations for a wordlist — useful to build a custom expanded list.

```bash
# All rules applied, output to stdout
python cli.py mutate samples/tiny_wordlist.txt

# Specific rules only
python cli.py mutate samples/tiny_wordlist.txt --rules leet --rules suffix

# Save to file
python cli.py mutate samples/tiny_wordlist.txt --output samples/mutated.txt

# Cap the leet explosion (default 64 combos per word)
python cli.py mutate samples/tiny_wordlist.txt --rules leet --max-leet 8
```

---

## 7. Full Audit Pipeline

Cracks hashes, scores plaintexts, breach-checks, then prints a full report.

```bash
# Quick audit with tiny wordlist
python cli.py audit samples/md5_hashes.txt --wordlist samples/tiny_wordlist.txt

# Full audit with rockyou (--no-mutate for speed)
python cli.py audit samples/md5_hashes.txt --wordlist rockyou.txt --no-mutate

# Full audit with mutations (thorough, slower)
python cli.py audit samples/md5_hashes.txt --wordlist rockyou.txt --mutate

# user:hash format, no breach check (fully offline)
python cli.py audit samples/user_hashes.txt --wordlist rockyou.txt --format user:hash --no-breach-check

# Output as JSON (useful for piping or saving)
python cli.py audit samples/md5_hashes.txt --wordlist samples/tiny_wordlist.txt --json

# Mixed algorithms, full pipeline
python cli.py audit samples/mixed_hashes.txt --wordlist rockyou.txt
```

---

## Sample File Reference

| File | Contents | Use with |
|---|---|---|
| `md5_hashes.txt` | 15 MD5 hashes | `crack`, `audit` |
| `sha1_hashes.txt` | 10 SHA-1 hashes | `crack`, `audit` |
| `sha256_hashes.txt` | 10 SHA-256 hashes | `crack`, `audit` |
| `bcrypt_hashes.txt` | 3 bcrypt hashes (cost 4) | `crack` |
| `user_hashes.txt` | 11 `username:md5` entries | `crack --format user:hash` |
| `mixed_hashes.txt` | MD5 + SHA-1 + SHA-256 | `identify`, `crack --no-mutate` |
| `tiny_wordlist.txt` | 30 common passwords | any `--wordlist` argument |
