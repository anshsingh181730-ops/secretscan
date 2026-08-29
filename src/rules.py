"""
rules.py — Detection rules for secretscan.

Two layers of detection:
1. Pattern-based: known secret formats (AWS keys, GitHub tokens, JWTs, etc.)
2. Entropy-based: catches high-randomness strings that don't match a known
   pattern but still look like secrets (custom API keys, random passwords).

Zero third-party dependencies — only `re` and `math` from the standard library.
"""

import re
import math


# ---------------------------------------------------------------------------
# Pattern-based rules
# ---------------------------------------------------------------------------
# Each rule: (name, compiled regex, confidence label)
# Order matters a little for readability in output, not for correctness.

PATTERN_RULES = [
    (
        "AWS Access Key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "HIGH",
    ),
    (
        "AWS Secret Key",
        re.compile(r"(?i)aws_secret(_access)?_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "HIGH",
    ),
    (
        "GitHub Token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        "HIGH",
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "HIGH",
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "HIGH",
    ),
    (
        "JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "HIGH",
    ),
    (
        "Generic API Key Assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*"
            r"['\"]([A-Za-z0-9_\-/+]{16,})['\"]"
        ),
        "MEDIUM",
    ),
]


# ---------------------------------------------------------------------------
# Entropy-based detection
# ---------------------------------------------------------------------------
# Finds quoted strings in source lines, then scores them by Shannon entropy.
# High entropy + sufficient length is a decent heuristic for "random-looking
# secret" without knowing the exact format in advance.

QUOTED_STRING_RE = re.compile(r"""['"]([A-Za-z0-9+/_\-=]{20,})['"]""")

ENTROPY_THRESHOLD = 4.3   # bits/char; empirically reasonable for base64-ish secrets
MIN_ENTROPY_LEN = 20      # ignore short strings, too many false positives


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def find_pattern_matches(line: str):
    """Return list of (rule_name, matched_text, confidence) for a line.

    If the rule's regex has a capture group for the secret value itself
    (to exclude surrounding quotes), use the last group; otherwise fall
    back to the full match.
    """
    results = []
    for name, pattern, confidence in PATTERN_RULES:
        m = pattern.search(line)
        if m:
            if m.lastindex:
                matched_text = m.group(m.lastindex)
            else:
                matched_text = m.group(0)
            results.append((name, matched_text, confidence))
    return results


def find_entropy_matches(line: str, already_matched_spans=None):
    """
    Return list of (rule_name, matched_text, confidence) for high-entropy
    quoted strings in a line. Skips spans already caught by pattern rules
    to avoid double-reporting the same secret.
    """
    already_matched_spans = already_matched_spans or []
    results = []
    for m in QUOTED_STRING_RE.finditer(line):
        span = m.span(1)  # span of the captured value, not including quotes
        # Skip if this overlaps a pattern match already found
        if any(a[0] <= span[0] < a[1] or span[0] <= a[0] < span[1] for a in already_matched_spans):
            continue
        candidate = m.group(1)
        if len(candidate) < MIN_ENTROPY_LEN:
            continue
        ent = shannon_entropy(candidate)
        if ent >= ENTROPY_THRESHOLD:
            results.append((
                f"High-entropy string (entropy={ent:.2f})",
                candidate,
                "MEDIUM",
            ))
    return results
