"""
rules.py — Detection rules for SecretScan.

Two layers:
1. Pattern-based detection for known credential formats.
2. Entropy-based detection for random-looking quoted values.

Standard library only.
"""

import math
import re


PATTERN_RULES = [
    (
        "AWS Access Key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "HIGH",
    ),
    (
        "AWS Secret Key",
        re.compile(
            r"(?i)\baws_secret(?:_access)?_key\s*[=:]\s*['\"]?"
            r"([A-Za-z0-9/+=]{40})['\"]?"
        ),
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
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        "HIGH",
    ),
    (
        "JWT Token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
        "HIGH",
    ),
    (
        "Generic API Key Assignment",
        re.compile(
            r"""(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)
            \s*[=:]\s*['"]([A-Za-z0-9_+\-/=]{16,})['"]""",
            re.VERBOSE,
        ),
        "MEDIUM",
    ),
]


QUOTED_STRING_RE = re.compile(r"""['"]([A-Za-z0-9+/_=-]{20,})['"]""")
ENTROPY_THRESHOLD = 4.3
MIN_ENTROPY_LEN = 20


def configure_entropy(threshold: float | None = None, min_length: int | None = None) -> None:
    """Set entropy thresholds for the current process."""
    global ENTROPY_THRESHOLD, MIN_ENTROPY_LEN
    if threshold is not None:
        ENTROPY_THRESHOLD = float(threshold)
    if min_length is not None:
        MIN_ENTROPY_LEN = max(1, int(min_length))

IGNORE_MARKER_RE = re.compile(
    r"secretscan-ignore(?:\s*:\s*(?P<rules>[^#]+))?",
    re.IGNORECASE,
)


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0

    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _matches_ignore_rule(rule_name: str, ignore_spec: str | None) -> bool:
    """Return whether an inline secretscan-ignore applies to rule_name."""
    if not ignore_spec:
        return True

    requested = {
        item.strip().casefold()
        for item in re.split(r"[,;]", ignore_spec)
        if item.strip()
    }
    return not requested or rule_name.casefold() in requested


def is_inline_ignored(line: str, rule_name: str | None = None) -> bool:
    """
    Check for an inline ignore marker.

    Examples:
        # secretscan-ignore
        # secretscan-ignore: AWS Access Key, Generic API Key Assignment

    If no rule is supplied, every finding on the line is ignored.
    """
    marker = IGNORE_MARKER_RE.search(line)
    if not marker:
        return False
    return _matches_ignore_rule(
        rule_name or "",
        marker.group("rules"),
    )


def find_pattern_matches(line: str):
    """
    Return (rule_name, matched_text, confidence, span) tuples.

    Overlapping pattern matches are de-duplicated in favor of the
    higher-confidence rule so one credential is not reported twice.
    """
    raw = []

    for name, pattern, confidence in PATTERN_RULES:
        for match in pattern.finditer(line):
            if match.lastindex:
                start, end = match.span(match.lastindex)
                matched_text = match.group(match.lastindex)
            else:
                start, end = match.span(0)
                matched_text = match.group(0)
            raw.append((name, matched_text, confidence, (start, end)))

    priority = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    raw.sort(key=lambda item: priority.get(item[2], 0), reverse=True)

    results = []
    for item in raw:
        span = item[3]
        if any(
            max(span[0], other[3][0]) < min(span[1], other[3][1])
            for other in results
        ):
            continue
        results.append(item)

    # Restore deterministic source/rule order.
    results.sort(key=lambda item: (item[3][0], item[3][1], item[0]))
    return results


def find_entropy_matches(line: str, already_matched_spans=None):
    """
    Return (rule_name, matched_text, confidence, span) tuples.

    Quoted strings overlapping a pattern finding are skipped.
    """
    already_matched_spans = already_matched_spans or []
    results = []

    for match in QUOTED_STRING_RE.finditer(line):
        start, end = match.span(1)

        if any(
            max(start, a) < min(end, b)
            for a, b in already_matched_spans
        ):
            continue

        candidate = match.group(1)
        if len(candidate) < MIN_ENTROPY_LEN:
            continue

        entropy = shannon_entropy(candidate)
        if entropy >= ENTROPY_THRESHOLD:
            results.append(
                (
                    f"High-entropy string (entropy={entropy:.2f})",
                    candidate,
                    "MEDIUM",
                    (start, end),
                )
            )

    return results
