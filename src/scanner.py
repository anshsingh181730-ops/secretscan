"""
scanner.py — Core scanning logic for SecretScan.

Standard-library-only scanner with:
- recursive directory scanning
- .gitignore-aware filtering
- binary/oversize skipping
- .bash_history / .zsh_history scanning (opt-in)
- inline ignore support
- safe redacted line context
- baseline fingerprints

No part of this module invokes an external tool (git, etc.) at
runtime. Staged-file scanning is handled entirely by the pre-commit
hook shell script (see secretscan.py's PRE_COMMIT_HOOK_TEMPLATE),
which passes the already-staged file list to `scan` as ordinary
positional arguments. That keeps the git interaction inside git's own
hook mechanism instead of making this artifact shell out to git
itself — see STDLIB.md for the reasoning.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os

from rules import is_inline_ignored


DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".exe", ".dll", ".so", ".pyc", ".woff", ".woff2", ".ttf",
    ".mp4", ".mp3", ".bin", ".class", ".jar", ".7z", ".rar", ".webp",
    ".mov", ".avi", ".wasm", ".dylib",
}

HISTORY_FILENAMES = {".bash_history", ".zsh_history"}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def load_ignore_patterns(root: str):
    """Read root .gitignore patterns."""
    patterns = []
    gitignore_path = os.path.join(root, ".gitignore")

    if os.path.isfile(gitignore_path):
        try:
            with open(
                gitignore_path,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except OSError:
            pass

    return patterns


def is_ignored_by_patterns(relpath: str, patterns) -> bool:
    """
    Best-effort .gitignore-style matching.

    Supports ordinary globs, directory globs, rooted patterns and
    basename matching. Negation is intentionally not interpreted because
    a security scanner should prefer conservative exclusion rules.
    """
    relpath = relpath.replace(os.sep, "/").lstrip("./")
    basename = os.path.basename(relpath)

    for raw_pattern in patterns:
        pattern = raw_pattern.strip().replace("\\", "/")
        if not pattern or pattern.startswith("#"):
            continue

        # A negated .gitignore entry is not treated as an include here.
        if pattern.startswith("!"):
            continue

        pattern = pattern.rstrip("/")
        rooted = pattern.startswith("/")
        pattern = pattern.lstrip("/")

        if rooted:
            if fnmatch.fnmatch(relpath, pattern):
                return True
        elif (
            fnmatch.fnmatch(relpath, pattern)
            or fnmatch.fnmatch(basename, pattern)
            or fnmatch.fnmatch(relpath, f"*/{pattern}")
        ):
            return True

    return False


def _file_allowed(fpath: str, relpath: str, ignore_patterns, include_history: bool) -> bool:
    fname = os.path.basename(fpath)
    ext = os.path.splitext(fname)[1].lower()
    is_history_file = fname in HISTORY_FILENAMES

    if is_history_file and not include_history:
        return False

    if ext in BINARY_EXTENSIONS and not is_history_file:
        return False

    if is_ignored_by_patterns(relpath, ignore_patterns):
        return False

    try:
        if os.path.getsize(fpath) > MAX_FILE_SIZE_BYTES:
            return False
    except OSError:
        return False

    return True


def iter_target_files(
    root: str,
    extra_ignore_dirs=None,
    max_file_size_bytes=None,
    include_history=False,
):
    """Yield eligible files under root.

    Shell history files (.bash_history, .zsh_history) are skipped by
    default — set include_history=True (--include-shell-history on
    the CLI) to opt in, since scanning a user's shell history is more
    invasive than scanning a project's own source files.
    """
    if os.path.isfile(root):
        yield root
        return

    ignore_patterns = load_ignore_patterns(root)
    ignored_dirs = set(DEFAULT_IGNORE_DIRS) | set(extra_ignore_dirs or [])
    max_size = max_file_size_bytes or MAX_FILE_SIZE_BYTES

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in ignored_dirs
        ]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            relpath = os.path.relpath(fpath, root)

            if _file_allowed(fpath, relpath, ignore_patterns, include_history):
                try:
                    if os.path.getsize(fpath) > max_size:
                        continue
                except OSError:
                    continue
                yield fpath


def _redact_line(line: str, spans) -> str:
    """Redact all detected secret spans from a source line."""
    if not spans:
        return line.rstrip("\r\n")

    merged = []
    for start, end in sorted(spans):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    pieces = []
    cursor = 0
    for start, end in merged:
        pieces.append(line[cursor:start])
        pieces.append("[REDACTED]")
        cursor = end
    pieces.append(line[cursor:])

    return "".join(pieces).rstrip("\r\n")


def finding_fingerprint(filepath: str, root: str, line_number: int,
                        rule_name: str, matched_text: str) -> str:
    """
    Stable non-reversible identifier for a finding.

    The raw secret is only used as input to SHA-256 and is never stored.
    """
    try:
        relpath = os.path.relpath(filepath, root).replace(os.sep, "/")
    except ValueError:
        relpath = os.path.abspath(filepath)

    material = "\0".join(
        [relpath, str(line_number), rule_name, matched_text]
    )
    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()


class Finding:
    """A detected potential secret; raw value remains in memory only."""

    __slots__ = (
        "filepath",
        "line_number",
        "rule_name",
        "matched_text",
        "confidence",
        "line_context",
        "fingerprint",
        "suggestion",
    )

    def __init__(
        self,
        filepath,
        line_number,
        rule_name,
        matched_text,
        confidence,
        line_context="",
        fingerprint="",
        suggestion="",
    ):
        self.filepath = filepath
        self.line_number = line_number
        self.rule_name = rule_name
        self.matched_text = matched_text
        self.confidence = confidence
        self.line_context = line_context
        self.fingerprint = fingerprint
        self.suggestion = suggestion

    def redacted(self):
        """Return only a masked representation of the detected value."""
        t = self.matched_text
        if len(t) <= 8:
            return "*" * len(t)
        return t[:4] + "*" * (len(t) - 8) + t[-4:]


def _suggestion_for(rule_name: str) -> str:
    """Return a remediation suggestion without exposing any secret."""
    if rule_name == "Private Key Header":
        return "Move the private key to a secure secret store and rotate it if exposed."
    if rule_name == "JWT Token":
        return "Do not commit the token; use environment/configured secrets and rotate it if real."
    if rule_name.startswith("AWS"):
        return "Move AWS credentials to the AWS credential chain/environment and rotate them if real."
    if rule_name == "GitHub Token":
        return "Move the token to a secure secret store and revoke/rotate it if real."
    if rule_name == "Slack Token":
        return "Move the token to a secure secret store and revoke/rotate it if real."
    if rule_name.startswith("High-entropy"):
        return "Move the value to an environment variable or secret manager; verify it is not a test value."
    return "Move the value to an environment variable or secret manager and keep it out of source control."


def scan_file(filepath: str, pattern_finder, entropy_finder, root=None):
    """Scan one text file and return Finding objects."""
    findings = []
    root = root or os.path.dirname(os.path.abspath(filepath))

    try:
        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as handle:
            for line_number, line in enumerate(handle, start=1):
                pattern_matches = pattern_finder(line)
                spans = []

                for item in pattern_matches:
                    if len(item) == 4:
                        name, matched_text, confidence, span = item
                    else:
                        name, matched_text, confidence = item
                        idx = line.find(matched_text)
                        span = (
                            (idx, idx + len(matched_text))
                            if idx >= 0 else (0, 0)
                        )

                    spans.append(span)

                    # A rule-specific ignore can suppress just this finding.
                    if is_inline_ignored(line, name):
                        continue

                    findings.append(
                        Finding(
                            filepath,
                            line_number,
                            name,
                            matched_text,
                            confidence,
                        )
                    )

                entropy_matches = entropy_finder(line, spans)

                for item in entropy_matches:
                    if len(item) == 4:
                        name, matched_text, confidence, span = item
                    else:
                        name, matched_text, confidence = item
                        idx = line.find(matched_text)
                        span = (
                            (idx, idx + len(matched_text))
                            if idx >= 0 else (0, 0)
                        )

                    if is_inline_ignored(line, name):
                        continue

                    spans.append(span)
                    findings.append(
                        Finding(
                            filepath,
                            line_number,
                            name,
                            matched_text,
                            confidence,
                        )
                    )

                if findings:
                    line_findings = [
                        f for f in findings
                        if f.filepath == filepath
                        and f.line_number == line_number
                    ]
                    context = _redact_line(line, spans)
                    for finding in line_findings:
                        finding.line_context = context
                        finding.fingerprint = finding_fingerprint(
                            filepath,
                            root,
                            line_number,
                            finding.rule_name,
                            finding.matched_text,
                        )
                        finding.suggestion = _suggestion_for(
                            finding.rule_name
                        )

    except (OSError, UnicodeError):
        pass

    return findings


def scan_path(
    roots,
    pattern_finder,
    entropy_finder,
    extra_ignore_dirs=None,
    max_file_size_bytes=None,
    include_history=False,
):
    """
    Scan one or more files/directories and return (findings, files_scanned).

    `roots` may be a single path string or a list of path strings —
    the pre-commit hook passes a list of already-staged files here
    (obtained by the hook script itself via `git diff --cached`), so
    this module never needs to query git directly.
    """
    if isinstance(roots, str):
        roots = [roots]

    all_findings = []
    files_scanned = 0

    for root in roots:
        root = os.path.abspath(root)
        scan_root = root if os.path.isdir(root) else os.path.dirname(root)

        for filepath in iter_target_files(
            root, extra_ignore_dirs, max_file_size_bytes, include_history
        ):
            files_scanned += 1
            all_findings.extend(
                scan_file(
                    filepath,
                    pattern_finder,
                    entropy_finder,
                    root=scan_root,
                )
            )

    return all_findings, files_scanned


def apply_baseline(findings, baseline):
    """Remove findings whose fingerprint is already accepted."""
    if not baseline:
        return list(findings)

    accepted = set(baseline.get("fingerprints", []))
    return [
        finding for finding in findings
        if finding.fingerprint not in accepted
    ]
