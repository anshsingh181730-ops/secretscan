"""
scanner.py — Core scanning logic for secretscan.

Walks a file or directory, reads text files, and runs detection rules
line-by-line. Uses only the standard library: os, fnmatch.
"""

import os
import fnmatch


# Directories we never want to walk into — noise, not code.
DEFAULT_IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".mypy_cache", ".pytest_cache",
}

# Skip obviously binary / non-text extensions to avoid garbage matches
# and wasted time.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".exe", ".dll", ".so", ".pyc", ".woff", ".woff2", ".ttf",
    ".mp4", ".mp3", ".bin",
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # skip anything over 5MB, likely not source


class Finding:
    """A single detected potential secret."""

    __slots__ = ("filepath", "line_number", "rule_name", "matched_text", "confidence")

    def __init__(self, filepath, line_number, rule_name, matched_text, confidence):
        self.filepath = filepath
        self.line_number = line_number
        self.rule_name = rule_name
        self.matched_text = matched_text
        self.confidence = confidence

    def redacted(self):
        """Return the matched text with the middle masked out, for safe display."""
        t = self.matched_text
        if len(t) <= 8:
            return "*" * len(t)
        return t[:4] + "*" * (len(t) - 8) + t[-4:]


def load_ignore_patterns(root: str):
    """Read a .gitignore at the root (if present) for extra glob-based skips."""
    patterns = []
    gitignore_path = os.path.join(root, ".gitignore")
    if os.path.isfile(gitignore_path):
        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except OSError:
            pass
    return patterns


def is_ignored_by_patterns(relpath: str, patterns) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(relpath, pat) or fnmatch.fnmatch(os.path.basename(relpath), pat):
            return True
    return False


def iter_target_files(root: str):
    """Yield file paths under root, skipping ignored dirs/binaries/oversized files."""
    if os.path.isfile(root):
        yield root
        return

    ignore_patterns = load_ignore_patterns(root)

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORE_DIRS]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            relpath = os.path.relpath(fpath, root)

            ext = os.path.splitext(fname)[1].lower()
            if ext in BINARY_EXTENSIONS:
                continue

            if is_ignored_by_patterns(relpath, ignore_patterns):
                continue

            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            yield fpath


def scan_file(filepath: str, pattern_finder, entropy_finder):
    """Scan a single file, return a list of Finding objects."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                pattern_matches = pattern_finder(line)
                spans = []
                for name, matched_text, confidence in pattern_matches:
                    findings.append(Finding(filepath, line_number, name, matched_text, confidence))
                    idx = line.find(matched_text)
                    if idx != -1:
                        spans.append((idx, idx + len(matched_text)))

                entropy_matches = entropy_finder(line, spans)
                for name, matched_text, confidence in entropy_matches:
                    findings.append(Finding(filepath, line_number, name, matched_text, confidence))
    except (OSError, UnicodeDecodeError):
        # Unreadable file — skip silently, don't crash the whole scan
        pass
    return findings


def scan_path(root: str, pattern_finder, entropy_finder):
    """Scan a file or directory tree, return (findings, files_scanned_count)."""
    all_findings = []
    files_scanned = 0
    for fpath in iter_target_files(root):
        files_scanned += 1
        all_findings.extend(scan_file(fpath, pattern_finder, entropy_finder))
    return all_findings, files_scanned
