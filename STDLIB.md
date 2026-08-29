# STDLIB.md — Package Substitutions

Every place we'd normally reach for a third-party package, and what we
used from the Python standard library instead.

| I'd normally install | Used instead | Why it works |
|---|---|---|
| `gitleaks` / `truffleHog` (Go binaries) | `re` (regex) + `math` (`math.log2`) | These tools' core detection is regex pattern matching plus entropy scoring. Both are pure computation over strings — no need for a compiled external binary or a package; `re` and `math` cover it fully. |
| `detect-secrets` (Python, pip) | Hand-rolled rule engine in `src/rules.py` | Same underlying concept (a list of named detectors, each returning matches), reimplemented as a plain list of `(name, compiled_pattern, confidence)` tuples with two dispatch functions. No plugin system needed for this scope. |
| `click` or `argparse` extensions for subcommands | `argparse` (stdlib) `add_subparsers()` | `argparse` already supports `scan` / `install-hook` as first-class subcommands with their own flags — no need for a richer CLI framework. |
| `colorama` / `rich` / `termcolor` | Raw ANSI escape codes (`\033[31m`, etc.) in `src/reporter.py` | Terminal color codes are a well-known fixed set of escape sequences. We check `sys.stdout.isatty()` ourselves to avoid printing raw escape codes into piped/redirected output, which is exactly what these libraries do under the hood. |
| `pathspec` (proper `.gitignore` parsing) | `fnmatch` (stdlib) | We don't implement full gitignore semantics (no negation, no anchoring rules) — `fnmatch.fnmatch()` against each `.gitignore` line covers the common case (`*.log`, `secrets/`, `*.pem`) that matters for a scanner. Documented as a known limitation in README rather than silently claimed as complete. |
| `pytest` (+ `pytest` plugins for fixtures) | `unittest` (stdlib) | `unittest.TestCase` with `setUp`/`tearDown` covers everything this suite needs: fixture files via `tempfile.mkdtemp()`, assertions, test discovery via `python -m unittest discover`. |
| `python-dotenv` | Not used — out of scope | We don't read `.env` files ourselves; the scanner treats `.env` like any other text file and scans its contents for secrets, which is actually the more useful behavior here (catching secrets that *shouldn't* be in `.env` files committed to git). |
| `uuid` generation packages (if we needed scan-run IDs) | `time.strftime()` for timestamps | We only needed a human-readable timestamp for JSON output, not a unique ID — `time` (stdlib) was sufficient, avoided pulling in `uuid` usage where it wasn't actually needed. |
| `jsonschema` (validating our JSON output) | Manual dict construction in `format_json()` | Our JSON output shape is small and fully controlled by us (`json.dumps` on a plain dict) — no external input is being validated, so schema validation would be solving a problem we don't have. |
| `watchdog` (for a possible real-time file-watch mode) | Not implemented in this version — documented as a future direction | Considered for a "scan on save" mode; Python's stdlib has no cross-platform file-watching primitive (see capability matrix: "File watching: Python 3.14 = polling"), so a real implementation would need manual `os.stat()` polling. Left out of v1 to keep scope tight and honest rather than ship a half-working watch mode. |

## package killer candidate

**Target:** `detect-secrets` (PyPI) — a widely used pre-commit secret
scanner from Yelp, commonly installed via `pip install detect-secrets`
and used in CI pipelines and pre-commit hook configs across many open
source and internal company repos.

**What we reimplemented:** the core detection loop — pattern-based
rules for known secret formats, plus entropy-based detection for
unknown/custom formats, redacted output, and git pre-commit hook
installation — all without needing `pip install` at all.

**What we didn't reimplement** (honest scope limits): `detect-secrets`
also supports a baseline file for tracking already-accepted findings,
a plugin architecture for custom detectors, and integration with
several secret-management platforms. `secretscan` is intentionally
narrower — a single-purpose, zero-setup scanner rather than a full
platform.

## Design choices worth noting

- **No cipher implementation of any kind.** This tool only *detects*
  patterns and measures entropy — it never encrypts, decrypts, hashes
  for security purposes, or implements any cryptographic primitive. This
  keeps it fully outside the "never roll your own cipher" concern.
- **Redaction is always-on**, not a flag you have to remember to pass —
  the `Finding.redacted()` method is the only way findings are ever
  rendered to the user, so a full secret can't accidentally leak into
  terminal history or CI logs.