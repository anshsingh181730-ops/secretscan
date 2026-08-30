# secretscan

A zero-dependency local secrets leak scanner. Catches hardcoded API keys,
tokens, private keys, and other high-entropy secrets in your codebase —
before they get committed — using nothing but the Python standard
library.

**Track:** E — Security & Crypto Utilities
**Language:** Python 3.11+ (developed and tested on 3.12, targets 3.14)
**Team size:** 4


## The Problem

Developers accidentally commit secrets to version control constantly —
an AWS key left in a config file, a Slack token pasted in for a quick
test, a `.env` file that was never added to `.gitignore`. Existing
scanners (`gitleaks`, `detect-secrets`, `truffleHog`) solve this well,
but they are themselves dependencies you have to install — binaries to
download, or packages to `pip install`. That's a little ironic for a
*security* tool. `secretscan` needs nothing beyond a Python interpreter
that's already on your machine.


## What It Does

### Detection Engine

1. **Pattern matching** — recognizes common secret formats across cloud,
   source-control, SaaS, authentication, key-material, and database families:
   AWS access/secret/session credentials, Google API/OAuth credentials, Azure
   SAS tokens, GitHub/GitLab/Bitbucket tokens, Slack/Discord tokens, Stripe,
   SendGrid, npm, PyPI, Twilio, Heroku, Mailgun, Shopify, OpenAI, Hugging Face,
   Databricks, JWT/Bearer/Basic credentials, private/PGP key headers, generic
   credential assignments, authorization headers, and database credential URLs.
   Provider-specific rules are combined with generic context-aware rules so
   unknown vendor-specific credentials can still be surfaced without third-party
   packages.

2. **Entropy analysis** — checks quoted strings that look random even when they
   do not match a known provider format. Entropy findings are filtered using
   conservative context rules to reduce common false positives.

### Beyond Basic Detection

- **Line-level context** — every finding shows not just the file and
  line number, but the surrounding line itself (with the secret
  redacted in place), so you can see exactly what needs fixing without
  opening the file.
- **Shell history scanning** — optionally scans `.bash_history` /
  `.zsh_history` for secrets typed directly into the terminal
  (`export API_KEY=...`), a leak source most scanners ignore entirely.
- **Inline ignore comments** — mark an intentional test/dummy secret
  with `# secretscan-ignore` on the same line to exclude it from
  results, without disabling detection project-wide.
- **Severity-aware exit codes** — HIGH-confidence findings can gate a
  commit or CI pipeline; MEDIUM-confidence findings warn without
  blocking, so noisy heuristics don't stall a team's workflow.
- **Baseline file support** — accepted/reviewed findings can be
  recorded in `.secretscan-baseline.json` so re-scans don't repeatedly
  flag the same already-triaged result.
- **Fix suggestions** (`--fix-suggest`) — beyond pointing at the
  problem, the scanner suggests moving the value to `.env` and checks
  whether `.env` is already covered by `.gitignore`.
- **Scan summary output** — a concise end-of-run summary (files
  scanned, findings by severity, elapsed time) for quick confirmation
  a scan actually ran and what it covered.
- **`.gitignore`-aware scanning** — files already excluded from version
  control are skipped by default, since a file that can never be
  committed doesn't need to be flagged. Only files that could actually
  reach a commit are scanned — which is precisely why a `.env` file
  missing from `.gitignore` gets flagged: that's the exact scenario
  the tool exists to catch.
- **Skipped-file reporting** — every file excluded from a scan (binary
  extension, `.gitignore` match, over the 5 MB cap, or unreadable) is
  counted and categorized, not just silently dropped. The human
  summary shows a total and per-reason breakdown; `--json` includes
  the full breakdown plus a sample of individual skipped paths, so a
  secret sitting in a file that's just over the size cap can't
  disappear with zero signal.


## How To Run It

No installation step required beyond Python itself.


### Getting the code

You can obtain the project either by cloning the repository or by
downloading it as a ZIP archive from GitHub:

```bash
git clone https://github.com/<your-org>/secretscan.git
cd secretscan
```

Or, from the GitHub repository page: **Code → Download ZIP**, then
extract the archive and open a terminal inside the extracted
`secretscan` folder before running any command below.


### Finding a file or folder's path (Windows)

Every command below takes a `<path>` argument pointing at the project
you want to scan. To get that path on Windows:

1. Open **File Explorer** and navigate to the file or folder you want
   to scan.
2. Click once on the **address bar** at the top (or right-click the
   file/folder and choose **Copy as path**).
3. The full path is now copied — paste it directly into your terminal
   command.
4. If the path contains spaces (e.g. `Smart Resume Builder`), wrap it
   in double quotes: `"C:\Users\you\Downloads\Smart Resume Builder"`.

On macOS/Linux, right-click the file/folder and look for **Copy Path**
(Finder) or run `pwd` inside the target folder in a terminal (Linux).


### Common commands

```bash
# Scan a single file
python3 secretscan.py scan config.py

# Scan an entire project directory (recursively)
python3 secretscan.py scan ./my-project

# Scan a folder on Windows with a path containing spaces
python3 secretscan.py scan "C:\Users\you\Downloads\Smart Resume Builder"

# Machine-readable output, for CI pipelines
python3 secretscan.py scan ./my-project --json

# Include fix suggestions alongside findings
python3 secretscan.py scan ./my-project --fix-suggest

# Also scan shell history for leaked secrets
python3 secretscan.py scan ./my-project --include-shell-history

# Install as a git pre-commit hook
python3 secretscan.py install-hook --path .
```

Note: on Windows, use `python` instead of `python3` if your Python
installation registers itself under that name.

Or with `make` (Linux/macOS, or Windows with `make` installed):

```bash
make run TARGET=./my-project
make test                  # run the full test suite
make verify-zero-deps      # prove zero third-party dependencies
make install-hook          # install as a git pre-commit hook
```

**Exit codes:** `0` = clean or only MEDIUM/low-severity findings,
`1` = at least one HIGH-confidence secret found. This lets CI pipelines
and git hooks gate on real risk rather than treating every heuristic
match as a hard failure.

---


## Marking a Known-Safe Line

```python
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"  # secretscan-ignore
```

Use sparingly, and only for genuinely intentional test/dummy values —
this is an escape hatch, not a way to silence real findings.

## What It Ignores

- `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`,
  `build`, and common cache directories — always skipped.
- Anything matched by applicable `.gitignore` rules, including nested
  `.gitignore` files and ordered negation rules — these are files normally
  excluded from version control. (Git still allows force-adding an ignored
  file with `git add -f`; the pre-commit hook is protected against this
  because it passes the actual staged files to the scanner directly,
  bypassing directory-walk filtering entirely — see `TestPreCommitHookIntegration`.)
- Binary file extensions (images, archives, compiled binaries, fonts,
  media files).
- Files larger than 5 MB (very unlikely to be hand-written source).
- Lines explicitly marked with `# secretscan-ignore`.
- Findings already recorded in `.secretscan-baseline.json`.

The test suite (`tests/test_scanner.py`) uses `subprocess` to create and
drive real git repos when testing the optional pre-commit hook — that's
test infrastructure exercising git, not the scanner. The `secretscan`
runtime itself (including `dist/secretscan_single.py`) contains zero
`subprocess` calls; see `deps-proof.txt` section 6.

## Bugs Found And Fixed

In the spirit of the "Honest Limitations" section below, these are
real defects that existed in earlier drafts of this tool and were
found and fixed before submission — not limitations we're choosing to
live with, but bugs that are now closed:

- **Unquoted filenames in the git hook.** The generated
  `.git/hooks/pre-commit` script used to capture staged filenames into
  a shell variable and expand it unquoted
  (`"$SCANNER" scan $STAGED_FILES`). POSIX shell word-splits an
  unquoted expansion on whitespace, so a staged path containing a
  space broke into bogus fragments, and a filename starting with `-`
  (e.g. `-secrets.env`) could be parsed by `argparse` as a flag
  instead of a path. Fixed by never putting filenames in a shell
  variable at all: the hook now streams `git diff -z` (NUL-delimited)
  straight through `xargs -0` into `secretscan.py scan --`, with `--`
  guaranteeing every argument after it is treated as a path. Covered
  by an integration test (`TestPreCommitHookIntegration` in
  `tests/test_scanner.py`) that installs the real hook into a real git
  repo and commits a file named `-weird secret.env` to prove both the
  block (secret present) and the pass-through (secret absent) work.
- **Silently skipped files.** Files excluded from a scan (binary
  extension, `.gitignore` match, over the 5 MB cap, unreadable) used
  to vanish with no count or listing anywhere in CLI/JSON/HTML output
  — only a static, non-quantified line in the interactive UI's
  pre-scan help text. Fixed by adding a `SkipLog` (`src/scanner.py`)
  that every scan populates with exact counts per reason plus a capped
  sample of paths, now surfaced in the human summary, `--json` output,
  the HTML report, and the interactive UI's results screen. See
  `TestSkippedFileTracking` in `tests/test_scanner.py`.
- **`make run PATH=...` in this README didn't work.** `PATH` is a
  reserved variable (the executable search path); passing
  `PATH=./my-project` to `make` overrode it for that invocation and
  `python3` could no longer be found, so the documented command failed
  outright. The Makefile's variable was already named `TARGET` — only
  the README's example was wrong. Fixed to `make run TARGET=./my-project`.

- **`.gitignore` semantics.** Earlier versions used simple `fnmatch()` rules,
  so negation (`!important.env`), directory-only patterns (`secrets/`),
  `**` globbing, and nested `.gitignore` files could be handled incorrectly.
  Fixed by adding ordered gitignore rule evaluation with negation,
  directory-aware matching, globstar support, and nested ignore-file loading.
- **Shell history coverage.** Earlier versions recognized only `.bash_history`
  and `.zsh_history`. Fixed by covering common POSIX/sh, ksh/mksh, Fish,
  csh/tcsh, and PowerShell history filenames while keeping history scanning
  opt-in.
- **`--html-report PATH` didn't honor `PATH`.** It only kept the requested
  *directory* and then wrote its own derived filename
  (`<base>_report.html`) into it, so `--html-report /tmp/custom.html`
  silently produced `/tmp/clean_code_report.html` instead of
  `/tmp/custom.html`. Fixed to write exactly the path given. Covered by
  `TestHtmlReportFilename` in `tests/test_scanner.py`.

## Honest Limitations

This is a heuristic scanner, not a guarantee. Being upfront about where
it falls short:

- **Entropy is still heuristic, but it is aggressively false-positive hardened.**
  Before scoring, the detector filters UUIDs, conventional fixed-width
  hexadecimal digests, common machine identifiers/integrity values, data-URI
  payloads, and clearly marked test/example/fixture values when they are not
  assigned to a secret-like field. Secret-like context takes precedence so an
  unknown credential is not discarded merely because it resembles generated
  data. This substantially reduces common false positives, but it cannot make
  entropy detection mathematically 100% false-positive-free: entropy alone
  cannot prove that an unknown value is a credential.
- **Detector coverage is intentionally finite.** Pattern coverage has been
  expanded to include Google API keys, Stripe secret keys, SendGrid API
  keys, npm access tokens, Twilio auth tokens, Bearer tokens, and common
  PostgreSQL/MySQL/MongoDB/Redis credential URLs, in addition to the
  original AWS, GitHub, Slack, private-key, JWT, and generic assignment
  rules. This is a meaningful coverage improvement, but it is not intended
  to match mature scanners or detect every vendor-specific credential
  format.
- **False negatives happen too.** A secret split across multiple lines,
  heavily obfuscated, or in a format not covered by our pattern list
  (`PATTERN_RULES` in `src/rules.py`) will be missed. This tool is
  a safety net, not a substitute for careful review or a secrets
  manager.
- **Entropy threshold is a tuned constant** (4.3 bits/char, 20-char
  minimum), not a proven-optimal value. Hex-only strings (16 possible
  symbols) cap out near 4.0 bits/char and can fall just under this
  threshold — a limitation we found during our own testing against
  real-shaped fake tokens, not just a theoretical edge case.
- **No network calls, ever.** This is a design choice, not just a
  limitation — the tool never phones home, never validates whether a
  key is "live," and never sends your code anywhere. Detection is
  100% local pattern/entropy analysis, verifiable by running with
  `python -S` (site-packages disabled) and confirming it still works.
- **`.gitignore` compatibility is implemented locally.** Ordered rules,
  negation, directory-only rules, `**` globbing, and nested `.gitignore`
  files are supported without invoking Git. The matcher intentionally avoids
  external packages and remains a practical implementation rather than a
  promise of byte-for-byte equivalence with every historical Git edge case.
- **Shell history scanning is opt-in and best-effort.** History filenames
  and locations are configurable by each shell, so no filename-based scanner
  can discover every custom history file. We cover the common Bash, Zsh,
  POSIX/sh, ksh/mksh, Fish, csh/tcsh, and PowerShell/PSReadLine filenames.


## Project Layout

```
secretscan/
  README.md
  STDLIB.md
  Makefile
  secretscan.py            # CLI entry point (modular dev version)
  build_single_file.py     # deterministic bundler -> dist/secretscan_single.py
  scripts/
    verify_reproducible_build.sh  # proves two builds hash identically
  dist/
    secretscan_single.py   # (generated) whole project as one file
  src/
    rules.py                # pattern + entropy detection rules
    scanner.py                # file/directory walking, scan orchestration, SkipLog
    reporter.py                 # human-readable + JSON + HTML output formatting
    config.py                     # .secretscan.toml config loading
    terminal_ui.py                  # interactive terminal UI
  tests/
    test_scanner.py             # unittest suite
    fixtures/                     # sample files with fake secrets for testing
  requirements.txt           # empty — zero dependencies
  deps-proof.txt              # verification that no third-party package is used
  .zero-dep.toml                # track + pitch declaration
  .secretscan-baseline.json       # (generated) accepted findings, if used
```


## Single-File Build

The modular layout under `src/` is for development, but the project also
ships as **one standalone file**: `dist/secretscan_single.py`, generated
from `secretscan.py` + `src/*.py` by `build_single_file.py` (itself
stdlib-only — the bundler adds no third-party dependency either).

```bash
python3 build_single_file.py
python3 dist/secretscan_single.py scan <path>
```

The bundle is a genuinely complete, runnable copy of the tool — same CLI,
same detectors, same zero dependencies — just merged into a single
`.py` file for anyone who wants one file to copy/vendor/audit.

### Reproducible Build

`build_single_file.py` is deterministic: fixed module order, no
timestamps, no environment-dependent output, sorted import list. Two
independent builds from the same source produce a **byte-identical**
file.

```bash
sh scripts/verify_reproducible_build.sh
```

(`verify_reproducible_build.sh` and the pre-commit hook installed by
`install-hook` are POSIX `/bin/sh` scripts — build/dev tooling, not part
of the scanner's runtime. `secretscan` itself, including
`dist/secretscan_single.py`, is cross-platform Python stdlib-only and
runs the same on Windows, macOS, and Linux; these two optional shell
scripts assume a POSIX shell, and `verify_reproducible_build.sh` in
particular only *orchestrates* the two builds in shell — the actual
hashing is `hashlib.sha256` in Python, not the external `sha256sum`
binary, precisely so it doesn't need a GNU-coreutils tool that isn't
on macOS by default. The pre-commit hook does call `git`/`xargs`
directly, since driving git's own hook mechanism requires it.)

Verified hashes (SHA256 of `dist/secretscan_single.py`), from two
separate build runs:

```
Build #1: 1e44cd80b0d15e3b0599b19d15744eb7d60a66ab055ecd1aa669eb7d00fd4a22
Build #2: 1e44cd80b0d15e3b0599b19d15744eb7d60a66ab055ecd1aa669eb7d00fd4a22
```

Both hashes match — confirming the build is reproducible. (Hashes
change whenever the source under `src/` or `secretscan.py` changes —
re-run `scripts/verify_reproducible_build.sh` after any edit and
update this section.)


## Testing

```bash
python3 -m unittest discover -s tests -v
```

The suite covers: every pattern rule against a known fake-secret
format, entropy detection on random vs. normal strings, redaction
correctness, directory-walk exclusions (`.git`, `node_modules`),
false-positive checks on ordinary code, skipped-file tracking and
reporting across all three output formats, and a real end-to-end git
integration test that installs the pre-commit hook into a throwaway
repo and confirms it blocks a commit containing a HIGH-confidence
secret in a filename with a space and a leading dash (the exact case
the hook-quoting bug missed) — including regression tests for gitignore negation/nested rules and broader shell-history coverage.

All test fixtures use **fake secrets only** — no real credentials are
used anywhere in this repository. The AWS example key
(`AKIAIOSFODNN7EXAMPLE`) is AWS's own published example key, safe to
use in test code.


## Why Zero Dependencies, For a Security Tool Specifically

A tool whose entire job is catching supply-chain and credential risk
shouldn't itself add supply-chain surface area. Every package you
install is code you didn't write and don't fully audit, running with
access to your source tree. `secretscan` runs with nothing beyond the
Python interpreter already on your machine — verified by running it
with `python -S`, which disables site-packages entirely and confirms
the tool still works correctly.
