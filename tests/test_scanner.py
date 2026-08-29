"""
Expanded unittest suite for SecretScan.

Run:
    python -m unittest discover -s tests -v

Safety:
    Test credentials are constructed at runtime instead of storing
    complete token-like strings directly in the repository.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reporter import format_human, format_json, write_html_report
from rules import (
    find_entropy_matches,
    find_pattern_matches,
    is_inline_ignored,
    shannon_entropy,
)
from scanner import Finding, scan_path


# ---------------------------------------------------------------------------
# SAFE TEST VALUES
# ---------------------------------------------------------------------------
#
# These values are deliberately constructed from pieces at runtime.
# Do NOT replace them with real API keys, access tokens, passwords,
# private keys, or production credentials.
#
# The values are fake test fixtures only.
# ---------------------------------------------------------------------------


def fake_aws_access_key():
    return "AKIA" + "IOSFODNN7EXAMPLE"


def fake_aws_secret_key():
    return (
        "wJalrXUtnFEMI"
        "/K7MDENG"
        "/bPxRfiCY"
        "EXAMPLEKEY"
    )


def fake_github_token():
    return (
        "ghp_"
        + "1234567890"
        + "abcdefghijklmnopqrstuvwxyz12"
    )


def fake_slack_token():
    return (
        "xoxb-"
        + "1234567890"
        + "-"
        + "1234567890123"
        + "-"
        + "fakefakefakefakefake"
    )


def fake_generic_api_key():
    return (
        "sk_"
        + "test_"
        + "thisIsNotARealKey123456789"
    )


# ---------------------------------------------------------------------------
# ENTROPY TESTS
# ---------------------------------------------------------------------------


class TestShannonEntropy(unittest.TestCase):

    def test_empty_string_is_zero_entropy(self):
        self.assertEqual(
            shannon_entropy(""),
            0.0,
        )

    def test_repeated_char_is_zero_entropy(self):
        self.assertEqual(
            shannon_entropy("aaaaaaaaaa"),
            0.0,
        )

    def test_random_string_has_high_entropy(self):
        value = (
            "a8f3k9x2m1p7q4z8w3n6"
            "r0j5h2y9b4c1e8t0s3"
        )

        self.assertGreater(
            shannon_entropy(value),
            4.0,
        )


# ---------------------------------------------------------------------------
# PATTERN RULE TESTS
# ---------------------------------------------------------------------------


class TestPatternRules(unittest.TestCase):

    def test_aws_access_key_detected(self):
        key = fake_aws_access_key()

        matches = find_pattern_matches(
            f'AWS_KEY = "{key}"\n'
        )

        self.assertIn(
            "AWS Access Key",
            [match[0] for match in matches],
        )

    def test_aws_secret_key_detected(self):
        key = fake_aws_secret_key()

        matches = find_pattern_matches(
            f'aws_secret_access_key = "{key}"\n'
        )

        self.assertIn(
            "AWS Secret Key",
            [match[0] for match in matches],
        )

    def test_github_token_detected(self):
        token = fake_github_token()

        matches = find_pattern_matches(
            f'GITHUB_TOKEN = "{token}"\n'
        )

        self.assertIn(
            "GitHub Token",
            [match[0] for match in matches],
        )

    def test_slack_token_detected(self):
        token = fake_slack_token()

        matches = find_pattern_matches(
            f'slack_token = "{token}"\n'
        )

        self.assertIn(
            "Slack Token",
            [match[0] for match in matches],
        )

    def test_private_key_header_detected(self):
        matches = find_pattern_matches(
            "-----BEGIN RSA PRIVATE KEY-----\n"
        )

        self.assertIn(
            "Private Key Header",
            [match[0] for match in matches],
        )

    def test_jwt_detected(self):
        # Deliberately synthetic JWT-shaped test value.
        header = "eyJ" + ("a" * 11)
        payload = "eyJ" + ("b" * 11)
        signature = "c" * 16

        token = f"{header}.{payload}.{signature}"

        matches = find_pattern_matches(
            f'token = "{token}"\n'
        )

        self.assertIn(
            "JWT Token",
            [match[0] for match in matches],
        )

    def test_generic_api_key_detected(self):
        key = fake_generic_api_key()

        matches = find_pattern_matches(
            f'api_key = "{key}"\n'
        )

        self.assertIn(
            "Generic API Key Assignment",
            [match[0] for match in matches],
        )

    def test_no_false_positive_on_normal_code(self):
        normal_lines = (
            "def calculate_total(items):\n",
            "    return sum(item.price for item in items)\n",
            "DEFAULT_PORT = 8080\n",
            "name = 'John Doe'\n",
        )

        for line in normal_lines:
            with self.subTest(line=line):
                self.assertEqual(
                    find_pattern_matches(line),
                    [],
                )


# ---------------------------------------------------------------------------
# ENTROPY DETECTION
# ---------------------------------------------------------------------------


class TestEntropyDetection(unittest.TestCase):

    def test_high_entropy_quoted_string_detected(self):
        value = (
            "a8f3k9x2m1p7q4z8w3n6"
            "r0j5h2y9b4c1e8t0s3"
        )

        matches = find_entropy_matches(
            f'random_secret = "{value}"\n',
            [],
        )

        self.assertGreaterEqual(
            len(matches),
            1,
        )

    def test_low_entropy_string_not_flagged(self):
        matches = find_entropy_matches(
            'greeting = "helloooooooooooooooooooo"\n',
            [],
        )

        self.assertEqual(
            matches,
            [],
        )

    def test_overlap_with_pattern_match_is_skipped(self):
        token = fake_github_token()

        line = f'GITHUB_TOKEN = "{token}"\n'

        pattern_matches = find_pattern_matches(line)

        self.assertTrue(
            pattern_matches,
            "The GitHub token fixture should first match the pattern rule.",
        )

        spans = [
            match[3]
            for match in pattern_matches
            if len(match) >= 4
        ]

        entropy_matches = find_entropy_matches(
            line,
            already_matched_spans=spans,
        )

        self.assertEqual(
            entropy_matches,
            [],
        )


# ---------------------------------------------------------------------------
# FINDING REDACTION / CONTEXT
# ---------------------------------------------------------------------------


class TestFindingRedactionAndContext(unittest.TestCase):

    def test_redacted_masks_middle(self):
        secret = fake_aws_access_key()

        finding = Finding(
            "file.py",
            1,
            "Test Rule",
            secret,
            "HIGH",
        )

        redacted = finding.redacted()

        self.assertNotEqual(
            redacted,
            secret,
        )

        self.assertTrue(
            redacted.startswith("AKIA"),
        )

        self.assertTrue(
            redacted.endswith("MPLE"),
        )

        self.assertIn(
            "*",
            redacted,
        )

    def test_short_string_fully_masked(self):
        finding = Finding(
            "file.py",
            1,
            "Test Rule",
            "short",
            "HIGH",
        )

        self.assertEqual(
            finding.redacted(),
            "*****",
        )

    def test_line_context_does_not_contain_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(
                tmp,
                "config.py",
            )

            secret = fake_aws_access_key()

            with open(
                path,
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    f'AWS_KEY = "{secret}"\n'
                )

            findings, _ = scan_path(
                tmp,
                find_pattern_matches,
                find_entropy_matches,
            )

            self.assertTrue(findings)

            context = findings[0].line_context

            self.assertNotIn(
                secret,
                context,
            )

            self.assertIn(
                "[REDACTED]",
                context,
            )


# ---------------------------------------------------------------------------
# INLINE IGNORE
# ---------------------------------------------------------------------------


class TestInlineIgnore(unittest.TestCase):

    def test_ignore_everything_on_line(self):
        token = fake_aws_access_key()

        self.assertTrue(
            is_inline_ignored(
                f'AWS_KEY = "{token}" # secretscan-ignore'
            )
        )

    def test_rule_specific_ignore(self):
        token = fake_aws_access_key()

        self.assertTrue(
            is_inline_ignored(
                f'AWS_KEY = "{token}" '
                "# secretscan-ignore: AWS Access Key",
                "AWS Access Key",
            )
        )

        self.assertFalse(
            is_inline_ignored(
                f'AWS_KEY = "{token}" '
                "# secretscan-ignore: Other Rule",
                "AWS Access Key",
            )
        )


# ---------------------------------------------------------------------------
# DIRECTORY SCANNING
# ---------------------------------------------------------------------------


class TestDirectoryScanning(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

        aws_key = fake_aws_access_key()

        # Regular file containing a synthetic test secret.
        with open(
            os.path.join(
                self.tmpdir,
                "config.py",
            ),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                f'AWS_KEY = "{aws_key}"\n'
            )

        # Clean file.
        with open(
            os.path.join(
                self.tmpdir,
                "clean.py",
            ),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                "x = 1\n"
            )

        # Git directory should be ignored.
        git_dir = os.path.join(
            self.tmpdir,
            ".git",
        )

        os.makedirs(
            git_dir,
            exist_ok=True,
        )

        with open(
            os.path.join(
                git_dir,
                "config",
            ),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                f'AWS_KEY = "{aws_key}"\n'
            )

        # node_modules should be ignored.
        node_modules = os.path.join(
            self.tmpdir,
            "node_modules",
            "somepkg",
        )

        os.makedirs(
            node_modules,
            exist_ok=True,
        )

        with open(
            os.path.join(
                node_modules,
                "index.js",
            ),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                f'var key = "{aws_key}";\n'
            )

    def tearDown(self):
        shutil.rmtree(
            self.tmpdir,
            ignore_errors=True,
        )

    def test_finds_secret_in_regular_file(self):
        findings, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
        )

        matched_files = {
            os.path.basename(f.filepath)
            for f in findings
        }

        self.assertIn(
            "config.py",
            matched_files,
        )

    def test_ignores_git_and_node_modules_dirs(self):
        findings, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
        )

        for finding in findings:
            self.assertNotIn(
                ".git",
                finding.filepath,
            )

            self.assertNotIn(
                "node_modules",
                finding.filepath,
            )

    def test_clean_file_produces_no_findings(self):
        findings, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
        )

        clean_findings = [
            finding
            for finding in findings
            if os.path.basename(
                finding.filepath
            ) == "clean.py"
        ]

        self.assertEqual(
            clean_findings,
            [],
        )

    def test_gitignore_is_honored(self):
        with open(
            os.path.join(
                self.tmpdir,
                ".gitignore",
            ),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                "ignored.txt\n"
            )

        ignored = os.path.join(
            self.tmpdir,
            "ignored.txt",
        )

        aws_key = fake_aws_access_key()

        with open(
            ignored,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                f'AWS_KEY = "{aws_key}"\n'
            )

        findings, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
        )

        self.assertNotIn(
            ignored,
            [
                finding.filepath
                for finding in findings
            ],
        )

    def test_history_files_are_scanned(self):
        history = os.path.join(
            self.tmpdir,
            ".bash_history",
        )

        aws_key = fake_aws_access_key()

        with open(
            history,
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                f'export AWS_KEY="{aws_key}"\n'
            )

        findings, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
        )

        self.assertTrue(
            any(
                finding.filepath == history
                for finding in findings
            )
        )


# ---------------------------------------------------------------------------
# REPORTING
# ---------------------------------------------------------------------------


class TestReporting(unittest.TestCase):

    def test_json_contains_safe_context(self):
        finding = Finding(
            "file.py",
            4,
            "Test Rule",
            "abcdefghijklmnopqrst",
            "MEDIUM",
            line_context='key = "[REDACTED]"',
            suggestion="Move it to an environment variable.",
        )

        data = json.loads(
            format_json(
                [finding],
                1,
                0.1234,
            )
        )

        self.assertEqual(
            data["findings"][0]["line_context"],
            'key = "[REDACTED]"',
        )

        self.assertNotIn(
            finding.matched_text,
            json.dumps(data),
        )

    def test_human_exit_policy(self):
        medium = Finding(
            "file.py",
            1,
            "Test Rule",
            "abcdefghijklmnopqrst",
            "MEDIUM",
        )

        high = Finding(
            "file.py",
            1,
            "Test Rule",
            fake_aws_access_key(),
            "HIGH",
        )

        medium_output = format_human(
            [medium],
            1,
            0.1,
            use_color=False,
        )

        high_output = format_human(
            [high],
            1,
            0.1,
            use_color=False,
        )

        self.assertIn(
            "Exit code: 0",
            medium_output,
        )

        self.assertIn(
            "Exit code: 1",
            high_output,
        )

    def test_html_escapes_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(
                tmp,
                "report.html",
            )

            finding = Finding(
                "<x>.py",
                1,
                "Rule <test>",
                "abcdefghijklmnopqrst",
                "MEDIUM",
                line_context='x < y "[REDACTED]"',
            )

            write_html_report(
                [finding],
                1,
                0.1,
                output,
                tmp,
            )

            with open(
                output,
                encoding="utf-8",
            ) as handle:
                html = handle.read()

            self.assertIn(
                "&lt;x&gt;.py",
                html,
            )

            self.assertNotIn(
                "<x>.py",
                html,
            )


# ---------------------------------------------------------------------------
# TEST ENTRY POINT
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()