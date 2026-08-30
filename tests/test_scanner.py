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
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(0, REPO_ROOT)

from reporter import format_human, format_json, write_html_report
from rules import (
    find_entropy_matches,
    find_pattern_matches,
    is_inline_ignored,
    shannon_entropy,
)
from scanner import Finding, SkipLog, is_ignored_by_patterns, scan_path

import secretscan as secretscan_cli


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
        "generic_"
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

    def test_google_api_key_detected(self):
        key = "AIza" + ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r")
        matches = find_pattern_matches(f'google_key = "{key}"\n')
        self.assertIn("Google API Key", [match[0] for match in matches])

    def test_stripe_secret_key_detected(self):
        key = "sk_live_" + ("A1b2C3d4E5f6G7h8I9j0K1l2")
        matches = find_pattern_matches(f'stripe_key = "{key}"\n')
        self.assertIn("Stripe Secret Key", [match[0] for match in matches])

    def test_sendgrid_key_detected(self):
        key = "SG." + ("A" * 22) + "." + ("b" * 22)
        matches = find_pattern_matches(f'sendgrid_key = "{key}"\n')
        self.assertIn("SendGrid API Key", [match[0] for match in matches])

    def test_npm_token_detected(self):
        key = "npm_" + ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5" )
        matches = find_pattern_matches(f'npm_token = "{key}"\n')
        self.assertIn("npm Access Token", [match[0] for match in matches])

    def test_twilio_auth_token_detected(self):
        token = "abcdef0123456789abcdef0123456789"
        matches = find_pattern_matches(f'twilio_auth_token = "{token}"\n')
        self.assertIn("Twilio Auth Token", [match[0] for match in matches])

    def test_bearer_token_detected(self):
        token = "AbCdEf0123456789GhIjKlMnOpQrStUvW"
        matches = find_pattern_matches(f'Authorization: Bearer {token}\n')
        self.assertIn("Bearer Token", [match[0] for match in matches])

    def test_modern_ai_provider_tokens_detected(self):
        cases = [
            ("Anthropic API Key", "sk-ant-api03-" + "a" * 32),
            ("Groq API Key", "gsk_" + "a" * 32),
            ("Replicate API Token", "r8_" + "a" * 32),
            ("Perplexity API Key", "pplx-" + "a" * 32),
            ("OpenRouter API Key", "sk-or-v1-" + "a" * 48),
            ("xAI API Key", "xai-" + "a" * 32),
            ("Together API Key", "tgp_v1_" + "a" * 32),
            ("Fireworks API Key", "fw_" + "a" * 32),
            ("ElevenLabs API Key", "sk_" + "a" * 32),
        ]
        for rule_name, token in cases:
            with self.subTest(rule=rule_name):
                matches = find_pattern_matches(f'TOKEN = "{token}"\n')
                self.assertTrue(any(m[0] == rule_name for m in matches))

    def test_platform_and_infrastructure_tokens_detected(self):
        cases = [
            ("Supabase Access Token", "sbp_" + "a" * 32),
            ("Vercel Token", "vercel_" + "a" * 32),
            ("Netlify Token", "nfp_" + "a" * 32),
            ("Sentry Auth Token", "sntrys_" + "a" * 32),
            ("Linear API Key", "lin_api_" + "a" * 32),
            ("Resend API Key", "re_" + "a" * 32),
            ("Brevo API Key", "xkeysib-" + "a" * 32),
            ("CircleCI Token", "CCIPAT_" + "a" * 32),
            ("Docker Hub Token", "dckr_pat_" + "a" * 32),
            ("DigitalOcean Token", "dop_" + "a" * 32),
            ("Terraform Cloud Token", "atlasv1." + "a" * 32),
            ("Alibaba Cloud Access Key", "LTAI" + "a" * 20),
        ]
        for rule_name, token in cases:
            with self.subTest(rule=rule_name):
                matches = find_pattern_matches(f'TOKEN = "{token}"\n')
                self.assertTrue(any(m[0] == rule_name for m in matches))

    def test_unquoted_generic_secret_assignment_detected(self):
        matches = find_pattern_matches(
            "API_KEY=genericUnquotedSecretValue123456789 # comment\n"
        )
        self.assertTrue(any(m[0] == "Generic Secret Assignment" for m in matches))

    def test_cloudinary_and_firebase_credentials_detected(self):
        cloudinary = "cloudinary://123456789012345:secretvalue123456789@example"
        firebase = '\"private_key\": \"-----BEGIN PRIVATE KEY-----\"'
        self.assertTrue(any(m[0] == "Cloudinary Credential URL" for m in find_pattern_matches(cloudinary)))
        self.assertTrue(any(m[0] == "Firebase Service Account Key" for m in find_pattern_matches(firebase)))

    def test_database_credential_url_detected(self):
        url = "postgresql://appuser:superSecret123@db.example.com:5432/app"
        matches = find_pattern_matches(f'DATABASE_URL = "{url}"\n')
        self.assertIn("Database Credential URL", [match[0] for match in matches])

    def test_database_credential_url_stays_high_for_real_remote_host(self):
        url = "postgresql://appuser:superSecret123@db.example.com:5432/app"
        matches = find_pattern_matches(f'DATABASE_URL = "{url}"\n')
        db_matches = [m for m in matches if m[0] == "Database Credential URL"]
        self.assertTrue(db_matches)
        self.assertEqual(db_matches[0][2], "HIGH")

    def test_database_credential_url_localhost_placeholder_is_downgraded(self):
        """postgres://postgres:postgres@localhost:5432/app and similar
        local-dev placeholders are extremely common in docker-compose.yml
        and .env.example files and are not leaked credentials. They should
        still be reported (so a real localhost leak isn't hidden outright)
        but not at HIGH, since the installed git hook blocks on HIGH and
        would otherwise reject completely ordinary commits."""
        cases = [
            'DATABASE_URL = "postgres://postgres:postgres@localhost:5432/app"',
            'DATABASE_URL = "mysql://root:root@db:3306/test"',
            'DATABASE_URL = "redis://user:changeme@localhost:6379"',
        ]
        for line in cases:
            matches = find_pattern_matches(line + "\n")
            db_matches = [m for m in matches if m[0] == "Database Credential URL"]
            self.assertTrue(db_matches, f"expected a match for: {line}")
            self.assertEqual(
                db_matches[0][2], "MEDIUM",
                f"expected MEDIUM (not HIGH) for placeholder URL: {line}",
            )

    def test_aws_session_token_detected(self):
        token = "A" * 80
        matches = find_pattern_matches(f'aws_session_token = "{token}"\n')
        self.assertIn("AWS Session Token", [m[0] for m in matches])

    def test_github_fine_grained_token_detected(self):
        token = "github_pat_" + ("A1b2C3d4E5f6G7h8I9j0_" * 2)
        matches = find_pattern_matches(f'token = "{token}"\n')
        self.assertIn("GitHub Token", [m[0] for m in matches])

    def test_gitlab_token_detected(self):
        token = "glpat-" + ("A1b2C3d4E5f6G7h8I9j0" * 2)
        matches = find_pattern_matches(f'token = "{token}"\n')
        self.assertIn("GitLab Token", [m[0] for m in matches])

    def test_shopify_token_detected(self):
        token = "shpat_" + ("A1b2C3d4E5f6G7h8I9j0" * 2)
        matches = find_pattern_matches(f'shopify_token = "{token}"\n')
        self.assertIn("Shopify Access Token", [m[0] for m in matches])

    def test_openai_project_key_detected(self):
        token = "sk-proj-" + ("A1b2C3d4E5f6G7h8I9j0" * 2)
        matches = find_pattern_matches(f'OPENAI_API_KEY = "{token}"\n')
        self.assertIn("OpenAI API Key", [m[0] for m in matches])

    def test_hugging_face_token_detected(self):
        token = "hf_" + ("A1b2C3d4E5f6G7h8I9j0" * 2)
        matches = find_pattern_matches(f'HF_TOKEN = "{token}"\n')
        self.assertIn("Hugging Face Token", [m[0] for m in matches])

    def test_pgp_private_key_header_detected(self):
        matches = find_pattern_matches("-----BEGIN PGP PRIVATE KEY BLOCK-----\n")
        self.assertIn("PGP Private Key Header", [m[0] for m in matches])

    def test_mariadb_credential_url_detected(self):
        url = "mariadb://appuser:superSecret123@db.example.com/app"
        matches = find_pattern_matches(f'DATABASE_URL = "{url}"\n')
        self.assertIn("Database Credential URL", [m[0] for m in matches])

    def test_generic_credential_assignment_detected_without_api_word(self):
        matches = find_pattern_matches('credential = "thisIsASecretValue12345"\n')
        self.assertIn("Generic API Key Assignment", [m[0] for m in matches])

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

    def test_uuid_is_not_flagged_by_entropy(self):
        matches = find_entropy_matches(
            'request_id = "550e8400-e29b-41d4-a716-446655440000"\n',
            [],
        )

        self.assertEqual(matches, [])

    def test_common_hex_digest_is_not_flagged_by_entropy(self):
        digest = "0123456789abcdef" * 4

        matches = find_entropy_matches(
            f'checksum = "{digest}"\n',
            [],
        )

        self.assertEqual(matches, [])

    def test_test_fixture_random_value_is_not_flagged(self):
        value = (
            "a8f3k9x2m1p7q4z8w3n6"
            "r0j5h2y9b4c1e8t0s3"
        )

        matches = find_entropy_matches(
            f'test_fixture_value = "{value}"\n',
            [],
        )

        self.assertEqual(matches, [])

    def test_machine_id_is_not_flagged_by_entropy(self):
        value = "a8f3k9x2m1p7q4z8w3n6r0j5h2y9b4c1e8t0s3"
        matches = find_entropy_matches(
            f'request_id = "{value}"\n',
            [],
        )
        self.assertEqual(matches, [])

    def test_checksum_is_not_flagged_by_entropy(self):
        value = "a8f3k9x2m1p7q4z8w3n6r0j5h2y9b4c1e8t0s3"
        matches = find_entropy_matches(
            f'checksum = "{value}"\n',
            [],
        )
        self.assertEqual(matches, [])

    def test_data_uri_is_not_flagged_by_entropy(self):
        value = "a8f3k9x2m1p7q4z8w3n6r0j5h2y9b4c1e8t0s3"
        matches = find_entropy_matches(
            f'icon = "data:image/png;base64,{value}"\n',
            [],
        )
        self.assertEqual(matches, [])

    def test_random_secret_context_still_detected(self):
        value = (
            "a8f3k9x2m1p7q4z8w3n6"
            "r0j5h2y9b4c1e8t0s3"
        )

        matches = find_entropy_matches(
            f'random_secret = "{value}"\n',
            [],
        )

        self.assertGreaterEqual(len(matches), 1)

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

            findings, _, _ = scan_path(
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
        findings, _, _ = scan_path(
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
        findings, _, _ = scan_path(
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
        findings, _, _ = scan_path(
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

        findings, _, _ = scan_path(
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

    def test_history_files_are_ignored_by_default(self):
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

        findings, _, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
        )

        # Shell history is opt-in (--include-shell-history) since
        # scanning it by default is more invasive than scanning a
        # project's own source files.
        self.assertFalse(
            any(
                finding.filepath == history
                for finding in findings
            )
        )

    def test_history_files_are_scanned_when_opted_in(self):
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

        findings, _, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
            include_history=True,
        )

        self.assertTrue(
            any(
                finding.filepath == history
                for finding in findings
            )
        )


# ---------------------------------------------------------------------------
# GITIGNORE COMPATIBILITY
# ---------------------------------------------------------------------------


class TestGitignoreCompatibility(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, relative, content):
        path = os.path.join(self.tmpdir, *relative.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_negation_reincludes_file(self):
        self._write(".gitignore", "*.log\n!important.log\n")
        ignored = self._write("debug.log", "x\n")
        allowed = self._write("important.log", "x\n")

        findings, scanned, skipped = scan_path(
            self.tmpdir, find_pattern_matches, find_entropy_matches
        )

        scanned_paths = {
            sample["path"] for sample in skipped.samples
        }
        self.assertIn(ignored, scanned_paths)
        self.assertNotIn(allowed, scanned_paths)
        self.assertGreaterEqual(scanned, 2)  # .gitignore + important.log

    def test_directory_only_pattern_ignores_contents(self):
        self._write(".gitignore", "secrets/\n")
        secret_file = self._write("secrets/key.txt", 'key = "x"\n')

        _, scanned, skipped = scan_path(
            self.tmpdir, find_pattern_matches, find_entropy_matches
        )

        self.assertIn(secret_file, [s["path"] for s in skipped.samples])
        self.assertEqual(skipped.counts.get("gitignore_match", 0), 1)
        self.assertEqual(scanned, 1)

    def test_nested_gitignore_is_applied(self):
        self._write("app/.gitignore", "*.secret\n")
        ignored = self._write("app/config.secret", "x\n")
        allowed = self._write("other/config.secret", "x\n")

        _, scanned, skipped = scan_path(
            self.tmpdir, find_pattern_matches, find_entropy_matches
        )

        sampled = [s["path"] for s in skipped.samples]
        self.assertIn(ignored, sampled)
        self.assertNotIn(allowed, sampled)
        self.assertGreaterEqual(scanned, 2)

    def test_globstar_matches_nested_files(self):
        self._write(".gitignore", "logs/**/*.txt\n")
        ignored = self._write("logs/2026/app/output.txt", "x\n")

        _, _, skipped = scan_path(
            self.tmpdir, find_pattern_matches, find_entropy_matches
        )

        self.assertIn(ignored, [s["path"] for s in skipped.samples])

    def test_legacy_pattern_list_still_works(self):
        self.assertTrue(is_ignored_by_patterns("build/app.py", ["build/"]))
        self.assertTrue(is_ignored_by_patterns("nested/app.log", ["*.log"]))
        self.assertFalse(
            is_ignored_by_patterns("important.log", ["*.log", "!important.log"])
        )


# ---------------------------------------------------------------------------
# SHELL HISTORY COVERAGE
# ---------------------------------------------------------------------------


class TestShellHistoryCoverage(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_common_history_filenames_are_opt_in(self):
        history_names = [
            ".bash_history",
            ".zsh_history",
            ".sh_history",
            ".ksh_history",
            ".history",
            "fish_history",
            "ConsoleHost_history.txt",
        ]

        for name in history_names:
            path = os.path.join(self.tmpdir, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f'export AWS_KEY="{fake_aws_access_key()}"\n')

        _, _, skipped = scan_path(
            self.tmpdir, find_pattern_matches, find_entropy_matches
        )
        self.assertEqual(
            skipped.counts.get("shell_history_excluded", 0),
            len(history_names),
        )

        findings, _, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
            include_history=True,
        )
        found = {os.path.basename(f.filepath) for f in findings}
        self.assertTrue(set(history_names) <= found)

    def test_nested_fish_history_is_detected(self):
        path = os.path.join(self.tmpdir, ".local", "share", "fish", "fish_history")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f'cmd: export AWS_KEY="{fake_aws_access_key()}"\n')

        findings, _, _ = scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
            include_history=True,
        )

        self.assertTrue(any(f.filepath == path for f in findings))


# ---------------------------------------------------------------------------
# SKIPPED-FILE TRACKING
# ---------------------------------------------------------------------------
#
# Regression coverage for the "silent skipped files" gap: binary,
# .gitignore'd, oversized, and unreadable files used to disappear from
# every report with zero signal. scan_path()'s third return value
# (a SkipLog) must now account for every one of them.


class TestSkippedFileTracking(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

        # A binary file — skipped by extension.
        with open(
            os.path.join(self.tmpdir, "logo.png"), "wb"
        ) as handle:
            handle.write(b"\x89PNG\r\n\x1a\nnot a real png")

        # A .gitignore'd file.
        with open(
            os.path.join(self.tmpdir, ".gitignore"), "w", encoding="utf-8"
        ) as handle:
            handle.write("ignored.txt\n")

        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"

        with open(
            os.path.join(self.tmpdir, "ignored.txt"), "w", encoding="utf-8"
        ) as handle:
            handle.write(f'key = "{aws_key}"\n')

        # An oversized file (we pass a tiny max_file_size_bytes below).
        with open(
            os.path.join(self.tmpdir, "big.txt"), "w", encoding="utf-8"
        ) as handle:
            handle.write("x" * 200)

        # A normal file that should actually be scanned.
        with open(
            os.path.join(self.tmpdir, "app.py"), "w", encoding="utf-8"
        ) as handle:
            handle.write(f'key = "{aws_key}"\n')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _scan(self):
        return scan_path(
            self.tmpdir,
            find_pattern_matches,
            find_entropy_matches,
            max_file_size_bytes=50,
        )

    def test_skip_log_is_returned_as_third_value(self):
        _, _, skipped = self._scan()
        self.assertIsInstance(skipped, SkipLog)

    def test_binary_file_is_counted_as_skipped(self):
        _, _, skipped = self._scan()
        self.assertGreaterEqual(skipped.counts.get("binary_extension", 0), 1)

    def test_gitignored_file_is_counted_as_skipped(self):
        _, _, skipped = self._scan()
        self.assertGreaterEqual(skipped.counts.get("gitignore_match", 0), 1)

    def test_oversized_file_is_counted_as_skipped(self):
        _, _, skipped = self._scan()
        self.assertGreaterEqual(skipped.counts.get("oversize", 0), 1)

    def test_total_matches_sum_of_reasons(self):
        _, _, skipped = self._scan()
        self.assertEqual(skipped.total, sum(skipped.counts.values()))
        self.assertGreaterEqual(skipped.total, 3)

    def test_samples_reference_real_skipped_paths(self):
        _, _, skipped = self._scan()
        sampled_names = {os.path.basename(s["path"]) for s in skipped.samples}
        self.assertTrue(sampled_names & {"logo.png", "ignored.txt", "big.txt"})

    def test_scanned_file_is_still_found(self):
        findings, files_scanned, skipped = self._scan()
        matched_files = {os.path.basename(f.filepath) for f in findings}
        self.assertIn("app.py", matched_files)
        # The gitignored copy of the same secret must NOT show up.
        self.assertNotIn(
            "ignored.txt",
            matched_files,
            "a .gitignore'd file must be skipped, not scanned",
        )

    def test_no_skip_log_means_no_skipped_files_reported(self):
        """A directory with nothing to skip should report an empty log,
        not error out."""
        clean_dir = tempfile.mkdtemp()
        try:
            with open(
                os.path.join(clean_dir, "clean.py"), "w", encoding="utf-8"
            ) as handle:
                handle.write("x = 1\n")

            _, _, skipped = scan_path(
                clean_dir,
                find_pattern_matches,
                find_entropy_matches,
            )
            self.assertEqual(skipped.total, 0)
            self.assertEqual(skipped.counts, {})
        finally:
            shutil.rmtree(clean_dir, ignore_errors=True)

    def test_human_report_surfaces_skip_counts(self):
        findings, files_scanned, skipped = self._scan()
        output = format_human(findings, files_scanned, 0.01, use_color=False, skipped=skipped)
        self.assertIn("Files skipped", output)

    def test_human_report_omits_skip_line_when_nothing_skipped(self):
        output = format_human([], 1, 0.01, use_color=False, skipped=None)
        self.assertNotIn("Files skipped", output)

    def test_json_report_includes_skip_breakdown(self):
        findings, files_scanned, skipped = self._scan()
        payload = json.loads(
            format_json(findings, files_scanned, 0.01, skipped=skipped)
        )
        self.assertIn("files_skipped", payload)
        self.assertIn("files_skipped_by_reason", payload)
        self.assertEqual(payload["files_skipped"], skipped.total)
        self.assertEqual(
            sum(payload["files_skipped_by_reason"].values()),
            skipped.total,
        )

    def test_default_ignored_directory_is_recorded_not_silent(self):
        """A whole subtree pruned via DEFAULT_IGNORE_DIRS (build/,
        node_modules/, .git/, etc.) used to vanish from every report
        with zero signal — even if it held a real secret. It must now
        show up in the skip log, even though we deliberately don't walk
        into it to count individual files (that would defeat the point
        of pruning it for performance)."""
        project_dir = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(project_dir, "build"))
            os.makedirs(os.path.join(project_dir, "node_modules"))
            aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
            with open(
                os.path.join(project_dir, "build", "secret.py"),
                "w", encoding="utf-8",
            ) as handle:
                handle.write(f'key = "{aws_key}"\n')
            with open(
                os.path.join(project_dir, "app.py"),
                "w", encoding="utf-8",
            ) as handle:
                handle.write("x = 1\n")

            findings, files_scanned, skipped = scan_path(
                project_dir,
                find_pattern_matches,
                find_entropy_matches,
            )

            self.assertGreaterEqual(skipped.counts.get("ignored_directory", 0), 2)
            sampled_paths = {os.path.basename(s["path"]) for s in skipped.samples}
            self.assertTrue(sampled_paths & {"build", "node_modules"})
        finally:
            shutil.rmtree(project_dir, ignore_errors=True)

    def test_html_report_includes_skipped_section(self):
        findings, files_scanned, skipped = self._scan()
        with tempfile.TemporaryDirectory() as tmp:
            output_path = os.path.join(tmp, "report.html")
            write_html_report(
                findings,
                files_scanned,
                0.01,
                output_path,
                self.tmpdir,
                skipped=skipped,
            )
            with open(output_path, encoding="utf-8") as handle:
                document = handle.read()
            self.assertIn("Skipped Files", document)
            self.assertIn(f"Skipped: {skipped.total}", document)


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
# PRE-COMMIT HOOK TEMPLATE
# ---------------------------------------------------------------------------
#
# Regression coverage for the hook-quoting bug: an unquoted
# $STAGED_FILES expansion word-split on spaces and let argparse treat
# a "-"-prefixed filename as a flag. The fix avoids ever putting
# filenames in a shell variable at all.


class TestPreCommitHookTemplate(unittest.TestCase):

    def test_template_never_expands_an_unquoted_filename_variable(self):
        """The specific bug: `scan $STAGED_FILES` (or any bare
        $VAR holding filenames) word-splits on spaces/globs. The fixed
        template must not contain that pattern anywhere."""
        template = secretscan_cli.PRE_COMMIT_HOOK_TEMPLATE
        self.assertNotIn("$STAGED_FILES", template)
        self.assertNotRegex(
            template,
            r"scan\s+\$\w+\s*$",
            "found an unquoted filename-variable expansion passed to scan",
        )

    def test_template_uses_null_delimited_transfer_and_end_of_options(self):
        template = secretscan_cli.PRE_COMMIT_HOOK_TEMPLATE
        self.assertIn("-z", template)
        self.assertIn("xargs -0", template)
        self.assertIn("scan --", template)

    def test_template_formats_without_error(self):
        content = secretscan_cli.PRE_COMMIT_HOOK_TEMPLATE.format(
            scanner_path="/tmp/secretscan.py",
            python_executable="/usr/bin/python3",
        )
        self.assertIn("#!/bin/sh", content)
        self.assertIn("/tmp/secretscan.py", content)


@unittest.skipUnless(shutil.which("git"), "git is not available on PATH")
class TestPreCommitHookIntegration(unittest.TestCase):
    """End-to-end: install the real hook into a real git repo and
    confirm a commit is actually blocked, for a filename that starts
    with '-' AND contains a space — the exact case the old unquoted
    `$STAGED_FILES` expansion mishandled."""

    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self._run(["git", "init", "-q"])
        self._run(["git", "config", "user.email", "test@example.com"])
        self._run(["git", "config", "user.name", "Test"])

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def _run(self, args, check=True):
        return subprocess.run(
            args,
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=check,
        )

    def test_commit_with_tricky_filename_secret_is_blocked(self):
        install = subprocess.run(
            [
                sys.executable,
                os.path.join(REPO_ROOT, "secretscan.py"),
                "install-hook",
                "--path",
                ".",
            ],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )
        self.assertEqual(install.returncode, 0, install.stderr)

        tricky_dir = os.path.join(self.repo, "a dir")
        os.makedirs(tricky_dir, exist_ok=True)
        tricky_name = "-weird secret.env"
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        with open(
            os.path.join(tricky_dir, tricky_name), "w", encoding="utf-8"
        ) as handle:
            handle.write(f"{aws_key}\n")

        self._run(["git", "add", "-A"])
        commit = self._run(
            ["git", "commit", "-m", "add tricky secret"],
            check=False,
        )

        self.assertNotEqual(
            commit.returncode,
            0,
            "hook should have blocked a commit containing a HIGH finding",
        )
        self.assertIn("AWS Access Key", commit.stdout + commit.stderr)

    def test_commit_without_secrets_succeeds_with_tricky_filename(self):
        install = subprocess.run(
            [
                sys.executable,
                os.path.join(REPO_ROOT, "secretscan.py"),
                "install-hook",
                "--path",
                ".",
            ],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )
        self.assertEqual(install.returncode, 0, install.stderr)

        tricky_dir = os.path.join(self.repo, "clean dir")
        os.makedirs(tricky_dir, exist_ok=True)
        tricky_name = "-clean file.py"
        with open(
            os.path.join(tricky_dir, tricky_name), "w", encoding="utf-8"
        ) as handle:
            handle.write("x = 1\n")

        self._run(["git", "add", "-A"])
        commit = self._run(
            ["git", "commit", "-m", "add clean file"],
            check=False,
        )

        self.assertEqual(
            commit.returncode,
            0,
            f"expected clean commit to succeed: {commit.stdout}\n{commit.stderr}",
        )


class TestHtmlReportFilename(unittest.TestCase):
    """Regression test: --html-report PATH must write exactly PATH.

    Earlier versions ignored the requested filename and only kept the
    requested directory, always writing "<base>_report.html" inside it
    instead of the exact path the user asked for.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.clean_file = os.path.join(self.tmpdir, "clean.py")
        with open(self.clean_file, "w", encoding="utf-8") as handle:
            handle.write("x = 1\n")

    def _run_cli(self, *extra_args):
        return subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "secretscan.py"),
             "scan", self.clean_file, *extra_args],
            capture_output=True,
            text=True,
            cwd=self.tmpdir,
        )

    def test_exact_filename_is_honored(self):
        requested = os.path.join(self.tmpdir, "custom-name.html")
        result = self._run_cli("--html-report", requested)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            os.path.isfile(requested),
            f"expected {requested} to exist; dir contains: "
            f"{os.listdir(self.tmpdir)}",
        )
        wrong_guess = os.path.join(
            self.tmpdir, f"{os.path.basename(self.clean_file)}_report.html"
        )
        self.assertFalse(
            os.path.exists(wrong_guess),
            "scanner wrote its own derived filename instead of the "
            "requested one",
        )

    def test_relative_filename_is_honored(self):
        result = self._run_cli("--html-report", "report.html")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = os.path.join(self.tmpdir, "report.html")
        self.assertTrue(os.path.isfile(expected), os.listdir(self.tmpdir))


# ---------------------------------------------------------------------------
# TEST ENTRY POINT
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()