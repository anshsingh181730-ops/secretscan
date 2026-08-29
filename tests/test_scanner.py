"""
test_scanner.py — unittest suite for secretscan.

Run with:
    python3 -m unittest discover -s tests -v

Covers:
- Each pattern rule detects its known-format fake secret
- Entropy detection catches high-randomness strings
- Clean code produces zero findings (no false positives)
- Directory scanning skips ignored dirs (.git, node_modules, etc.)
- Redaction never leaks the full secret in output
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rules import find_pattern_matches, find_entropy_matches, shannon_entropy  # noqa: E402
from scanner import scan_path, Finding                                        # noqa: E402


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string_is_zero_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_repeated_char_is_zero_entropy(self):
        self.assertEqual(shannon_entropy("aaaaaaaaaa"), 0.0)

    def test_random_string_has_high_entropy(self):
        # A genuinely random-looking string should score well above the threshold
        self.assertGreater(shannon_entropy("a8f3k9x2m1p7q4z8w3n6r0"), 4.0)


class TestPatternRules(unittest.TestCase):
    def test_aws_access_key_detected(self):
        line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        matches = find_pattern_matches(line)
        names = [m[0] for m in matches]
        self.assertIn("AWS Access Key", names)

    def test_aws_secret_key_detected(self):
        line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        matches = find_pattern_matches(line)
        names = [m[0] for m in matches]
        self.assertIn("AWS Secret Key", names)

    def test_github_token_detected(self):
        line = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"\n'
        matches = find_pattern_matches(line)
        names = [m[0] for m in matches]
        self.assertIn("GitHub Token", names)

    def test_slack_token_detected(self):
        token = "xoxb-" + "1234567890-" + "1234567890123-" + "fakefakefakefakefake"
        line = f'slack_token = "{token}"\n'
        matches = find_pattern_matches(line)
        names = [m[0] for m in matches]
        self.assertIn("Slack Token", names)

    def test_private_key_header_detected(self):
        line = "-----BEGIN RSA PRIVATE KEY-----\n"
        matches = find_pattern_matches(line)
        names = [m[0] for m in matches]
        self.assertIn("Private Key Header", names)

    def test_generic_api_key_detected(self):
        line = 'api_key = "sk_test_thisIsNotARealKey123456789"\n'
        matches = find_pattern_matches(line)
        names = [m[0] for m in matches]
        self.assertIn("Generic API Key Assignment", names)

    def test_no_false_positive_on_normal_code(self):
        lines = [
            "def calculate_total(items):\n",
            "    return sum(item.price for item in items)\n",
            "DEFAULT_PORT = 8080\n",
            "name = 'John Doe'\n",
        ]
        for line in lines:
            matches = find_pattern_matches(line)
            self.assertEqual(matches, [], f"False positive on: {line!r}")


class TestEntropyDetection(unittest.TestCase):
    def test_high_entropy_quoted_string_detected(self):
        line = 'random_secret = "a8f3k9x2m1p7q4z8w3n6r0j5h2y9b4c1e8t0s3"\n'
        matches = find_entropy_matches(line, already_matched_spans=[])
        self.assertTrue(len(matches) >= 1)

    def test_low_entropy_string_not_flagged(self):
        line = 'greeting = "helloooooooooooooooooooo"\n'
        matches = find_entropy_matches(line, already_matched_spans=[])
        self.assertEqual(matches, [])

    def test_overlap_with_pattern_match_is_skipped(self):
        # If a pattern rule already caught this span, entropy shouldn't double-report
        line = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"\n'
        pattern_matches = find_pattern_matches(line)
        spans = []
        for name, matched_text, confidence in pattern_matches:
            idx = line.find(matched_text)
            spans.append((idx, idx + len(matched_text)))
        entropy_matches = find_entropy_matches(line, already_matched_spans=spans)
        self.assertEqual(entropy_matches, [])


class TestFindingRedaction(unittest.TestCase):
    def test_redacted_masks_middle(self):
        f = Finding("file.py", 1, "Test Rule", "AKIAIOSFODNN7EXAMPLE", "HIGH")
        redacted = f.redacted()
        self.assertNotEqual(redacted, "AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(redacted.startswith("AKIA"))
        self.assertTrue(redacted.endswith("MPLE"))
        self.assertIn("*", redacted)

    def test_short_string_fully_masked(self):
        f = Finding("file.py", 1, "Test Rule", "short", "HIGH")
        self.assertEqual(f.redacted(), "*****")


class TestDirectoryScanning(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

        # A file with a real (fake) secret
        with open(os.path.join(self.tmpdir, "config.py"), "w") as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        # A clean file
        with open(os.path.join(self.tmpdir, "clean.py"), "w") as f:
            f.write("x = 1\n")

        # A secret hidden inside an ignored directory — should NOT be found
        git_dir = os.path.join(self.tmpdir, ".git")
        os.makedirs(git_dir, exist_ok=True)
        with open(os.path.join(git_dir, "config"), "w") as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        node_modules = os.path.join(self.tmpdir, "node_modules", "somepkg")
        os.makedirs(node_modules, exist_ok=True)
        with open(os.path.join(node_modules, "index.js"), "w") as f:
            f.write('var key = "AKIAIOSFODNN7EXAMPLE";\n')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_finds_secret_in_regular_file(self):
        findings, files_scanned = scan_path(
            self.tmpdir, find_pattern_matches, find_entropy_matches
        )
        matched_files = {os.path.basename(f.filepath) for f in findings}
        self.assertIn("config.py", matched_files)

    def test_ignores_git_and_node_modules_dirs(self):
        findings, files_scanned = scan_path(
            self.tmpdir, find_pattern_matches, find_entropy_matches
        )
        for f in findings:
            self.assertNotIn(".git", f.filepath)
            self.assertNotIn("node_modules", f.filepath)

    def test_clean_file_produces_no_findings_for_itself(self):
        findings, _ = scan_path(self.tmpdir, find_pattern_matches, find_entropy_matches)
        clean_findings = [f for f in findings if os.path.basename(f.filepath) == "clean.py"]
        self.assertEqual(clean_findings, [])


if __name__ == "__main__":
    unittest.main()
