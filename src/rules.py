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
    # AWS / cloud-provider credentials
    (
        "AWS Access Key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
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
        "AWS Session Token",
        re.compile(
            r"(?is)\b(?:aws_session_token|aws_security_token|x-amz-security-token)"
            r"\s*[=:]\s*['\"]([A-Za-z0-9/+=_-]{20,})['\"]"
        ),
        "HIGH",
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "HIGH",
    ),
    (
        "Google OAuth Client Secret",
        re.compile(r"(?i)\bclient_secret\s*[=:]\s*['\"]([A-Za-z0-9._-]{12,})['\"]"),
        "HIGH",
    ),
    (
        "Azure Storage SAS Token",
        re.compile(r"(?i)(?:\?|&)sv=\d{4}-\d{2}-\d{2}&[^\s'\"]*sig=[A-Za-z0-9%+/=_-]{10,}"),
        "HIGH",
    ),

    # Git hosting / source-control tokens
    (
        "GitHub Token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
        "HIGH",
    ),
    (
        "GitLab Token",
        re.compile(r"\b(?:glpat-[A-Za-z0-9_-]{20,255}|gldt-[A-Za-z0-9_-]{20,255})\b"),
        "HIGH",
    ),
    (
        "Bitbucket Token",
        re.compile(r"(?i)\b(?:bitbucket[_-]?(?:token|app[_-]?password)|bb[_-]?token)\s*[=:]\s*['\"]([A-Za-z0-9_-]{16,})['\"]"),
        "HIGH",
    ),

    # SaaS / API provider tokens
    (
        "Slack Token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "HIGH",
    ),
    (
        "Discord Bot Token",
        re.compile(r"\b(?:[MN][A-Za-z0-9_-]{23,27})\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        "HIGH",
    ),
    (
        "SendGrid API Key",
        re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b"),
        "HIGH",
    ),
    (
        "npm Access Token",
        re.compile(r"\bnpm_[0-9A-Za-z]{30,}\b"),
        "HIGH",
    ),
    (
        "PyPI API Token",
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Twilio Auth Token",
        re.compile(r"(?i)\b(?:twilio[_-]?auth[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?([0-9a-f]{32})['\"]?"),
        "HIGH",
    ),
    (
        "Heroku API Key",
        re.compile(r"(?i)\b(?:heroku[_-]?api[_-]?key|heroku[_-]?key)\s*[=:]\s*['\"]([0-9a-f]{20,64})['\"]"),
        "HIGH",
    ),
    (
        "Mailgun API Key",
        re.compile(r"\bkey-[0-9a-f]{32}\b"),
        "HIGH",
    ),
    (
        "Shopify Access Token",
        re.compile(r"\bshpat_[A-Za-z0-9_-]{20,}\b|\bshpss_[A-Za-z0-9_-]{20,}\b|\bshpca_[A-Za-z0-9_-]{20,}\b|\bshppa_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "OpenAI API Key",
        re.compile(r"\bsk-(?!(?:ant-api\d{2,3}-|or-v1-))(?:proj-|org-)?[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Hugging Face Token",
        re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
        "HIGH",
    ),
    (
        "Databricks Token",
        re.compile(r"\bdapi[0-9a-f]{32}\b", re.IGNORECASE),
        "HIGH",
    ),

    # Modern AI / LLM providers
    (
        "Anthropic API Key",
        re.compile(r"\bsk-ant-api\d{2,3}-[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Groq API Key",
        re.compile(r"\bgsk_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Replicate API Token",
        re.compile(r"\br8_[A-Za-z0-9]{20,}\b"),
        "HIGH",
    ),
    (
        "Perplexity API Key",
        re.compile(r"\bpplx-[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "OpenRouter API Key",
        re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "xAI API Key",
        re.compile(r"\bxai-[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Together API Key",
        re.compile(r"\btgp_v1_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Fireworks API Key",
        re.compile(r"\bfw_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "ElevenLabs API Key",
        re.compile(r"\bsk_[A-Za-z0-9]{20,}\b"),
        "HIGH",
    ),

    # Developer platforms / CI / infrastructure
    (
        "Supabase Access Token",
        re.compile(r"\bsbp_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Vercel Token",
        re.compile(r"\bvercel_[A-Za-z0-9_-]{20,}\b", re.IGNORECASE),
        "HIGH",
    ),
    (
        "Netlify Token",
        re.compile(r"\bnfp_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Sentry Auth Token",
        re.compile(r"\bsntrys_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Linear API Key",
        re.compile(r"\blin_api_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Resend API Key",
        re.compile(r"\bre_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Brevo API Key",
        re.compile(r"\bxkeysib-[A-Za-z0-9-]{20,}\b"),
        "HIGH",
    ),
    (
        "CircleCI Token",
        re.compile(r"\bCCIPAT_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Docker Hub Token",
        re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "DigitalOcean Token",
        re.compile(r"\bdo[op]_[A-Za-z0-9_-]{20,}\b"),
        "HIGH",
    ),
    (
        "Terraform Cloud Token",
        re.compile(r"\batlasv1\.[A-Za-z0-9._=-]{20,}\b"),
        "HIGH",
    ),

    # Cloud / messaging credential formats
    (
        "Alibaba Cloud Access Key",
        re.compile(r"\bLTAI[A-Za-z0-9]{12,}\b"),
        "HIGH",
    ),
    (
        "Cloudinary Credential URL",
        re.compile(r"(?i)\bcloudinary://[^\s:/]+:[^\s@]+@[^\s]+"),
        "HIGH",
    ),
    (
        "Firebase Service Account Key",
        re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----"),
        "HIGH",
    ),
    (
        "Twilio API Key",
        re.compile(r"\bSK[0-9a-f]{32}\b", re.IGNORECASE),
        "HIGH",
    ),

    # Key material and auth transport
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?(?:ENCRYPTED )?PRIVATE KEY-----"),
        "HIGH",
    ),
    (
        "SSH Private Key Header",
        re.compile(r"-----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----"),
        "HIGH",
    ),
    (
        "PGP Private Key Header",
        re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "HIGH",
    ),
    (
        "JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "HIGH",
    ),
    (
        "Bearer Token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"),
        "HIGH",
    ),
    (
        "Basic Auth Credential",
        re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]{20,}={0,2}"),
        "HIGH",
    ),

    (
        "Generic Secret Assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|access[_-]?key|secret|token|password|passwd|pwd|credential|client[_-]?secret|refresh[_-]?token|session[_-]?token|private[_-]?key|signing[_-]?key)"
            r"\s*[=:]\s*([A-Za-z0-9_+\-/=.:~]{20,})(?=\s*(?:#|;|$))"
        ),
        "MEDIUM",
    ),
    # Generic assignment catches unknown vendor-specific credentials.
    (
        "Generic API Key Assignment",
        re.compile(
            r"""(?i)\b(api[_-]?key|access[_-]?token|access[_-]?key|secret|token|password|passwd|pwd|credential|client[_-]?secret|refresh[_-]?token|session[_-]?token|private[_-]?key|signing[_-]?key)\s*[=:]\s*['\"]([A-Za-z0-9_+\-/=.:~]{16,})['\"]""",
            re.VERBOSE,
        ),
        "MEDIUM",
    ),
    (
        "Generic Authorization Header",
        re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*(?:Bearer|Token|Basic)\s+[A-Za-z0-9._~+/=-]{16,}"),
        "HIGH",
    ),

    # Database / service credential URLs.
    (
        "Database Credential URL",
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver)://[^\s:/]+:[^\s@]+@[^\s]+"),
        "HIGH",
    ),
]

# The "Database Credential URL" rule above is deliberately broad (it has to
# catch postgres/mysql/mongo/redis/etc. in one pattern), which means it also
# matches extremely common local-dev placeholder connection strings —
# postgres://postgres:postgres@localhost:5432/app,
# mysql://root:root@db:3306/test, redis://user:changeme@localhost:6379 —
# that show up constantly in docker-compose.yml, .env.example, and READMEs
# and are not leaked credentials. Flagging those at HIGH would mean the
# installed git hook (which blocks on any HIGH finding) rejects completely
# ordinary commits. This mirrors the same context-based suppression already
# applied to entropy candidates (TEST_CONTEXT_RE / BENIGN_NAME_RE below) —
# it downgrades confidence rather than hiding the finding outright, so a
# real secret sitting on the same shape of URL is still visible, just as a
# warning instead of a block.
_DB_CREDENTIAL_URL_DETAIL_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver)://"
    r"(?P<user>[^\s:/]+):(?P<password>[^\s@]+)@(?P<host>[^\s/:]+)(?::\d+)?"
)

_PLACEHOLDER_DB_HOSTS_RE = re.compile(
    r"(?i)^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|db|database|postgres|"
    r"postgresql|mysql|mariadb|mongo|mongodb|redis|host\.docker\.internal|"
    r"example\.com|your[_-]?host|db[_-]?host)$"
)

_PLACEHOLDER_DB_CREDENTIAL_WORDS = {
    "root", "admin", "user", "test", "guest", "postgres", "mysql", "mongo",
    "mariadb", "redis", "password", "passwd", "pass", "changeme",
    "change_me", "secret", "example", "demo", "default", "docker",
    "admin123", "postgres123", "mypassword", "myuser", "123456", "letmein",
}


def _db_credential_url_is_placeholder(matched_text: str) -> bool:
    """True if a Database Credential URL match looks like a well-known
    local-dev placeholder rather than a real leaked credential: either
    the host is a bare local/dev sentinel (localhost, db, 127.0.0.1, ...),
    or both the username and password are common example words used
    together (root:root, postgres:postgres, user:changeme, ...)."""
    match = _DB_CREDENTIAL_URL_DETAIL_RE.search(matched_text)
    if not match:
        return False

    host = match.group("host")
    if _PLACEHOLDER_DB_HOSTS_RE.match(host):
        return True

    user = match.group("user").casefold()
    password = match.group("password").casefold()
    return (
        user in _PLACEHOLDER_DB_CREDENTIAL_WORDS
        and password in _PLACEHOLDER_DB_CREDENTIAL_WORDS
    )

QUOTED_STRING_RE = re.compile(r"""['"]([A-Za-z0-9+/_=-]{20,})['"]""")
ENTROPY_THRESHOLD = 4.3
MIN_ENTROPY_LEN = 20

# Entropy is a heuristic, so common random-looking non-secrets should be
# filtered before scoring. These checks are local and standard-library-only.
UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# Conventional fixed-width hexadecimal digests are intentionally random-looking.
HEX_DIGEST_LENGTHS = {32, 40, 64, 96, 128}

# Common machine-generated values that can have high Shannon entropy but are
# not credentials. Keep these deliberately conservative: the goal is to
# suppress strong false-positive classes without hiding unknown secrets.
HEX_ONLY_RE = re.compile(r"(?i)^[0-9a-f]+$")
BASE64_ONLY_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

BENIGN_NAME_RE = re.compile(
    r"(?i)(?:^|[_\W])(?:id|uid|guid|uuid|request[_-]?id|trace[_-]?id|span[_-]?id|"
    r"correlation[_-]?id|transaction[_-]?id|checksum|hash|digest|sha(?:1|224|256|384|512)?|"
    r"md5|fingerprint|etag|revision|commit(?:[_-]?sha)?|build(?:[_-]?id)?|version|"
    r"nonce|salt|iv|initialization[_-]?vector|signature|serial(?:[_-]?number)?|"
    r"boundary|content[_-]?hash|cache[_-]?key)(?:$|[_\W])"
)

DATA_URI_RE = re.compile(r"(?i)^data:[^,]+,")

TEST_CONTEXT_RE = re.compile(
    r"(?i)(?:^|[_\W])(?:test|tests|fixture|fixtures|mock|mocks|dummy|fake|sample|"
    r"example|examples|placeholder|placeholders)(?:$|[_\W])"
)
SECRET_CONTEXT_RE = re.compile(
    r"(?i)(?:^|[_\W])(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd|"
    r"credential|auth|authorization|bearer|private[_-]?key|client[_-]?secret|"
    r"session[_-]?token|refresh[_-]?token|signing[_-]?key|jwt)(?:$|[_\W])"
)


def _is_hex_digest(candidate: str) -> bool:
    return (
        len(candidate) in HEX_DIGEST_LENGTHS
        and bool(re.fullmatch(r"[0-9a-fA-F]+", candidate))
    )


def _entropy_candidate_is_relevant(line: str, candidate_start: int, candidate: str) -> bool:
    """Filter high-confidence entropy false positives using local source context."""
    prefix = line[:candidate_start]

    if UUID_RE.fullmatch(candidate):
        return False

    if _is_hex_digest(candidate) and not SECRET_CONTEXT_RE.search(prefix):
        return False
    prefix_lower = prefix.casefold()

    # Test/demo data is usually intentionally random-looking. If the same
    # assignment explicitly mentions a secret-like name, keep it because the
    # test may be exercising a real detector case.
    if TEST_CONTEXT_RE.search(prefix) and not SECRET_CONTEXT_RE.search(prefix):
        return False

    # Avoid data URIs and embedded asset payloads. They are often long,
    # base64-looking strings and are not credentials.
    if DATA_URI_RE.search(prefix):
        return False

    # Machine identifiers and integrity values are another major source of
    # entropy false positives. Only suppress them when the local key/name is
    # clearly non-secret. A nearby secret keyword wins.
    if BENIGN_NAME_RE.search(prefix) and not SECRET_CONTEXT_RE.search(prefix):
        return False

    # Very common source-control/build metadata should not be treated as an
    # unknown secret merely because it is random-looking.
    if re.search(r"(?i)\b(?:sha256|sha384|sha512|md5|checksum|digest|commit)\b", prefix_lower):
        return False

    # Pure hexadecimal values are overwhelmingly hashes/IDs. Values of other
    # lengths are allowed because some real secrets are hexadecimal.
    if (
        HEX_ONLY_RE.fullmatch(candidate)
        and len(candidate) in range(24, 129)
        and not SECRET_CONTEXT_RE.search(prefix)
    ):
        return False

    return True


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

            match_confidence = confidence
            if name == "Database Credential URL" and _db_credential_url_is_placeholder(matched_text):
                match_confidence = "MEDIUM"

            raw.append((name, matched_text, match_confidence, (start, end)))

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

        if not _entropy_candidate_is_relevant(line, start, candidate):
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
