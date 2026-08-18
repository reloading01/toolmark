"""Secret masking for triage output.

Session transcripts contain raw prompts, file contents and credentials. The
report is itself a leak surface, so masking is on by default and the analyst
opts out explicitly.
"""

from __future__ import annotations

import re

# Ordered: specific vendor formats first so they win over the generic
# assignment rule and get an informative label.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}")),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("basic_auth_url", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@")),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*)"
            r"(\s*[:=]\s*)"
            r"(\"[^\"\n]{6,}\"|'[^'\n]{6,}'|[^\s'\"#;,)]{6,})"
        ),
    ),
]


def _mask(label: str) -> str:
    return f"[REDACTED:{label}]"


def redact(text: str) -> tuple[str, list[str]]:
    """Return the masked text and the labels of everything that was masked."""
    if not text:
        return text, []
    hits: list[str] = []
    out = text
    for label, pattern in _PATTERNS:
        if label == "secret_assignment":

            def repl(m: re.Match[str], _label: str = label) -> str:
                hits.append(_label)
                return f"{m.group(1)}{m.group(2)}{_mask(_label)}"

            out = pattern.sub(repl, out)
        else:
            out, n = pattern.subn(lambda _m, _l=label: _mask(_l), out)
            hits.extend([label] * n)
    return out, hits


def redact_value(value, enabled: bool = True):
    """Recursively mask strings inside tool inputs, preserving structure."""
    if not enabled:
        return value
    if isinstance(value, str):
        return redact(value)[0]
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    return value


def truncate(text: str, limit: int = 400) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [+{len(text) - limit} chars]"
