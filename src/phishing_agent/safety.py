"""Safety boundaries for untrusted email text and result exports."""

import re

_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions\b", re.I),
    re.compile(r"\b(?:reveal|print|show)\s+(?:the\s+)?(?:system\s+)?(?:prompt|secrets?|credentials)\b", re.I),
    re.compile(r"\b(?:call|use|invoke)\s+(?:your\s+)?tools?\b", re.I),
    re.compile(r"\bact\s+as\s+(?:the\s+)?(?:system|developer|assistant)\b", re.I),
)


def detect_prompt_injection(text: str) -> bool:
    """Flag common instruction-like content; the deterministic agent ignores it."""
    return any(pattern.search(text or "") for pattern in _INJECTION_PATTERNS)


def csv_safe_cell(value: object) -> object:
    """Prevent spreadsheet formula interpretation in user-controlled exports."""
    if not isinstance(value, str):
        return value
    trimmed = value.lstrip()
    if trimmed.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def csv_safe_frame(frame):
    """Return a copy whose text cells cannot become spreadsheet formulas."""
    return frame.map(csv_safe_cell)
