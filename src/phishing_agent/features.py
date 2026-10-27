"""Transparent, local feature extraction from email text and supplied metadata."""

import re

from .parser import defang_url, domain_from_address, domain_from_url, extract_urls
from .safety import detect_prompt_injection
from .schemas import EmailRecord, FeatureSet

URGENCY_TERMS = (
    "urgent", "immediately", "act now", "within 24 hours", "today",
    "suspended", "expire", "final warning", "verify now", "account locked",
)
CREDENTIAL_TERMS = (
    "password", "sign in", "log in", "verify your account", "credentials",
    "one-time code", "security code",
)
PAYMENT_TERMS = (
    "wire transfer", "bank details", "payment", "gift card", "invoice",
    "pay immediately", "change of bank", "bank account",
)
RISKY_EXTENSIONS = (".html", ".htm", ".iso", ".js", ".vbs", ".exe", ".scr", ".docm", ".xlsm", ".zip", ".lnk")
_AUTH_FAIL = re.compile(r"\b(spf|dkim|dmarc)(?:\s*[=:]\s*|\s+)(fail|softfail|permerror|temperror)\b", re.I)


def _hits(text: str, terms: tuple[str, ...]) -> list[str]:
    lower = text.casefold()
    return [term for term in terms if term in lower]


def extract_features(email: EmailRecord) -> FeatureSet:
    text = f"{email.subject}\n{email.body}"
    urls = extract_urls(text)
    sender_domain = domain_from_address(email.sender)
    reply_domain = domain_from_address(email.reply_to)
    domain_mismatch = bool(sender_domain and reply_domain and sender_domain != reply_domain)
    risky_extensions = sorted({
        extension for extension in RISKY_EXTENSIONS
        if re.search(re.escape(extension) + r"(?:\b|$)", email.attachment_metadata, re.I)
    })

    patterns: list[str] = []
    for url in urls:
        parsed_domain = domain_from_url(url)
        normalized = url.lower()
        if "@" in normalized:
            patterns.append(f"URL contains an @ sign: {defang_url(url)}")
        if parsed_domain and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parsed_domain):
            patterns.append(f"URL uses a numeric host: {defang_url(url)}")
        if parsed_domain and ("xn--" in parsed_domain or parsed_domain.count(".") >= 4):
            patterns.append(f"URL has an unusual hostname structure: {defang_url(url)}")
        if "%" in url:
            patterns.append(f"URL contains percent-encoded characters: {defang_url(url)}")

    auth_failures = sorted({
        f"{protocol.upper()} {status.upper()}"
        for protocol, status in _AUTH_FAIL.findall(email.auth_results)
    })
    return FeatureSet(
        url_count=len(urls),
        urls_defanged=[defang_url(url) for url in urls],
        sender_domain=sender_domain,
        reply_to_domain=reply_domain,
        domain_mismatch=domain_mismatch,
        urgency_terms=_hits(text, URGENCY_TERMS),
        credential_terms=_hits(text, CREDENTIAL_TERMS),
        payment_terms=_hits(text, PAYMENT_TERMS),
        risky_extensions=risky_extensions,
        authentication_failures=auth_failures,
        suspicious_url_patterns=list(dict.fromkeys(patterns)),
        prompt_injection_detected=detect_prompt_injection(text),
    )
