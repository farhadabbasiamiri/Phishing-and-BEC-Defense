"""Safe email and URL parsing. This module never opens links or attachments."""

from email import policy
from email.parser import Parser
from email.utils import getaddresses
import re
from urllib.parse import urlsplit

URL_RE = re.compile(r"""(?i)(?<![\w@])(?:https?://|hxxps?://|www\.)[^\s<>"']+""")
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}"
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def extract_urls(text: str) -> list[str]:
    """Extract URL-shaped strings without resolving or requesting them."""
    found: list[str] = []
    for match in URL_RE.findall(text or ""):
        url = match.rstrip(_TRAILING_URL_PUNCTUATION)
        if url and url not in found:
            found.append(url)
    return found


def defang_url(url: str) -> str:
    """Return a non-clickable display form of an extracted URL."""
    value = re.sub(r"(?i)^https://", "hxxps://", url.strip())
    value = re.sub(r"(?i)^http://", "hxxp://", value)
    return value.replace(".", "[.]")


def domain_from_address(value: str) -> str:
    """Extract a lowercase domain from an address or display-name address."""
    addresses = getaddresses([value or ""])
    if not addresses:
        return ""
    address = addresses[0][1]
    if "@" not in address:
        return ""
    domain = address.rsplit("@", 1)[1].strip().rstrip(".").lower()
    labels = domain.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        return ""
    return domain


def domain_from_url(value: str) -> str:
    """Parse the hostname locally; never resolve DNS or contact the host."""
    url = value.strip()
    if url.lower().startswith("hxxps://"):
        url = "https://" + url[8:]
    elif url.lower().startswith("hxxp://"):
        url = "http://" + url[7:]
    elif url.lower().startswith("www."):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def parse_headers(raw_headers: str) -> dict[str, str]:
    """Parse pasted RFC-style headers only; no message retrieval is performed."""
    if not raw_headers.strip():
        return {}
    message = Parser(policy=policy.default).parsestr(raw_headers, headersonly=True)
    return {
        key: str(message.get(key, "") or "")
        for key in ("From", "Reply-To", "Subject", "Authentication-Results")
        if message.get(key)
    }
