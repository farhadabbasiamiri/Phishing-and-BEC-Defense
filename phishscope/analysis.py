"""Parser, URL/domain checker and feature extractor.

SAFETY: nothing here ever opens, fetches or renders a URL. URLs are treated as
plain strings and are always shown defanged (hxxp://example[.]com).
"""
import re
from email import message_from_string, policy
from urllib.parse import urlparse

URL_RE = re.compile(r"(?:https?|hxxps?)://(?:\[[.:]\]|[^\s<>\"')\[\]])+", re.I)
HREF_RE = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)

LEGIT = {
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"},
    "paypal": {"paypal.com"}, "google": {"google.com", "gmail.com", "youtube.com"},
    "amazon": {"amazon.com", "amazon.ca"}, "apple": {"apple.com", "icloud.com"},
    "docusign": {"docusign.com", "docusign.net"}, "dropbox": {"dropbox.com"},
    "netflix": {"netflix.com"}, "linkedin": {"linkedin.com"}, "dhl": {"dhl.com"},
    "canadapost": {"canadapost.ca", "canadapost-postescanada.ca"},
    "laurentian": {"laurentian.ca"}, "rbc": {"rbc.com", "rbcroyalbank.com"},
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy", "cutt.ly"}
SUS_TLDS = {"xyz", "top", "click", "icu", "buzz", "support", "zip", "mov", "work", "rest", "cfd", "sbs"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "aol.com"}
RISKY_EXT = {"html", "htm", "iso", "img", "lnk", "js", "vbs", "exe", "scr", "docm", "xlsm", "zip", "rar", "one", "hta"}

KW = {
    "urgency": ["urgent", "immediately", "within 24 hours", "right away", "final notice", "act now",
                "account will be suspended", "expires today", "asap", "last warning", "time sensitive"],
    "payment": ["wire transfer", "gift card", "invoice", "bank details", "bank account", "payment",
                "bitcoin", "change of banking", "direct deposit", "remittance", "purchase card"],
    "credential": ["verify your account", "confirm your password", "sign in", "log in", "login",
                   "password", "credentials", "security code", "mfa", "re-authenticate", "validate your"],
    "secrecy": ["confidential", "do not call", "don't call", "keep this between us", "i am in a meeting",
                "cannot talk", "reply only by email", "do not tell"],
}
INJECTION = [r"ignore (all |any )?(previous|prior) instructions", r"mark (this|the email) as (safe|benign)",
             r"you are (an? )?(ai|assistant|language model)", r"system prompt", r"do not (flag|report) this"]


def defang(u):
    if "hxxp" in u or "[.]" in u:
        return u
    return u.replace("http", "hxxp", 1).replace(".", "[.]")


def refang(u):
    return u.replace("hxxp", "http").replace("[.]", ".").replace("[:]", ":")


def _addr(value):
    m = re.search(r"([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})", value or "")
    return m.group(1).lower() if m else ""


def _dom(addr):
    return addr.split("@")[-1].lower() if "@" in addr else ""


def reg_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _norm(s):
    return s.lower().replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w").replace("-", "")


# ---------------------------------------------------------------- parsing
def parse_raw(text):
    """Parse a pasted email. Works with full headers or just a body."""
    text = text.replace("\r\n", "\n").strip()
    if not re.match(r"^[A-Za-z][A-Za-z-]*:\s", text):
        return normalize({"body": text})
    msg = message_from_string(text, policy=policy.default)
    body_part = msg.get_body(preferencelist=("plain", "html"))
    body = body_part.get_content() if body_part else str(msg.get_payload())
    atts = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    extra = msg.get("X-Attachments", "")
    atts += [a.strip() for a in re.split(r"[;,]", extra) if a.strip()]
    return normalize({
        "subject": msg.get("Subject", ""), "from": msg.get("From", ""), "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""), "body": body,
        "auth": " ".join(msg.get_all("Authentication-Results", []) or []) + " " + str(msg.get("Received-SPF", "")),
        "attachments": atts,
    })


def normalize(rec):
    """Turn a raw record (paste or CSV row) into the PhishScope schema."""
    def g(k):
        v = rec.get(k)
        return "" if v is None or str(v) == "nan" else str(v)
    auth = g("auth") or " ".join(f"{k}={g(k)}" for k in ("spf", "dkim", "dmarc") if g(k))

    def flag(name):
        m = re.search(rf"{name}=(\w+)", auth, re.I)
        return m.group(1).lower() if m else "none"
    atts = rec.get("attachments", "")
    if isinstance(atts, str):
        atts = [a.strip() for a in re.split(r"[;|]", atts) if a.strip()]
    frm = g("from")
    return {
        "id": g("id") or "pasted", "subject": g("subject"), "from_raw": frm,
        "from_name": re.sub(r"<.*?>|\"", "", frm).strip(), "from_addr": _addr(frm),
        "reply_to": _addr(g("reply_to")), "return_path": _addr(g("return_path")),
        "body": g("body"), "spf": flag("spf"), "dkim": flag("dkim"), "dmarc": flag("dmarc"),
        "attachments": list(atts),
    }


# ------------------------------------------------------------ URL checking
def extract_urls(body):
    pairs = [(re.sub(r"<.*?>", "", m.group(2)).strip(), m.group(1)) for m in HREF_RE.finditer(body)]
    seen = {u for _, u in pairs}
    for m in URL_RE.finditer(body):
        u = m.group(0).rstrip(".,;")
        if u not in seen:
            pairs.append((None, u))
            seen.add(u)
    return pairs


def check_url(display, url):
    u = refang(url)
    try:
        host = (urlparse(u).hostname or "").lower()
    except ValueError:
        host = ""
    rd = reg_domain(host)
    label = rd.split(".")[0]
    issues = []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        issues.append("IP address used instead of a domain")
    if rd in SHORTENERS:
        issues.append("URL shortener hides the real destination")
    if "xn--" in host:
        issues.append("Punycode / possible homograph domain")
    if rd.split(".")[-1] in SUS_TLDS:
        issues.append(f"Uncommon TLD .{rd.split('.')[-1]}")
    if "@" in u.split("//", 1)[-1].split("/")[0]:
        issues.append("'@' in URL authority (credential-style trick)")
    if host.count(".") >= 4:
        issues.append("Excessive subdomains")
    for brand, legit in LEGIT.items():
        if rd in legit:
            break
        in_host = brand in _norm(host.replace(".", ""))
        near = _lev(_norm(label), brand) <= 2 and len(label) >= 5
        if in_host or near:
            issues.append(f"Lookalike of '{brand}' (real domain would be {sorted(legit)[0]})")
            break
    if display:
        m = re.search(r"((?:[\w-]+\.)+[a-z]{2,})", display, re.I)
        if m and reg_domain(m.group(1)) != rd:
            issues.append(f"Link text shows '{display[:40]}' but goes to {rd}")
    return {"url": defang(url), "domain": rd, "issues": issues}


# ----------------------------------------------------------------- features
def _hits(text, words):
    t = text.lower()
    return [w for w in words if w in t]


def extract_features(rec):
    text = f"{rec['subject']} {rec['body']}"
    urls = [check_url(d, u) for d, u in extract_urls(rec["body"])]
    fdom, rdom = _dom(rec["from_addr"]), _dom(rec["reply_to"])
    brand_claim = next((b for b in LEGIT if b in rec["from_name"].lower().replace(" ", "")), None)
    exts = [a.rsplit(".", 1)[-1].lower() for a in rec["attachments"] if "." in a]
    any_issue = lambda key: int(any(key in i for u in urls for i in u["issues"]))
    f = {
        "n_urls": len(urls),
        "n_url_domains": len({u["domain"] for u in urls}),
        "url_issue_count": sum(len(u["issues"]) for u in urls),
        "url_lookalike": any_issue("Lookalike"),
        "url_mismatch": any_issue("Link text"),
        "url_ip_or_short": int(any_issue("IP address") or any_issue("shortener")),
        "url_bad_tld": int(any_issue("TLD") or any_issue("Punycode")),
        "replyto_mismatch": int(bool(rdom and fdom and reg_domain(rdom) != reg_domain(fdom))),
        "returnpath_mismatch": int(bool(rec["return_path"] and fdom and reg_domain(_dom(rec["return_path"])) != reg_domain(fdom))),
        "brand_spoof": int(bool(brand_claim and fdom and reg_domain(fdom) not in LEGIT[brand_claim])),
        "freemail_exec": int(fdom in FREEMAIL and bool(re.search(r"\b(ceo|cfo|president|director|vp|dean|chair)\b", rec["from_name"].lower()))),
        "spf_fail": int(rec["spf"] in {"fail", "softfail"}),
        "dkim_fail": int(rec["dkim"] == "fail"),
        "dmarc_fail": int(rec["dmarc"] == "fail"),
        "auth_all_pass": int(rec["spf"] == rec["dkim"] == rec["dmarc"] == "pass"),
        "urgency": len(_hits(text, KW["urgency"])),
        "payment": len(_hits(text, KW["payment"])),
        "credential": len(_hits(text, KW["credential"])),
        "secrecy": len(_hits(text, KW["secrecy"])),
        "risky_attachment": int(any(e in RISKY_EXT for e in exts)),
        "double_extension": int(any(re.search(r"\.\w{2,4}\.\w{2,4}$", a) and a.rsplit(".", 1)[-1].lower() in RISKY_EXT for a in rec["attachments"])),
        "injection": int(any(re.search(p, text, re.I) for p in INJECTION)),
    }
    f["_urls"] = urls
    f["_hits"] = {k: _hits(text, v) for k, v in KW.items()}
    return f


FEATURE_COLS = [
    "n_urls", "n_url_domains", "url_issue_count", "url_lookalike", "url_mismatch", "url_ip_or_short", "url_bad_tld",
    "replyto_mismatch", "returnpath_mismatch", "brand_spoof", "freemail_exec", "spf_fail", "dkim_fail", "dmarc_fail",
    "auth_all_pass", "urgency", "payment", "credential", "secrecy", "risky_attachment", "double_extension", "injection"]
