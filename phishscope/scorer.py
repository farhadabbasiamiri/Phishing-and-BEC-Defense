"""Transparent rule score + optional ML classifier + hybrid."""
FLAG_AT, PHISH_AT = 25, 55

# (feature, weight function, human-readable text)
RULES = [
    ("url_lookalike", lambda f: 30 * f["url_lookalike"], "Link points to a lookalike of a well-known brand domain"),
    ("brand_spoof", lambda f: 25 * f["brand_spoof"], "Sender display name claims a brand but the address domain does not match"),
    ("url_mismatch", lambda f: 20 * f["url_mismatch"], "Link text shows one domain but the link goes to another"),
    ("url_ip_or_short", lambda f: 15 * f["url_ip_or_short"], "Link uses an IP address or URL shortener"),
    ("url_bad_tld", lambda f: 12 * f["url_bad_tld"], "Link uses an uncommon TLD or punycode"),
    ("replyto_mismatch", lambda f: 20 * f["replyto_mismatch"], "Reply-To domain differs from the From domain"),
    ("returnpath_mismatch", lambda f: 10 * f["returnpath_mismatch"], "Return-Path domain differs from the From domain"),
    ("freemail_exec", lambda f: 25 * f["freemail_exec"], "Executive-style name sending from a free email provider"),
    ("spf_fail", lambda f: 10 * f["spf_fail"], "SPF failed or soft-failed"),
    ("dkim_fail", lambda f: 8 * f["dkim_fail"], "DKIM signature failed"),
    ("dmarc_fail", lambda f: 12 * f["dmarc_fail"], "DMARC failed"),
    ("urgency", lambda f: 5 * min(f["urgency"], 3), "Urgency / pressure language"),
    ("payment", lambda f: 6 * min(f["payment"], 2), "Payment or banking request language"),
    ("credential", lambda f: 5 * min(f["credential"], 2), "Asks the reader to sign in or confirm credentials"),
    ("secrecy", lambda f: 8 * min(f["secrecy"], 2), "Secrecy / do-not-call language typical of BEC"),
    ("bec_combo", lambda f: 15 * int(f["payment"] > 0 and f["secrecy"] > 0), "Payment request combined with secrecy (BEC pattern)"),
    ("risky_attachment", lambda f: 20 * f["risky_attachment"], "Attachment type often used to deliver phishing pages or malware"),
    ("double_extension", lambda f: 15 * f["double_extension"], "Attachment has a double extension"),
    ("injection", lambda f: 25 * f["injection"], "Email text tries to instruct an AI/analyst (prompt-injection attempt)"),
    ("auth_all_pass", lambda f: -15 * f["auth_all_pass"], "SPF, DKIM and DMARC all pass (reduces risk)"),
]


def label_for(score):
    return "Phishing" if score >= PHISH_AT else "Suspicious" if score >= FLAG_AT else "Benign"


def rule_score(feats):
    evidence, total = [], 0
    for name, fn, text in RULES:
        w = fn(feats)
        if w:
            total += w
            evidence.append({"indicator": name, "detail": text, "weight": w})
    for u in feats["_urls"]:
        for issue in u["issues"]:
            evidence.append({"indicator": "url", "detail": f"{u['url']}: {issue}", "weight": 0})
    total = max(0, min(100, total))
    evidence.sort(key=lambda e: -abs(e["weight"]))
    return {"score": total, "label": label_for(total), "evidence": evidence}


# ------------------------------------------------------------------ ML
def train_ml(X, y):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, C=0.5)).fit(X, y)


def ml_prob(model, feats, cols):
    import pandas as pd
    return float(model.predict_proba(pd.DataFrame([[feats[c] for c in cols]], columns=cols))[0][1])


def hybrid_score(rule, prob):
    return round(0.5 * rule + 0.5 * 100 * prob, 1)
