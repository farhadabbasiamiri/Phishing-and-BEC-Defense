"""Synthetic email generator. All malicious-looking domains are random and stored defanged;
nothing here points at real infrastructure."""
import csv
import random

FIRST = ["Alex", "Sam", "Jordan", "Priya", "Marc", "Chloe", "Liam", "Aisha", "Noah", "Emma", "Omar", "Sofia"]
LAST = ["Tremblay", "Singh", "Roy", "Chen", "Martin", "Nguyen", "Gagnon", "Patel", "Lavoie", "Brown"]
BRANDS = ["microsoft", "paypal", "google", "amazon", "docusign", "dropbox", "netflix", "linkedin", "canadapost", "rbc"]
WORDS = ["secure", "login", "verify", "account", "support", "portal", "update", "service", "help"]
BAD_TLD = ["xyz", "top", "click", "icu", "support", "work"]
VENDORS = ["northshorefoods.ca", "bluelakesupply.ca", "granitetools.com", "sudburyprint.ca", "cedarparts.com"]
LEGIT_SITES = {"microsoft": "microsoft.com", "paypal": "paypal.com", "google": "google.com",
               "amazon": "amazon.ca", "docusign": "docusign.com", "dropbox": "dropbox.com",
               "netflix": "netflix.com", "linkedin": "linkedin.com", "canadapost": "canadapost.ca", "rbc": "rbcroyalbank.com"}
ORG = "laurentian.ca"


def _typo(b, r):
    opts = [b.replace("o", "0", 1), b.replace("l", "1", 1), b.replace("m", "rn", 1), b + "-" + r.choice(WORDS),
            r.choice(WORDS) + "-" + b]
    t = r.choice(opts)
    return t if t != b else b + "-" + r.choice(WORDS)


def _name(r):
    return f"{r.choice(FIRST)} {r.choice(LAST)}"


def _defanged(domain, path=""):
    return "hxxps://" + domain.replace(".", "[.]") + path


def _bad_domain(r, brand):
    return f"{_typo(brand, r)}.{r.choice(BAD_TLD)}"


def _auth(r, p_pass):
    if r.random() < p_pass:
        return "pass", "pass", "pass"
    return r.choice(["fail", "softfail", "none"]), r.choice(["fail", "none"]), r.choice(["fail", "none"])


def phish(r, i):
    kind = r.choice(["credential", "invoice", "bec", "parcel", "payroll", "evasive", "evasive_bec"])
    brand = r.choice(BRANDS)
    spf, dkim, dmarc = _auth(r, 0.12)
    rec = dict(id=f"P{i:04d}", label="phishing", category=kind, reply_to="", return_path="", attachments="")
    bd = _bad_domain(r, brand)
    link = _defanged(bd, "/verify?id=" + str(r.randint(1000, 9999)))
    if kind == "credential":
        rec.update(subject=r.choice([f"Action required: {brand.title()} account suspended", "Unusual sign-in detected",
                                     "Your password expires today"]),
                   **{"from": f"{brand.title()} Security <no-reply@{bd}>"},
                   body=f"Hello,\n\nWe noticed unusual activity. You must verify your account within 24 hours or it will be suspended.\nSign in here: {link}\n\nThank you,\n{brand.title()} Support")
    elif kind == "invoice":
        rec.update(subject=f"Invoice {r.randint(1000, 9999)} - payment overdue",
                   **{"from": f"Accounts <billing@{bd}>"}, reply_to=f"collect@{r.choice(WORDS)}-mail.{r.choice(BAD_TLD)}",
                   body="Please find the attached invoice. Payment is urgent; final notice before escalation. Open the attachment to view bank details.",
                   attachments=r.choice([f"Invoice_{r.randint(100,999)}.html", f"Invoice.pdf.exe", f"Statement_{r.randint(10,99)}.docm", "Payment.iso"]))
    elif kind == "bec":
        boss = _name(r)
        rec.update(subject="Quick favour", **{"from": f"{boss}, President <{boss.split()[0].lower()}.{boss.split()[1].lower()}@{r.choice(['gmail.com','outlook.com','proton.me'])}>"},
                   body=f"Hi,\n\nI am in a meeting and cannot talk. I need you to purchase {r.randint(3,8)} gift card codes of $100 for a client today. Keep this confidential and reply only by email.\n\n{boss}",
                   spf="pass", dkim="pass", dmarc="none")
        spf, dkim, dmarc = "pass", "none", "none"
    elif kind == "parcel":
        rec.update(subject="Your parcel could not be delivered", **{"from": "Canada Post <tracking@canadapost-delivery.top>"},
                   body=f"Delivery failed. Reschedule immediately and pay the $2.99 fee: {_defanged('bit.ly', '/' + ''.join(r.choices('abcxyz789', k=6)))}")
    elif kind == "payroll":
        rec.update(subject="Change of direct deposit", **{"from": f"{_name(r)} <hr@{ORG.replace('.ca', '-hr.ca')}>"},
                   reply_to=f"{r.choice(FIRST).lower()}{r.randint(10,99)}@gmail.com",
                   body="Hello payroll, please update my bank account details before Friday. Do not call, I am travelling. Send confirmation by email.")
    elif kind == "evasive":  # compromised account: passes auth, link looks soft
        spf, dkim, dmarc = "pass", "pass", "pass"
        rec.update(subject="Shared document", **{"from": f"{_name(r)} <{r.choice(FIRST).lower()}@{r.choice(VENDORS)}>"},
                   body=f"I shared a file with you. Please sign in to view it: {_defanged(bd, '/doc')}")
    else:  # evasive_bec: clean wording, no links
        spf, dkim, dmarc = "pass", "pass", "none"
        rec.update(subject="Updated banking details", **{"from": f"{_name(r)} <accounts@{r.choice(VENDORS)}>"},
                   reply_to=f"accounts@{r.choice(VENDORS).replace('.', '-')}.com",
                   body="Hello, our bank account details have changed. Please use the new details for the next payment.")
    rec.update(spf=spf, dkim=dkim, dmarc=dmarc)
    return rec


def benign(r, i):
    kind = r.choice(["newsletter", "memo", "invoice", "reset", "invite", "hard_it", "hard_marketing"])
    spf = dkim = dmarc = "pass"
    rec = dict(id=f"B{i:04d}", label="benign", category=kind, reply_to="", return_path="", attachments="")
    brand = r.choice(BRANDS)
    if kind == "newsletter":
        rec.update(subject="Monthly newsletter", **{"from": f"News <news@{LEGIT_SITES[brand]}>"},
                   body="Highlights this month:\nhttps://www.%s/blog/a\nhttps://www.%s/blog/b\nhttps://www.%s/events" % ((LEGIT_SITES[brand],) * 3))
    elif kind == "memo":
        rec.update(subject="Faculty meeting Thursday", **{"from": f"{_name(r)} <{r.choice(FIRST).lower()}@{ORG}>"},
                   body="Hi all, reminder of the meeting Thursday at 2pm in room A-204. Agenda attached. Thanks!", attachments="agenda.pdf")
    elif kind == "invoice":
        v = r.choice(VENDORS)
        rec.update(subject=f"Invoice {r.randint(1000,9999)} for October", **{"from": f"Accounts <billing@{v}>"},
                   body="Hello, attached is the invoice for last month's order. Payment terms are net 30. Let us know if you have questions.", attachments="invoice.pdf")
    elif kind == "reset":
        rec.update(subject="Reset your password", **{"from": f"Google <no-reply@accounts.google.com>"},
                   body="You asked to reset your password. Sign in to your account at https://accounts.google.com/reset within 24 hours. If this wasn't you, ignore this email.")
    elif kind == "invite":
        rec.update(subject="Project sync", **{"from": f"{_name(r)} <{r.choice(FIRST).lower()}@{ORG}>"},
                   body="Join the call at https://teams.microsoft.com/l/meetup-join/abc. Agenda: status update, risks, next steps.")
    elif kind == "hard_it":  # urgent but legitimate; forwarder breaks DKIM
        dkim = "fail"
        rec.update(subject="Urgent: password expires today", **{"from": f"IT Help Desk <helpdesk@{ORG}>"},
                   body="Your campus password expires today. Please log in at https://login.microsoftonline.com to change it immediately.")
    else:  # hard_marketing: shorteners + soft SPF
        spf = "softfail"
        rec.update(subject="Final notice: sale ends today!", **{"from": f"Deals <deals@{r.choice(VENDORS)}>"},
                   body="Act now! Our sale expires today. Shop: https://bit.ly/%s" % "".join(r.choices("abcdef123", k=6)))
    rec.update(spf=spf, dkim=dkim, dmarc=dmarc)
    return rec


def generate(n_phish=250, n_benign=250, seed=42):
    r = random.Random(seed)
    rows = [phish(r, i) for i in range(n_phish)] + [benign(r, i) for i in range(n_benign)]
    r.shuffle(rows)
    return rows


def write_csv(path, rows):
    cols = ["id", "label", "category", "subject", "from", "reply_to", "return_path", "spf", "dkim", "dmarc", "attachments", "body"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for row in rows:
            w.writerow({c: row.get(c, "") for c in cols})
