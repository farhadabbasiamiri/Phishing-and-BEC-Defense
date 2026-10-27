"""Generate a reproducible, balanced set of fictional training emails."""

import csv
import random
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "data" / "dummy_emails.csv"
SEED = 42


def build_records() -> list[dict[str, str]]:
    rng = random.Random(SEED)
    benign = [
        ("Project meeting notes", "Hi {name}, here are the notes from our project meeting. Please review when convenient."),
        ("Library book reminder", "A friendly reminder that your library book is due next week. Visit the library in person if you have questions."),
        ("Lunch order confirmation", "Your lunch order is confirmed for the usual pickup window. Reply if you need help."),
        ("Draft report for review", "Could you review this draft report by Friday? No rush if you need more time."),
        ("Schedule update", "The planning meeting moved to {time} tomorrow. The calendar invitation has been updated."),
        ("Workshop materials", "The workshop materials are ready. We will share them at the session next week."),
        ("Room reservation", "Your study room reservation is confirmed for {time}. Please contact the library desk with questions."),
        ("Monthly newsletter", "This month's department newsletter includes project updates, upcoming events, and office hours."),
        ("Travel itinerary", "Here is the itinerary for the approved campus visit. Let me know if the schedule needs adjustment."),
        ("Thank you for your help", "Thank you for helping with the event. We appreciate your time and careful planning."),
        ("Office hours this week", "I will be available during office hours on {day}. Bring any questions about the assignment."),
        ("Shared notes", "I added my notes from the group discussion to our shared class folder. Take a look when you have time."),
        ("Maintenance notice", "Routine maintenance is planned for the classroom projector after the last class on Friday."),
        ("Volunteer schedule", "The volunteer schedule is attached for review. Please let the coordinator know about conflicts."),
        ("Reading group", "The reading group will meet in the usual room next Wednesday. Feel free to suggest a paper."),
    ]
    suspicious = [
        ("Urgent: verify your account", "Your account will be suspended today. Verify your password immediately at hxxp://account-check.example/verify"),
        ("Payment overdue", "Final warning: invoice payment is overdue. Wire transfer the amount today and send bank details."),
        ("Confidential gift-card request", "I am in a meeting. Buy gift cards immediately and send the codes. Keep this confidential."),
        ("Mailbox locked", "Your mailbox is locked. Sign in now to verify your credentials or access will expire within 24 hours: hxxps://mail-access.example/login"),
        ("Updated supplier bank details", "Please change the supplier bank details before today's payment run. This is urgent; act now."),
        ("Security code required", "Your password expires today. Reply with your security code and credentials to restore access immediately."),
        ("Overdue invoice action required", "Pay the invoice immediately using a wire transfer. Do not contact the usual finance team."),
        ("Shared document access", "Your account will expire today. Sign in and verify your password at hxxp://document-share.example/secure"),
        ("Payroll update required", "Confirm your bank account and password immediately so payroll is not suspended today."),
        ("Private executive request", "Purchase gift cards today and send the codes by reply. Do not discuss this request with anyone."),
        ("Final delivery notice", "Your parcel is held. Pay the outstanding fee today and enter your credentials to release it."),
        ("Unusual sign-in alert", "We detected a sign-in. Verify your password immediately at hxxps://identity-check.example/session"),
        ("Revised payment instructions", "Change the bank details before payment. This confidential wire transfer must happen today."),
        ("Document access expires", "Sign in now to keep access to the shared document. Verify your account within 24 hours."),
        ("Action required: account review", "Your account is locked. Reply with your one-time code and password to avoid suspension."),
    ]
    benign_senders = [
        ("alex", "university.example"), ("sam", "campus.example"),
        ("library", "university.example"), ("events", "campus.example"),
        ("coordinator", "department.example"),
    ]
    suspicious_senders = [
        ("notice", "account-alert.example"), ("billing", "vendor-notice.example"),
        ("support", "mail-check.example"), ("director", "company-notice.example"),
        ("payroll", "staff-update.example"),
    ]
    rows: list[dict[str, str]] = []
    for label, templates, senders, count, prefix in (
        ("benign", benign, benign_senders, 150, "B"),
        ("suspicious", suspicious, suspicious_senders, 150, "S"),
    ):
        for index in range(count):
            subject, body = templates[index % len(templates)]
            name = ["Riley", "Jordan", "Casey", "Taylor", "Morgan"][index % 5]
            sender_name, sender_domain = senders[index % len(senders)]
            values = {"name": name, "time": f"{9 + index % 8}:00", "day": ["Monday", "Tuesday", "Wednesday"][index % 3]}
            body = body.format(**values)
            if label == "benign":
                reply_to = ""
                auth = "SPF pass; DKIM pass; DMARC pass"
                attachment = ["", "", "", "meeting-notes.pdf"][index % 4]
                body += ["", " Thank you.", " Please let me know if you have questions.", ""][index % 4]
            else:
                reply_to = f"reply{index % 7}@unrelated-mail.example" if index % 3 else ""
                auth = ["SPF fail; DKIM fail; DMARC fail", "SPF pass; DKIM fail; DMARC fail", "Not provided"][index % 3]
                attachment = ["", "account.html", "invoice.xlsm", ""][index % 4]
                body += ["", " Please act now.", " This request is for the named recipient.", ""][index % 4]
            rows.append({
                "id": f"SYN-{prefix}-{index + 1:03d}",
                "sender": f"{sender_name}@{sender_domain}",
                "reply_to": reply_to,
                "subject": subject,
                "body": body,
                "auth_results": auth,
                "attachment_metadata": attachment,
                "label": label,
            })
    rng.shuffle(rows)
    return rows


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    rows = build_records()
    columns = ["id", "sender", "reply_to", "subject", "body", "auth_results", "attachment_metadata", "label"]
    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {len(rows)} synthetic emails at {OUTPUT}")


if __name__ == "__main__":
    main()
