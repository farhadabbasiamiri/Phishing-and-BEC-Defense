"""Generate data/emails.csv (250 phishing + 250 benign synthetic emails)."""
from phishscope.generator import generate, write_csv

rows = generate()
write_csv("data/emails.csv", rows)
print(f"Wrote {len(rows)} emails to data/emails.csv")
