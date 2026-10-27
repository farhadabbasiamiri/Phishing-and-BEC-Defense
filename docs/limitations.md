# Limitations and analyst guidance

This is an educational demonstration, not a production security control. It does not authenticate the sender, verify supplied SPF/DKIM/DMARC results, inspect complete RFC transport context, look up URL reputation, resolve domains, inspect attachment contents, or prove malicious intent. It uses a small authored synthetic dataset and English-language keyword/pattern features.

## False positives

Legitimate account notifications, urgent deadlines, invoices, security training, or unusual Reply-To routing may accumulate heuristic points. A URL or executable-looking filename is a warning signal, not proof of malware. Verify benign business context independently rather than dismissing a sender solely from a score.

## False negatives

Subtle or novel social engineering, compromised legitimate accounts, benign-looking link text, non-English messages, image-only content, hidden HTML, unusual encodings, and attacker tactics outside the fixed indicators may receive low scores. A passing supplied authentication result is not proof that the message or request is safe.

## Human review

Use scores only to prioritize careful review. Never click links, execute attachments, or make payments based only on this output. Confirm money, credential, and account requests using a separately obtained trusted contact method and follow organizational reporting procedures.