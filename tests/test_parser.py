"""Parsing tests ensure local-only URL handling."""

from src.phishing_agent.parser import defang_url, domain_from_address, extract_urls, parse_headers


def test_url_extraction_and_defanging():
    urls = extract_urls("Visit https://example.com/path, and hxxp://mail.example/reset.")
    assert urls == ["https://example.com/path", "hxxp://mail.example/reset"]
    assert defang_url(urls[0]) == "hxxps://example[.]com/path"
    assert defang_url(urls[1]) == "hxxp://mail[.]example/reset"


def test_deduplicates_urls_without_touching_network():
    assert extract_urls("https://example.com https://example.com") == ["https://example.com"]


def test_email_domain_parsing_handles_display_name():
    assert domain_from_address("Riley Example <riley@University.Example>") == "university.example"
    assert domain_from_address("not an address") == ""
    assert domain_from_address("sender@http://example.com") == ""


def test_pasted_header_parsing():
    parsed = parse_headers(
        "From: sender@university.example\nReply-To: reply@mail.example\n"
        "Subject: Example\nAuthentication-Results: SPF fail\n\n"
    )
    assert parsed["From"] == "sender@university.example"
    assert parsed["Subject"] == "Example"
    assert parsed["Authentication-Results"] == "SPF fail"
