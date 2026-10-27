"""Batch CSV validation, row-level errors, and safe exports."""

import pandas as pd

from src.phishing_agent.agent import analyze_email
from src.phishing_agent.csv_io import MAX_UPLOAD_BYTES, results_csv_bytes, validate_csv_bytes


def test_csv_missing_message_columns_fails_clearly():
    entries, errors = validate_csv_bytes(b"sender,reply_to\nperson@university.example,")
    assert entries == []
    assert "subject" in errors[0] and "body" in errors[0]


def test_row_validation_and_absent_optional_fields():
    entries, errors = validate_csv_bytes(
        b"subject,body,sender\nRoutine note,Hello,person@university.example\n,,bad-address\n"
    )
    assert errors == []
    assert entries[0]["email"].body == "Hello"
    assert entries[0]["email"].reply_to == ""
    assert entries[0]["errors"] == []
    assert entries[1]["email"] is None
    assert entries[1]["errors"]


def test_malformed_and_oversized_csv_report_errors():
    entries, errors = validate_csv_bytes(b'subject,body\n"unfinished')
    assert not entries and "parse" in errors[0].lower()
    entries, errors = validate_csv_bytes(b"x" * (MAX_UPLOAD_BYTES + 1))
    assert not entries and "limit" in errors[0].lower()


def test_empty_message_row_is_reported_without_aborting_batch():
    entries, errors = validate_csv_bytes(b"subject,body\n,Valid body\n,\n")
    assert errors == []
    assert entries[0]["email"] is not None
    assert entries[1]["email"] is None
    assert "subject or body" in entries[1]["errors"][0]


def test_empty_csv_and_duplicate_columns_are_reported():
    assert "parse" in validate_csv_bytes(b"")[1][0].lower()
    entries, errors = validate_csv_bytes(b"subject,body\n")
    assert entries == [] and "no email rows" in errors[0].lower()
    entries, errors = validate_csv_bytes(b"subject,body,text\nHello,first,second\n")
    assert entries == [] and "duplicate" in errors[0].lower()


def test_formula_injection_is_neutralized_in_download():
    csv_text = results_csv_bytes(pd.DataFrame({"subject": ["=2+2", "  @SUM(A1:A2)"]})).decode("utf-8-sig")
    assert "'=2+2" in csv_text
    assert "'  @SUM(A1:A2)" in csv_text


def test_csv_aliases_are_supported():
    entries, errors = validate_csv_bytes(b"From,Text,authentication_results\nperson@university.example,Hello,SPF pass\n")
    assert errors == []
    assert entries[0]["email"].sender == "person@university.example"
    assert entries[0]["email"].body == "Hello"


def test_batch_analysis_csv_download_contains_only_defanged_urls():
    entries, errors = validate_csv_bytes(
        b"subject,body\nRoutine note,Read https://portal.example/path\n,\n"
    )
    assert errors == []
    result = analyze_email(entries[0]["email"])
    output = pd.DataFrame([{
        "risk_label": result.risk_label.value,
        "subject": entries[0]["email"].subject,
        "urls": " | ".join(result.features.urls_defanged),
    }])
    exported = results_csv_bytes(output).decode("utf-8-sig")
    assert "hxxps://portal[.]example/path" in exported
    assert "https://portal.example/path" not in exported
    assert entries[1]["email"] is None
