"""CSV ingestion and safe result serialization with per-row validation."""

from io import StringIO
import re
from typing import Any

import pandas as pd
from pydantic import ValidationError

from .schemas import EmailRecord
from .safety import csv_safe_frame

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5_000
ALIASES = {
    "sender": ("sender", "from", "from_address"),
    "reply_to": ("reply_to", "reply-to"),
    "subject": ("subject",),
    "body": ("body", "text", "email_body"),
    "auth_results": ("auth_results", "authentication", "authentication_results"),
    "attachment_metadata": ("attachment_metadata", "attachments", "attachment"),
    "headers": ("headers", "raw_headers", "email_headers"),
}


def _normalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    renamed = {}
    for column in frame.columns:
        normalized = re.sub(r"[\s-]+", "_", str(column).strip().lower())
        duplicate = re.fullmatch(r"(.+)\.\d+", normalized)
        if duplicate:
            normalized = duplicate.group(1)
        target = next((key for key, values in ALIASES.items() if normalized in {
            re.sub(r"[\s-]+", "_", value) for value in values
        }), None)
        renamed[column] = target or normalized
    return frame.rename(columns=renamed)


def validate_csv_bytes(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse bounded CSV input and return safe, per-row results plus file errors."""
    if len(data) > MAX_UPLOAD_BYTES:
        return [], [f"CSV exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit."]
    try:
        frame = pd.read_csv(StringIO(data.decode("utf-8-sig")), dtype=str, keep_default_na=False)
    except (UnicodeDecodeError, pd.errors.ParserError, ValueError) as exc:
        return [], [f"Could not parse CSV: {type(exc).__name__}: {exc}"]
    frame = _normalize_columns(frame)
    if frame.columns.duplicated().any():
        return [], ["CSV contains duplicate columns or aliases that map to the same field."]
    if not {"subject", "body"}.intersection(frame.columns):
        return [], ["CSV must include at least one message column: 'subject' or 'body'."]
    if len(frame) > MAX_ROWS:
        return [], [f"CSV exceeds the {MAX_ROWS:,}-row processing limit."]
    if frame.empty:
        return [], ["CSV has column headers but contains no email rows."]

    output = []
    for position, (_, row) in enumerate(frame.iterrows(), start=2):
        values = {field: str(row.get(field, "") or "").strip() for field in ALIASES}
        errors: list[str] = []
        try:
            email = EmailRecord.model_validate(values)
        except ValidationError as exc:
            errors = [
                f"{'.'.join(str(part) for part in issue['loc'])}: {issue['msg']}"
                for issue in exc.errors()
            ]
            email = None
        output.append({"row_number": position, "email": email, "errors": errors})
    return output, []


def results_csv_bytes(frame: pd.DataFrame) -> bytes:
    """Serialize results safely for spreadsheet consumers."""
    return csv_safe_frame(frame).to_csv(index=False).encode("utf-8-sig")
