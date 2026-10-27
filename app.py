"""Streamlit dashboard for safe, offline-first email triage."""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.phishing_agent.agent import analyze_email
from src.phishing_agent.csv_io import results_csv_bytes, validate_csv_bytes
from src.phishing_agent.parser import defang_url, extract_urls
from src.phishing_agent.schemas import EmailRecord

DATASET_PATH = ROOT / "data" / "dummy_emails.csv"
BENIGN_SAMPLE = {
    "sender": "riley@university.example", "reply_to": "", "subject": "Project meeting notes",
    "body": "Hi Jordan, here are the notes from our project meeting. Please review when convenient.",
    "auth_results": "SPF pass; DKIM pass; DMARC pass", "attachment_metadata": "",
}
SUSPICIOUS_SAMPLE = {
    "sender": "notice@account-alert.example", "reply_to": "reply@unrelated-mail.example",
    "subject": "Urgent: verify your account",
    "body": "Your account will be suspended today. Verify your password immediately at hxxp://account-check.example/verify",
    "auth_results": "SPF fail; DKIM fail; DMARC fail", "attachment_metadata": "account.html",
}


def safe_display_text(value: object) -> str:
    text = str(value or "")
    for url in extract_urls(text):
        text = text.replace(url, defang_url(url))
    return text


@st.cache_data
def load_dataset() -> pd.DataFrame:
    return pd.read_csv(DATASET_PATH, dtype=str, keep_default_na=False)


def show_result(result) -> None:
    first, second, third = st.columns(3)
    first.metric("Risk label", result.risk_label.value)
    second.metric("Decision score", f"{result.risk_score}/100")
    third.metric("Heuristic score", f"{result.heuristic_score}/100")
    if result.ml_probability is not None:
        st.caption(f"Separate ML phishing-class probability: {result.ml_probability:.1%}. This is a model estimate, not a verified verdict.")
    st.progress(result.risk_score)
    st.subheader("Analyst summary")
    st.text(result.summary)
    st.subheader("Evidence")
    if result.evidence:
        for evidence in result.evidence:
            st.text(f"• {safe_display_text(evidence)}")
    else:
        st.text("No strong indicators were found in the selected analysis mode.")
    if result.features.sender_domain or result.features.reply_to_domain:
        st.text(f"Sender domain: {result.features.sender_domain or 'not provided'}")
        st.text(f"Reply-To domain: {result.features.reply_to_domain or 'not provided'}")
        st.text(f"Sender / Reply-To mismatch: {'Yes' if result.features.domain_mismatch else 'No / unavailable'}")
    st.subheader("Recommended actions")
    for action in result.recommended_actions:
        st.text(f"• {action}")
    if result.features.urls_defanged:
        st.subheader("Extracted URLs (defanged; not visited)")
        for url in result.features.urls_defanged:
            st.code(url, language=None)
    with st.expander("Uncertainty, limitations, and structured result"):
        for item in result.uncertainty:
            st.text(f"• {item}")
        for item in result.limitations:
            st.text(f"• {item}")
        st.json(result.to_dict())


st.set_page_config(page_title="Group 2A | Phishing Email Investigation Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ Group 2A: Phishing Email Investigation Agent")
st.caption("Offline-first, evidence-led email triage. Email text is untrusted data; links and attachments are never opened.")
st.warning("Educational triage tool only — not a production security control. Always use human review.")

with st.sidebar:
    st.header("Analysis settings")
    mode = st.selectbox("Decision mode", ["rules", "combined", "ml"], help="Rules: transparent baseline. Combined: 70% rules + 30% ML probability. ML: model probability only. Missing model falls back to rules.")
    st.caption("Heuristic scores are not probabilities. Supplied SPF/DKIM/DMARC results are not verified.")

single_tab, batch_tab, data_tab, model_tab = st.tabs(
    ["Single email", "CSV batch", "Dataset exploration", "Model & evaluation"]
)

with single_tab:
    st.subheader("Analyze one email")
    left, right = st.columns(2)
    with left:
        if st.button("Load benign example"):
            st.session_state["single_sample"] = BENIGN_SAMPLE.copy()
    with right:
        if st.button("Load suspicious example"):
            st.session_state["single_sample"] = SUSPICIOUS_SAMPLE.copy()
    sample = st.session_state.get("single_sample", BENIGN_SAMPLE)
    with st.form("single_email_form"):
        sender = st.text_input("From", value=sample["sender"])
        reply_to = st.text_input("Reply-To (optional)", value=sample["reply_to"])
        subject = st.text_input("Subject", value=sample["subject"])
        body = st.text_area("Body", value=sample["body"], height=180)
        auth_results = st.text_input("Authentication results (user-supplied)", value=sample["auth_results"])
        attachment_metadata = st.text_input("Attachment metadata only (never upload/open a file)", value=sample["attachment_metadata"])
        headers = st.text_area("Optional raw RFC-style headers", placeholder="From: sender@university.example\nSubject: Example subject", height=90)
        submitted = st.form_submit_button("Analyze email", type="primary")
    if submitted:
        try:
            email = EmailRecord.model_validate({
                "sender": sender, "reply_to": reply_to, "subject": subject, "body": body,
                "auth_results": auth_results, "attachment_metadata": attachment_metadata, "headers": headers,
            })
        except ValidationError as exc:
            st.error(f"Please correct the email input: {safe_display_text(str(exc))}")
        else:
            try:
                show_result(analyze_email(email, mode=mode))
            except ValueError as exc:
                st.error(f"Could not analyze this email: {exc}")

with batch_tab:
    st.subheader("Analyze a CSV batch")
    st.write("Required: at least one `subject` or `body` column. Optional: `sender`, `reply_to`, `auth_results`, `attachment_metadata`, and `headers`. Alternative headers include `from`, `text`, and `authentication_results`.")
    uploaded = st.file_uploader("Choose a UTF-8 CSV (maximum 5 MB and 5,000 rows)", type=["csv"])
    if uploaded is not None:
        entries, file_errors = validate_csv_bytes(uploaded.getvalue())
        for error in file_errors:
            st.error(error)
        if entries:
            output_rows = []
            for entry in entries:
                email = entry["email"]
                if email is None:
                    output_rows.append({
                        "row_number": entry["row_number"], "risk_label": "Invalid",
                        "validation_errors": " | ".join(entry["errors"]),
                    })
                    continue
                result = analyze_email(email, mode=mode)
                output_rows.append({
                    "row_number": entry["row_number"],
                    "risk_label": result.risk_label.value,
                    "risk_score": result.risk_score,
                    "heuristic_score": result.heuristic_score,
                    "ml_probability": result.ml_probability,
                    "sender": safe_display_text(email.sender),
                    "subject": safe_display_text(email.subject),
                    "urls_defanged": " | ".join(result.features.urls_defanged),
                    "evidence": " | ".join(result.evidence),
                    "recommended_actions": " | ".join(result.recommended_actions),
                    "uncertainty": " | ".join(result.uncertainty),
                    "validation_errors": "",
                })
            results = pd.DataFrame(output_rows)
            valid = results[results["risk_label"].isin(["Low", "Medium", "High"])]
            if not valid.empty:
                low, medium, high = st.columns(3)
                counts = valid["risk_label"].value_counts()
                low.metric("Low", int(counts.get("Low", 0)))
                medium.metric("Medium", int(counts.get("Medium", 0)))
                high.metric("High", int(counts.get("High", 0)))
                st.bar_chart(counts.reindex(["Low", "Medium", "High"], fill_value=0))
                risk_filter = st.multiselect("Filter by risk", ["Low", "Medium", "High"], default=["Low", "Medium", "High"])
                search = st.text_input("Search sender, subject, evidence, or validation issues").casefold()
                filtered = results[results["risk_label"].isin(risk_filter)]
                if search:
                    filtered = filtered[filtered.astype(str).apply(lambda row: search in " ".join(row).casefold(), axis=1)]
                st.dataframe(filtered, use_container_width=True, hide_index=True)
            else:
                st.info("No valid email rows were available to analyze.")
                st.dataframe(results, use_container_width=True, hide_index=True)
            st.download_button(
                "Download analysis results CSV",
                results_csv_bytes(results),
                file_name="email_analysis_results.csv",
                mime="text/csv",
            )

with data_tab:
    st.subheader("Synthetic dataset")
    try:
        dataset = load_dataset()
    except FileNotFoundError:
        st.error("Synthetic dataset is missing. Run `python scripts/generate_data.py`.")
    else:
        st.write(f"{len(dataset)} fictional examples; balanced labels.")
        st.bar_chart(dataset["label"].value_counts())
        display = dataset.head(30).copy()
        for column in ("subject", "body"):
            display[column] = display[column].map(safe_display_text)
        st.dataframe(display, use_container_width=True, hide_index=True)
        export = dataset.copy()
        for column in ("subject", "body"):
            export[column] = export[column].map(safe_display_text)
        st.download_button("Download safe, defanged sample dataset", results_csv_bytes(export), "dummy_emails.csv", "text/csv")

with model_tab:
    st.subheader("Decision modes")
    st.write("Rules computes the documented 0–100 heuristic. Combined computes round(0.70 × heuristic + 0.30 × ML phishing probability × 100). ML uses the model probability × 100. Risk labels use Low < 30, Medium 30–59, and High ≥ 60. An unavailable model falls back to rules and is identified in the result.")
    st.write("The heuristic score, final decision score, and ML probability are separate fields; a heuristic score is never presented as a probability.")
    st.subheader("Optional local model")
    artifact = ROOT / "models" / "phishing_model.joblib"
    st.write(f"Model artifact: {'available' if artifact.is_file() else 'not trained (rules-only fallback enabled)'}")
    st.code("python scripts/train_model.py\npython scripts/evaluate_model.py", language="powershell")
    st.subheader("Evaluation")
    st.write("Evaluation uses a reproducible stratified 75/25 split (seed 42); the vectorizer is fitted only on training rows. Run the command above to generate actual precision, recall, F1, confusion-matrix, and per-class metrics.")
    st.info("Synthetic holdout metrics are illustrative only. Repeated template language, simplified labels, and reserved domains do not represent real-world performance.")
    st.subheader("Safe operation")
    st.write("Email content is never interpreted as instructions. This deterministic agent has no tools, shell access, URL access, or external LLM/API integration. No URL is fetched or resolved and attachment bytes are never accepted or executed.")
