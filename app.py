"""PhishScope dashboard. Run: streamlit run app.py"""
import csv
import glob
import os
from datetime import datetime

import pandas as pd
import streamlit as st

from phishscope.agent import investigate, ollama_models

st.set_page_config(page_title="PhishScope", page_icon="🛡️", layout="wide")
os.makedirs("results", exist_ok=True)
AUDIT = "results/audit_log.csv"
COLORS = {"Phishing": "🔴", "Suspicious": "🟠", "Benign": "🟢"}


@st.cache_data(ttl=30)
def _cached_ollama_models():
    return ollama_models()


st.title("🛡️ PhishScope: safe phishing triage")
st.caption("Defensive use only. Links are analysed offline as text and always shown defanged; nothing is opened or fetched.")

with st.sidebar:
    st.header("Settings")
    use_llm = st.toggle("Use local LLM for explanation (Ollama)", value=False)
    if use_llm:
        installed_models, model_error = _cached_ollama_models()
        if installed_models:
            preferred_model = "qwen2.5:3b" if "qwen2.5:3b" in installed_models else installed_models[0]
            llm_model = st.selectbox(
                "Ollama model", installed_models, index=installed_models.index(preferred_model),
                key="ollama_model_select",
            )
        else:
            llm_model = st.text_input("Ollama model", "qwen2.5:3b", key="ollama_model_custom")
            st.caption(model_error or "Could not list Ollama models; enter a model name manually.")
    else:
        llm_model = st.text_input("Ollama model", "qwen2.5:3b", disabled=True, key="ollama_model_disabled")
    st.caption("The verdict always comes from the scorer. The LLM only writes the explanation; it falls back to a template if Ollama is not running.")
    analyst = st.text_input("Analyst name (for audit log)", "analyst1")


def log_action(email_id, action, decision):
    new = not os.path.exists(AUDIT)
    with open(AUDIT, "a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["time", "analyst", "email_id", "action", "decision"])
        w.writerow([datetime.now().isoformat(timespec="seconds"), analyst, email_id, action, decision])


def show_report(r, key):
    c1, c2, c3 = st.columns(3)
    c1.metric("Verdict", f"{COLORS[r['label']]} {r['label']}")
    c2.metric("Risk score", f"{r['score']}/100")
    c3.metric("ML probability", "n/a (run evaluate.py)" if r["ml_probability"] is None else f"{r['ml_probability']:.2f}")
    st.subheader("Summary")
    st.write(r["summary"])
    source = r.get("explanation_source", "template")
    if source.startswith("LLM (") and source.endswith(")"):
        st.success(f"Explanation source: Ollama ({source[5:-1]})")
    else:
        st.info("Explanation source: built-in template")
    if r.get("llm_error"):
        st.warning("Local LLM not used: " + r["llm_error"])
    st.subheader("Guidance for the recipient")
    st.info(r["user_guidance"])
    left, right = st.columns(2)
    with left:
        st.subheader("Evidence")
        ev = [e for e in r["evidence"] if e["indicator"] != "url"]
        st.dataframe(pd.DataFrame(ev)[["detail", "weight"]] if ev else pd.DataFrame({"detail": ["none"]}),
                     use_container_width=True, hide_index=True)
    with right:
        st.subheader("URLs (defanged)")
        if r["urls"]:
            st.dataframe(pd.DataFrame([{"url": u["url"], "domain": u["domain"], "issues": "; ".join(u["issues"]) or "none"} for u in r["urls"]]),
                         use_container_width=True, hide_index=True)
        else:
            st.write("No URLs found.")
    st.subheader("Proposed actions (human approval required for sensitive ones)")
    for i, a in enumerate(r["proposed_actions"]):
        cols = st.columns([5, 1, 1])
        cols[0].write(("🔒 " if a["requires_approval"] else "✅ ") + a["action"])
        if a["requires_approval"]:
            if cols[1].button("Approve", key=f"{key}-a{i}"):
                log_action(r["id"], a["action"], "approved")
                st.success("Approved and logged (simulated; no real action taken).")
            if cols[2].button("Reject", key=f"{key}-r{i}"):
                log_action(r["id"], a["action"], "rejected")
                st.warning("Rejected and logged.")
    with st.expander("Agent trace"):
        for t in r["trace"]:
            st.write("• " + t)


tab1, tab2, tab3 = st.tabs(["Paste an email", "Upload CSV", "Audit log"])

with tab1:
    samples = {os.path.basename(p): p for p in sorted(glob.glob("samples/*"))}
    choice = st.selectbox("Load a demo sample", ["(none)"] + list(samples))
    default = open(samples[choice]).read() if choice != "(none)" else ""
    text = st.text_area("Paste raw email (headers + body, or just the body). Defang any URLs as hxxp://example[.]com",
                        value=default, height=260, key=f"paste-{choice}")
    if st.button("Investigate", type="primary") and text.strip():
        st.session_state["report"] = investigate(text, use_llm, llm_model)
    if "report" in st.session_state:
        show_report(st.session_state["report"], "single")

with tab2:
    st.write("CSV columns: `id, subject, from, reply_to, return_path, spf, dkim, dmarc, attachments, body` (a `label` column is optional).")
    up = st.file_uploader("Upload CSV", type="csv")
    if up is not None:
        df = pd.read_csv(up).fillna("")
        reports = [investigate(row, use_llm=False) for row in df.to_dict("records")]
        out = pd.DataFrame([{"id": r["id"], "label": r["label"], "score": r["score"], "subject": r["subject"],
                             "top_evidence": "; ".join(e["detail"] for e in r["evidence"] if e["weight"] > 0)[:160]} for r in reports])
        out = out.sort_values("score", ascending=False).reset_index(drop=True)
        st.dataframe(out, use_container_width=True, hide_index=True)
        st.download_button("Download results CSV", out.to_csv(index=False), "phishscope_results.csv")
        pick = st.selectbox("Open a full report", out["id"].tolist())
        show_report(next(r for r in reports if r["id"] == pick), "batch")

with tab3:
    if os.path.exists(AUDIT):
        st.dataframe(pd.read_csv(AUDIT), use_container_width=True, hide_index=True)
    else:
        st.write("No approvals recorded yet.")
