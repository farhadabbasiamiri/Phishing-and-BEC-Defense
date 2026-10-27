# Short classroom demonstration

1. Run `streamlit run app.py` and open the loopback URL in the browser.
2. On **Single email**, analyze the benign sample. Point out that a low score is not a safety guarantee.
3. Load the suspicious sample. Review the Reply-To mismatch, urgency, credential request, defanged URL, and user-supplied authentication failure indicators.
4. Explain that the URL is text-only and was not visited; the attachment name is metadata and no file was opened.
5. On **CSV batch**, upload a UTF-8 CSV with `subject,body` columns and one empty-message row. Compare its row-level validation result and download output.
6. Show the separate heuristic score and ML probability, the model fallback when no artifact exists, and the synthetic-only caveat in **Model & evaluation**.

Remind the audience that the project is an educational triage aid and its labels require human review.