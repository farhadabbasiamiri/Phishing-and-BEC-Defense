import glob
import json
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from phishscope.agent import investigate, llm_explanation, ollama_models, template_explanation  # noqa: E402
from phishscope.analysis import check_url, defang, parse_raw  # noqa: E402

S = lambda n: open(glob.glob(f"samples/{n}*")[0]).read()


def test_credential_phish_is_phishing():
    assert investigate(S("01"))["label"] == "Phishing"


def test_bec_without_links_is_caught():
    r = investigate(S("02"))
    assert r["label"] == "Phishing" and r["urls"] == []


def test_legit_newsletter_is_benign():
    assert investigate(S("04"))["label"] == "Benign"


def test_urgent_but_legit_it_notice_not_phishing():
    assert investigate(S("05"))["label"] != "Phishing"


def test_prompt_injection_is_flagged_not_obeyed():
    r = investigate(S("06"))
    assert r["label"] == "Phishing"
    assert any(e["indicator"] == "injection" for e in r["evidence"])


def test_urls_are_always_defanged():
    r = investigate(S("01"))
    assert all("hxxp" in u["url"] and "[.]" in u["url"] for u in r["urls"])
    assert "http://" not in r["summary"] and "https://" not in r["user_guidance"]


def test_lookalike_and_mismatch_detection():
    assert any("Lookalike" in i for i in check_url(None, "hxxps://paypa1-login[.]xyz/x")["issues"])
    assert any("Link text" in i for i in check_url("https://www.amazon.ca", "hxxps://evil-site[.]top/x")["issues"])


def test_sensitive_actions_require_approval():
    acts = investigate(S("01"))["proposed_actions"]
    assert any(a["requires_approval"] for a in acts if "Block" in a["action"] or "quarantine" in a["action"])


def test_body_only_paste_works():
    assert parse_raw("Hello, please verify your account")["body"].startswith("Hello")


def test_llm_failure_falls_back_to_template():
    r = investigate(S("01"), use_llm=True, llm_model="does-not-exist")  # no Ollama in CI
    assert r["summary"] and r["explanation_source"] == "template"


def test_ollama_models_lists_installed_tags():
    response = type("Response", (), {
        "__enter__": lambda self: self,
        "__exit__": lambda self, *args: None,
        "read": lambda self: json.dumps({"models": [{"name": "qwen3.5:4b"}]}).encode(),
    })()
    with patch("phishscope.agent.urllib.request.urlopen", return_value=response):
        assert ollama_models("http://localhost:11434") == (["qwen3.5:4b"], "")
