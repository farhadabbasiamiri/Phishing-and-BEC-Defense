"""Offline-first, explainable phishing-email triage."""

from .agent import analyze_email
from .schemas import EmailRecord, AnalysisResult, RiskLabel

__all__ = ["analyze_email", "EmailRecord", "AnalysisResult", "RiskLabel"]
