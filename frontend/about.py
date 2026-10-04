"""About page: positioning, how it works, privacy and limits."""
from __future__ import annotations

import streamlit as st

from . import components as ui


def render() -> None:
    ui.render_brand()
    st.header("About ScamLens")
    st.write("ScamLens is an AI-powered decision-support tool. It helps people recognize suspicious communication, "
             "understand the evidence behind a warning, verify claims, and take safer actions before responding.")
    st.subheader("How it works")
    st.markdown(
        "1. **You share** a message, a screenshot or an email file.\n"
        "2. **We read it.** Screenshots are read on the server with OCR, and you can correct the text before analysis.\n"
        "3. **AI analysis** looks at intent, claims, requests, pressure, payments, links and impersonation.\n"
        "4. **Rule-based checks** keep the result consistent: urgency alone never produces a high-risk result.\n"
        "5. **You get an explanation:** red flags with quotes, what to do next, and how to verify."
    )
    st.subheader("What AI Risk Confidence means")
    st.write("It shows how confident the AI is in its assessment, based on the signals it found. "
             "It is not a verified probability that a message is fraudulent.")
    st.subheader("Privacy and safety")
    st.markdown(
        "- Links are analyzed as text and are **never opened**.\n"
        "- Screenshots are not stored. Only the extracted text and the result are saved in the history.\n"
        "- Message text is sent to the configured AI provider for analysis. Don't submit anything you aren't allowed to share.\n"
        "- All demo messages are fictional."
    )
    st.subheader("Limits")
    st.write("ScamLens is an AI-assisted risk assessment tool. It does not guarantee that a communication is "
             "fraudulent or safe. When in doubt, contact the organization using details you already trust.")
    st.subheader("If you think you've been scammed")
    st.write("Contact your bank or payment provider immediately, change affected passwords, keep screenshots and "
             "records, and report it to your local cybercrime authority or the platform where it happened.")
