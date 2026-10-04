"""Dashboard: real statistics computed from the database."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from . import api_client, components as ui


def render() -> None:
    ui.render_brand()
    st.header("Dashboard")
    try:
        s = api_client.stats()
    except api_client.APIError as exc:
        st.error(exc.message)
        return
    if s["total_analyses"] == 0:
        st.info("No analyses yet. Analyze a message and the numbers will appear here.")
        return

    c1, c2, c3 = st.columns(3)
    c1.metric("Total analyses", s["total_analyses"])
    c2.metric("High risk", s["high_risk"])
    c3.metric("Critical", s["critical"])
    st.metric("Most common category", s["most_common_category"] or "None so far")

    st.subheader("Risk distribution")
    dist = s["risk_distribution"]
    df = pd.DataFrame({"Risk level": [ui.RISK_LABELS[l] for l in ui.RISK_ORDER],
                       "Analyses": [dist[l] for l in ui.RISK_ORDER]}).set_index("Risk level")
    st.bar_chart(df, color="#0E5A6B")
    st.dataframe(df, width="stretch")

    if s["top_categories"]:
        st.subheader("Scam categories (medium risk and above)")
        cats = pd.DataFrame(s["top_categories"]).rename(columns={"category": "Category", "count": "Analyses"}).set_index("Category")
        st.bar_chart(cats, color="#B3261E", horizontal=True)

    st.subheader("Recent analyses")
    for item in s["recent"]:
        with st.container(border=True):
            ui.render_history_card(item)
