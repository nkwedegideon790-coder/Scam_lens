"""History page: browse and reopen previous analyses."""
from __future__ import annotations

import streamlit as st

from . import api_client, components as ui, state

PAGE_SIZE = 8


def render() -> None:
    ui.render_brand()
    st.header("Analysis history")
    levels = st.multiselect("Filter by risk level", ui.RISK_ORDER, key="hist_levels",
                            format_func=lambda l: f"{ui.RISK_ICONS[l]} {ui.RISK_LABELS[l]}")
    page = st.session_state.setdefault("hist_page", 0)
    try:
        data = api_client.list_analyses(PAGE_SIZE, page * PAGE_SIZE, levels or None)
    except api_client.APIError as exc:
        st.error(exc.message)
        return

    total, items = data["total"], data["items"]
    if total == 0:
        st.info("No analyses yet." if not levels else "No analyses match this filter.")
        return
    st.caption(f"{total} analysis{'es' if total != 1 else ''}")
    for item in items:
        with st.container(border=True):
            ui.render_history_card(item)
            with st.expander("Original input"):
                st.text(item["preview"] + ("…" if len(item["preview"]) >= 160 else ""))
            if st.button("Open full analysis", key=f"open_{item['id']}"):
                try:
                    full = api_client.get_analysis(item["id"])
                except api_client.APIError as exc:
                    st.error(exc.message)
                else:
                    state.show_result(full, None)

    pages = max(1, -(-total // PAGE_SIZE))
    prev_col, mid, next_col = st.columns([1, 2, 1])
    if prev_col.button("Previous", disabled=page <= 0, width="stretch"):
        st.session_state["hist_page"] = page - 1
        st.rerun()
    mid.markdown(f"<div style='text-align:center;padding-top:.5rem'>Page {page + 1} of {pages}</div>", unsafe_allow_html=True)
    if next_col.button("Next", disabled=page + 1 >= pages, width="stretch"):
        st.session_state["hist_page"] = page + 1
        st.rerun()
