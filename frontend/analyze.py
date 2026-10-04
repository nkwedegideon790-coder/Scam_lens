"""Analysis page: shows the current result."""
from __future__ import annotations

import streamlit as st

from . import components as ui, state


def render() -> None:
    ui.render_brand()
    result = st.session_state.get("result")
    if not result:
        st.header("Your analysis")
        st.info("Nothing analyzed yet. Paste a message, upload a screenshot or choose a file to get started.")
        if st.button("Start an analysis", type="primary"):
            state.go("home")
        return
    ui.render_result(result, st.session_state.get("result_image"))
    st.divider()
    left, right = st.columns(2)
    if left.button("Analyze another message", type="primary", width="stretch"):
        state.go("home")
    if right.button("View history", width="stretch"):
        state.go("history")
