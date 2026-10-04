"""Shared Streamlit session helpers and page registry."""
from __future__ import annotations

import streamlit as st

PAGES: dict = {}


def go(name: str) -> None:
    st.switch_page(PAGES[name])


def show_result(result: dict, image_bytes: bytes | None = None) -> None:
    st.session_state["result"] = result
    st.session_state["result_image"] = image_bytes
    go("analyze")
