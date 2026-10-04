"""Home: brand header plus the three input modes (Message, Screenshot, File)."""
from __future__ import annotations

import streamlit as st

from . import api_client, components as ui, state
from .demo_data import DEMO_NOTICE, DEMOS

NO_DEMO = "Choose an example…"
MAX_IMAGE_MB = 8


def _load_demo() -> None:
    choice = st.session_state.get("demo_choice")
    if choice in DEMOS:
        st.session_state["msg_text"] = DEMOS[choice]


def _run(action, image_bytes=None):
    try:
        with st.spinner("Analyzing for red flags…"):
            result = action()
    except api_client.APIError as exc:
        st.error(exc.message)
        return
    state.show_result(result, image_bytes)


def _message_tab() -> None:
    st.selectbox("Try a fictional example", [NO_DEMO, *DEMOS], key="demo_choice", on_change=_load_demo,
                 help="Loads a made-up message so you can see how ScamLens works.")
    st.markdown(f'<div class="sl-fictional">{ui.esc(DEMO_NOTICE)}</div>', unsafe_allow_html=True)
    st.text_area("Suspicious message", key="msg_text", height=200, placeholder="Paste a suspicious message here...")
    if st.button("Analyze Message", type="primary", width="stretch", key="btn_msg"):
        text = (st.session_state.get("msg_text") or "").strip()
        if not text:
            st.warning("Paste a message first.")
        else:
            _run(lambda: api_client.analyze_text(text, "message"))


def _screenshot_tab() -> None:
    upload = st.file_uploader("Screenshot of the message", type=["png", "jpg", "jpeg", "webp"], key="shot_upload",
                              help=f"PNG, JPG or WebP, up to {MAX_IMAGE_MB} MB.")
    if upload is None:
        st.session_state.pop("ocr", None)
        st.caption("Upload a screenshot, then review the text we read from it before analysis.")
        return
    data = upload.getvalue()
    if st.session_state.get("ocr", {}).get("file_id") != upload.file_id:
        st.session_state.pop("ocr", None)
    st.image(data, caption="Screenshot preview")

    if st.button("Extract & review text", type="primary", width="stretch", key="btn_ocr"):
        try:
            with st.spinner("Reading the screenshot…"):
                out = api_client.ocr(data, upload.name, upload.type or "image/png")
        except api_client.APIError as exc:
            st.session_state.pop("ocr", None)
            st.error(exc.message)
        else:
            st.session_state["ocr"] = {"file_id": upload.file_id, "raw": out["text"], "warnings": out["warnings"]}
            st.session_state["ocr_text"] = out["text"]

    ocr = st.session_state.get("ocr")
    if ocr:
        for w in ocr["warnings"]:
            st.warning(w)
        st.text_area("Extracted message (edit to fix any mistakes)", key="ocr_text", height=220)
        if st.button("Analyze this text", type="primary", width="stretch", key="btn_ocr_analyze"):
            text = (st.session_state.get("ocr_text") or "").strip()
            if not text:
                st.warning("The extracted text is empty. Add the message text or upload a clearer screenshot.")
            else:
                _run(lambda: api_client.analyze_text(text, "screenshot", ocr["raw"]), data)


def _file_tab() -> None:
    upload = st.file_uploader("Text or email file", type=["txt", "eml"], key="file_upload",
                              help="Plain text (.txt) or email (.eml), up to 1 MB. Attachments are never opened.")
    if st.button("Analyze File", type="primary", width="stretch", key="btn_file"):
        if upload is None:
            st.warning("Choose a .txt or .eml file first.")
        else:
            _run(lambda: api_client.analyze_file(upload.getvalue(), upload.name, upload.type or "text/plain"))


def render() -> None:
    ui.render_hero()
    tab_msg, tab_shot, tab_file = st.tabs(["Message", "Screenshot", "File"])
    with tab_msg:
        _message_tab()
    with tab_shot:
        _screenshot_tab()
    with tab_file:
        _file_tab()
