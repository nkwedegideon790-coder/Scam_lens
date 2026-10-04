"""ScamLens: Streamlit entry point. Run with: streamlit run app.py"""
import streamlit as st

st.set_page_config(page_title="ScamLens", page_icon="🔎", layout="centered", initial_sidebar_state="auto")

from frontend import about, analyze, api_client, components as ui, dashboard, history, home, state  # noqa: E402

ui.inject_css()

state.PAGES.update(
    home=st.Page(home.render, title="Home", icon=":material/home:", url_path="home", default=True),
    analyze=st.Page(analyze.render, title="Analyze", icon=":material/policy:", url_path="analyze"),
    history=st.Page(history.render, title="History", icon=":material/history:", url_path="history"),
    dashboard=st.Page(dashboard.render, title="Dashboard", icon=":material/monitoring:", url_path="dashboard"),
    about=st.Page(about.render, title="About", icon=":material/info:", url_path="about"),
)


@st.cache_data(ttl=15, show_spinner=False)
def _backend_status():
    try:
        return api_client.health(), None
    except api_client.APIError as exc:
        return None, exc.message


status, problem = _backend_status()
if problem:
    st.error(problem)
elif status and not status.get("ai_configured"):
    st.warning("The AI service is not configured on the backend yet (no API key). Analysis is unavailable until it is.")
elif status and not status.get("ocr_available"):
    st.info("Screenshot reading is unavailable on this server. You can still paste the message text.")

st.navigation(list(state.PAGES.values())).run()
