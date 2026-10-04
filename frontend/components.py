"""Reusable UI building blocks. All user/AI text is HTML-escaped before it touches the page."""
from __future__ import annotations

import html
from datetime import datetime

import streamlit as st

from . import theme

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_ICONS = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}
RISK_LABELS = {"LOW": "LOW RISK", "MEDIUM": "MEDIUM RISK", "HIGH": "HIGH RISK", "CRITICAL": "CRITICAL RISK"}
SOURCE_LABELS = {"message": "Pasted message", "screenshot": "Screenshot", "file": "File"}


def esc(value) -> str:
    """Escape for safe inclusion in markdown-embedded HTML (also blocks LaTeX `$` and keeps line breaks)."""
    text = html.escape("" if value is None else str(value), quote=True)
    return text.replace("$", "&#36;").replace("\n", "<br>")


def html_block(markup: str) -> None:
    # One line, no blank lines or indentation: otherwise markdown turns it into a code block.
    st.markdown(" ".join(markup.split()), unsafe_allow_html=True)


def inject_css() -> None:
    st.markdown(theme.CSS, unsafe_allow_html=True)


def fmt_date(iso: str) -> str:
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").strftime("%d %b %Y, %H:%M UTC")
    except (ValueError, TypeError):
        return iso or ""


def analysis_ref(analysis_id: int) -> str:
    return f"SL-{int(analysis_id):05d}"


def render_brand() -> None:
    html_block(f'<div class="sl-brand">{theme.LOGO_SVG}<span>ScamLens</span></div>')


def render_hero() -> None:
    render_brand()
    html_block(
        '<div class="sl-hero"><h1>See the red flags before you act.</h1>'
        "<p>AI-powered analysis for suspicious messages, screenshots, and fraud attempts. "
        "ScamLens shows what looks wrong, why it matters, and what to do next.</p></div>"
    )


def risk_pill(level: str) -> str:
    return f'<span class="sl-pill {esc(level)}">{RISK_ICONS.get(level, "")} {esc(RISK_LABELS.get(level, level))}</span>'


def render_banner(result: dict) -> None:
    level = result["risk_level"]
    filled = RISK_ORDER.index(level) + 1
    segs = "".join(f'<span class="sl-seg{" on" if i < filled else ""}"></span>' for i in range(4))
    conf = int(result["confidence"])
    cached = " (from earlier analysis)" if result.get("from_cache") else ""
    html_block(f"""
    <div class="sl-banner {esc(level)}" role="region" aria-label="Security assessment: {esc(result['risk_label'])}">
      <div class="sl-meta"><span>Security assessment</span><span>{esc(analysis_ref(result['id']))}, {esc(fmt_date(result['created_at']))}{cached}</span></div>
      <div class="sl-risk"><span class="sl-risk-icon" aria-hidden="true">{esc(result['risk_icon'])}</span><span class="sl-risk-label">{esc(result['risk_label'])}</span></div>
      <div class="sl-scale" aria-hidden="true">{segs}<span>Level {filled} of 4</span></div>
      <div class="sl-assess">{esc(result['assessment_message'])}</div>
      <div class="sl-conf-row"><span class="sl-conf-label">AI Risk Confidence</span><span class="sl-conf-value">{conf}%</span></div>
      <div class="sl-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{conf}" aria-label="AI Risk Confidence"><div style="width:{conf}%"></div></div>
      <div class="sl-cat">{esc(result['scam_category'])}</div>
      <p class="sl-summary">{esc(result['summary'])}</p>
      <p class="sl-note">{esc(result['confidence_note'])}</p>
    </div>""")
    for note in result.get("risk_notes") or []:
        st.info(note, icon=":material/tune:")


def render_red_flags(flags: list[dict]) -> None:
    st.markdown("### 🚩 Red flags")
    if not flags:
        st.write("No specific red flags were identified in this message.")
        return
    for f in flags:
        found = f.get("evidence_in_message")
        tag = "" if found in (None, True) else '<span class="sl-tag">paraphrased by AI, not an exact quote</span>'
        evidence = f.get("evidence") or "No direct quote was given."
        html_block(f"""
        <div class="sl-card">
          <h4>{esc(f['indicator'])}{tag}</h4>
          <div class="sl-k">Evidence</div><blockquote class="sl-quote">{esc(evidence)}</blockquote>
          <div class="sl-k">Why it matters</div><p class="sl-why">{esc(f['explanation'])}</p>
        </div>""")


def render_list_section(title: str, items: list[str]) -> None:
    st.markdown(title)
    for item in items:
        st.markdown(f"- {item.replace('$', chr(92) + '$')}")


def render_links(result: dict) -> None:
    st.markdown("### 🔗 Links")
    links = result.get("links") or []
    if not links:
        st.write(result.get("links_message") or "No URL detected.")
        return
    st.caption("ScamLens never opens links. The text below is not clickable on purpose.")
    for link in links:
        bad = link["suspicious"]
        reasons = "".join(f"<li>{esc(r)}</li>" for r in link.get("reasons") or [])
        status = "⚠️ Suspicious characteristics" if bad else "✔️ No obvious issues"
        html_block(f"""
        <div class="sl-link {'bad' if bad else 'ok'}">
          <code>{esc(link['url'])}</code>
          <div class="sl-k">{esc(status)}</div>
          {f'<ul>{reasons}</ul>' if reasons else ''}
          <p class="sl-why">{esc(link['message'])}</p>
        </div>""")


def render_signals(signals: list[dict]) -> None:
    if not signals:
        return
    with st.expander("Automated safety checks"):
        st.caption("Simple rule-based checks run alongside the AI to keep the risk level consistent. "
                   "Supporting signals alone (such as urgency) are not treated as proof of fraud.")
        for s in signals:
            kind = "strong signal" if s["strong"] else "supporting signal"
            html_block(f'<div class="sl-hist"><strong>{esc(s["label"])}</strong><span class="sl-tag">{kind}</span>'
                       f'<div class="sl-small">{esc(s["evidence"])}</div></div>')


def render_understanding(result: dict) -> None:
    rows = []
    if result.get("intent"):
        rows.append(("What the sender seems to want", result["intent"]))
    if result.get("sender_claims"):
        rows.append(("Who the sender claims to be", "; ".join(result["sender_claims"])))
    if result.get("requests_made"):
        rows.append(("What you are asked to do", "; ".join(result["requests_made"])))
    if result.get("language"):
        rows.append(("Language", result["language"]))
    if not rows:
        return
    with st.expander("What this message is trying to do"):
        for k, v in rows:
            html_block(f'<div class="sl-hist"><div class="sl-k">{esc(k)}</div>{esc(v)}</div>')


def render_extracted(result: dict, image_bytes: bytes | None = None) -> None:
    st.markdown("### 📋 Extracted content")
    st.caption(f"Source: {SOURCE_LABELS.get(result['input_type'], result['input_type'])}")
    if image_bytes:
        left, right = st.columns([1, 1.4])
        with left:
            st.image(image_bytes, caption="Screenshot preview")
        with right:
            html_block(f'<div class="sl-text">{esc(result["analyzed_text"])}</div>')
    else:
        html_block(f'<div class="sl-text">{esc(result["analyzed_text"])}</div>')
        if result["input_type"] == "screenshot":
            st.caption("Screenshots are not stored, only the extracted text.")
    if result["input_type"] == "screenshot" and result.get("original_text") and result["original_text"] != result["analyzed_text"]:
        with st.expander("Raw OCR output before your edits"):
            html_block(f'<div class="sl-text">{esc(result["original_text"])}</div>')


def render_result(result: dict, image_bytes: bytes | None = None) -> None:
    render_banner(result)
    render_red_flags(result.get("red_flags") or [])
    render_list_section("### 🛡 Recommended actions", result["recommended_actions"])
    render_list_section("### 🔎 Verify before acting", result["verification_steps"])
    render_links(result)
    render_signals(result.get("signals") or [])
    render_understanding(result)
    render_extracted(result, image_bytes)
    html_block(f'<div class="sl-disclaimer">{esc(result["disclaimer"])}</div>')
    if result.get("model"):
        st.caption(f"Analyzed with {result['model']}")


def render_history_card(item: dict) -> None:
    html_block(f"""
    <div class="sl-hist">{risk_pill(item['risk_level'])}
      <strong style="margin-left:.4rem">{esc(item['scam_category'])}</strong>
      <div class="sl-small">{esc(analysis_ref(item['id']))}, {esc(fmt_date(item['created_at']))}, {esc(SOURCE_LABELS.get(item['input_type'], item['input_type']))}, AI Risk Confidence {int(item['confidence'])}%</div>
      <div>{esc(item['summary'])}</div>
    </div>""")
