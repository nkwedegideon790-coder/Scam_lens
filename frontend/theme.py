"""Global CSS. Colour is never the only carrier of meaning: every risk state also has an icon, a text label and a level scale."""

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Serif:wght@500;600&display=swap');
:root{
  --sl-ink:#14202B; --sl-muted:#4A5866; --sl-line:#CBD4DD; --sl-paper:#FFFFFF; --sl-bg:#F4F6F8; --sl-brand:#0E5A6B;
  --low-fg:#0F5C34; --low-bg:#E4F3EA; --low-bd:#1B7F4B;
  --med-fg:#6B4200; --med-bg:#FFF1CC; --med-bd:#B77900;
  --high-fg:#9A1216; --high-bg:#FDE8E7; --high-bd:#B3261E;
  --crit-fg:#FFFFFF; --crit-bg:#6A0A13; --crit-bd:#3E050B;
}
html, body, [class*="css"], .stApp { font-family:'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', sans-serif; color:var(--sl-ink); }
.block-container{ max-width:880px; padding-top:2rem; padding-bottom:4rem; }
h1,h2,h3{ letter-spacing:-0.01em; }
.sl-brand{ display:flex; align-items:center; gap:.6rem; color:var(--sl-brand); font-weight:600; font-size:1.05rem; }
.sl-hero h1{ font-family:'IBM Plex Serif', Georgia, serif; font-size:2.4rem; line-height:1.15; margin:.6rem 0 .5rem; font-weight:600; }
.sl-hero p{ color:var(--sl-muted); font-size:1.08rem; max-width:34rem; margin:0 0 1.2rem; line-height:1.5; }

.sl-banner{ border:2px solid var(--sl-line); border-radius:12px; padding:1.25rem 1.3rem; margin:.5rem 0 1.2rem; background:var(--sl-paper); }
.sl-banner.LOW{ background:var(--low-bg); border-color:var(--low-bd); color:var(--low-fg); }
.sl-banner.MEDIUM{ background:var(--med-bg); border-color:var(--med-bd); color:var(--med-fg); border-style:dashed; }
.sl-banner.HIGH{ background:var(--high-bg); border-color:var(--high-bd); color:var(--high-fg); }
.sl-banner.CRITICAL{ background:var(--crit-bg); border-color:var(--crit-bd); color:var(--crit-fg); }
.sl-meta{ display:flex; flex-wrap:wrap; justify-content:space-between; gap:.25rem 1rem; font-size:.85rem; opacity:.9; }
.sl-risk{ display:flex; align-items:center; gap:.6rem; margin:.5rem 0 .25rem; }
.sl-risk-icon{ font-size:2rem; line-height:1; }
.sl-risk-label{ font-family:'IBM Plex Serif', Georgia, serif; font-size:2rem; font-weight:600; line-height:1.1; }
.sl-scale{ display:flex; align-items:center; gap:.3rem; font-size:.85rem; margin-bottom:.7rem; }
.sl-seg{ width:2.2rem; height:.55rem; border-radius:2px; border:1.5px solid currentColor; opacity:.9; }
.sl-seg.on{ background:currentColor; }
.sl-assess{ font-size:1.05rem; font-weight:500; margin:.2rem 0 .9rem; line-height:1.45; }
.sl-conf-row{ display:flex; align-items:baseline; gap:.6rem; flex-wrap:wrap; }
.sl-conf-label{ font-size:.9rem; font-weight:600; }
.sl-conf-value{ font-size:1.6rem; font-weight:600; }
.sl-bar{ height:.6rem; border:1.5px solid currentColor; border-radius:3px; margin:.3rem 0 .4rem; overflow:hidden; }
.sl-bar > div{ height:100%; background:currentColor; }
.sl-cat{ display:inline-block; border:1.5px solid currentColor; border-radius:999px; padding:.15rem .75rem; font-weight:600; font-size:.95rem; margin:.6rem 0 .5rem; }
.sl-summary{ margin:.2rem 0 .6rem; line-height:1.5; font-size:1rem; }
.sl-note{ font-size:.82rem; opacity:.92; line-height:1.4; margin:0; }

.sl-card{ background:var(--sl-paper); border:1px solid var(--sl-line); border-left:5px solid var(--sl-brand); border-radius:8px; padding:.9rem 1rem; margin:.6rem 0; }
.sl-card h4{ margin:0 0 .5rem; font-size:1.05rem; }
.sl-k{ font-size:.82rem; font-weight:600; color:var(--sl-muted); margin:.5rem 0 .15rem; }
.sl-quote{ border-left:3px solid var(--sl-line); padding:.2rem .7rem; margin:0; font-style:italic; background:#F8FAFB; border-radius:0 4px 4px 0; overflow-wrap:anywhere; }
.sl-why{ margin:0; line-height:1.5; }
.sl-tag{ display:inline-block; font-size:.75rem; font-weight:600; border:1px solid var(--sl-line); border-radius:4px; padding:0 .4rem; margin-left:.4rem; color:var(--sl-muted); background:#fff; }
.sl-link{ background:var(--sl-paper); border:1px solid var(--sl-line); border-radius:8px; padding:.8rem 1rem; margin:.5rem 0; }
.sl-link code{ display:block; overflow-wrap:anywhere; white-space:normal; font-size:.9rem; padding:.3rem .5rem; background:#EEF2F5; border-radius:4px; color:var(--sl-ink); }
.sl-link.bad{ border-left:5px solid var(--high-bd); } .sl-link.ok{ border-left:5px solid var(--low-bd); }
.sl-link ul{ margin:.4rem 0 .2rem 1.1rem; padding:0; }
.sl-text{ white-space:pre-wrap; overflow-wrap:anywhere; background:var(--sl-paper); border:1px solid var(--sl-line); border-radius:8px; padding:.8rem 1rem; line-height:1.5; max-height:22rem; overflow:auto; }
.sl-pill{ display:inline-block; font-weight:600; font-size:.85rem; border:1.5px solid currentColor; border-radius:4px; padding:0 .45rem; }
.sl-pill.LOW{ color:var(--low-fg); background:var(--low-bg);} .sl-pill.MEDIUM{ color:var(--med-fg); background:var(--med-bg); border-style:dashed;}
.sl-pill.HIGH{ color:var(--high-fg); background:var(--high-bg);} .sl-pill.CRITICAL{ color:var(--crit-fg); background:var(--crit-bg);}
.sl-hist{ line-height:1.45; } .sl-hist .sl-small{ color:var(--sl-muted); font-size:.85rem; }
.sl-disclaimer{ font-size:.85rem; color:var(--sl-muted); border-top:1px solid var(--sl-line); padding-top:.8rem; margin-top:1.5rem; line-height:1.45; }
.sl-fictional{ font-size:.88rem; color:var(--sl-muted); }
.stButton > button[kind="primary"]{ min-height:2.9rem; font-weight:600; }
:focus-visible{ outline:3px solid #1A73E8 !important; outline-offset:2px; }
@media (max-width:640px){ .sl-hero h1{ font-size:1.8rem; } .sl-risk-label{ font-size:1.6rem; } .block-container{ padding-left:1rem; padding-right:1rem; } }
@media (prefers-reduced-motion:reduce){ *{ animation:none !important; transition:none !important; } }
</style>
"""

LOGO_SVG = (
    '<svg width="30" height="30" viewBox="0 0 32 32" role="img" aria-label="ScamLens logo" xmlns="http://www.w3.org/2000/svg">'
    '<circle cx="13.5" cy="13.5" r="9" fill="none" stroke="#0E5A6B" stroke-width="3"/>'
    '<path d="M20.5 20.5 L28 28" stroke="#0E5A6B" stroke-width="3.5" stroke-linecap="round"/>'
    '<path d="M10.5 9.5 V18.5 M10.5 9.5 H17 L15.2 12.2 L17 14.9 H10.5" fill="#B3261E" stroke="#B3261E" stroke-width="1.6" stroke-linejoin="round"/>'
    "</svg>"
)
