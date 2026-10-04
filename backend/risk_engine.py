"""Deterministic safety layer: link analysis, rule-based signals, and risk calibration.

The AI proposes a risk level; this module checks it against transparent rules so that
(a) weak signals such as urgency alone never produce HIGH/CRITICAL, and
(b) strong combinations (e.g. an OTP request plus pressure) are not under-called.
Links are only *parsed*, never visited.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .schemas import LinkFinding, RedFlag, Signal

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RISK_META = {
    "LOW": {
        "label": "LOW RISK", "icon": "🟢",
        "message": "No major scam indicators detected, but AI analysis cannot guarantee that a message is safe.",
    },
    "MEDIUM": {
        "label": "MEDIUM RISK", "icon": "🟡",
        "message": "Unable to determine with high confidence. Verify the sender independently before taking action.",
    },
    "HIGH": {
        "label": "HIGH RISK", "icon": "🔴",
        "message": "High-risk communication detected. This communication shows characteristics commonly associated with scams.",
    },
    "CRITICAL": {
        "label": "CRITICAL RISK", "icon": "🚨",
        "message": ("Critical-risk communication detected. It shows severe indicators such as credential theft, "
                    "payment fraud, threats or malicious links. Do not respond, click or pay."),
    },
}

CONFIDENCE_NOTE = (
    "AI Risk Confidence is how confident the AI is in this assessment, based on the signals it detected. "
    "It is not a verified probability that the message is fraudulent."
)
DISCLAIMER = (
    "ScamLens is an AI-assisted risk assessment tool. It does not guarantee that a communication is "
    "fraudulent or safe. Always verify through official channels before acting."
)
NO_URL_MESSAGE = "No URL detected."
LINK_SUSPICIOUS_MESSAGE = "This link has suspicious characteristics. Verify the domain before opening it."
LINK_OK_MESSAGE = "No obvious suspicious characteristics in the link itself. Still verify the domain before opening it."


def idx(level: str) -> int:
    return RISK_ORDER.index(level)


# --------------------------------------------------------------------- link analysis
_TLDS = (
    "com net org ng info biz co io xyz top click link live online site shop store app me ly gl gd cc tk ml ga cf gq "
    "icu buzz club vip work support ru cn gov edu uk za gh ke tz ug us ws to sbs cfd rest monster cyou page dev "
    "website tech pro fun life world today email help services zip mov ink wiki cloud digital"
).split()
_TLD_ALT = "|".join(sorted(_TLDS, key=len, reverse=True))
_URL_RE = re.compile(
    rf"""(?<![\w@.\-/])(?:
        (?:https?|hxxps?)://[^\s<>"'\)\]]+
      | www\.[^\s<>"'\)\]]+
      | (?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_TLD_ALT})\b(?::\d+)?(?:/[^\s<>"'\)\]]*)?
    )""",
    re.I | re.X,
)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
              "tiny.cc", "rebrand.ly", "s.id", "t.ly", "bl.ink", "lnkd.in", "wa.me"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "link", "buzz", "icu", "cfd", "sbs", "tk", "ml", "ga", "cf", "gq", "work",
                   "support", "monster", "rest", "cyou", "zip", "mov", "vip", "club", "live", "fun"}
MULTI_SUFFIXES = {"com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng", "co.uk", "org.uk", "co.za", "org.za", "com.gh",
                  "co.ke", "co.tz", "co.ug", "com.au", "co.in"}
URL_KEYWORDS = ("login", "signin", "verify", "verification", "secure", "update", "confirm", "account", "password",
                "otp", "bvn", "claim", "wallet", "reward", "bonus", "giveaway", "suspend", "unlock", "kyc")
# Well-known names and the domains this tool recognises for them (used only to spot look-alikes).
BRAND_DOMAINS = {
    "paypal": {"paypal.com"}, "google": {"google.com"}, "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"}, "amazon": {"amazon.com"}, "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"}, "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "netflix": {"netflix.com"}, "paystack": {"paystack.com"}, "flutterwave": {"flutterwave.com"},
    "gtbank": {"gtbank.com"}, "zenithbank": {"zenithbank.com"}, "accessbank": {"accessbankplc.com"},
}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def extract_urls(text: str) -> list[str]:
    seen: list[str] = []
    for m in _URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;:!?)\"'")
        if url and url.lower() not in (s.lower() for s in seen):
            seen.append(url)
    return seen[:10]


def _registrable(host: str) -> tuple[str, int]:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:]), len(labels) - 3
    return ".".join(labels[-2:]), max(0, len(labels) - 2)


def analyze_url(url: str) -> LinkFinding:
    """Static heuristics only. The URL is never fetched."""
    display = url if len(url) <= 300 else url[:300] + "…"
    normalized = re.sub(r"^hxxp", "http", url, flags=re.I)
    explicit_http = normalized.lower().startswith("http://")
    try:
        parts = urlsplit(normalized if "://" in normalized else "//" + normalized)
        host = (parts.hostname or "").lower().strip(".")
        port = parts.port
        has_userinfo = parts.username is not None
        path = (parts.path or "") + ("?" + parts.query if parts.query else "")
    except ValueError:
        return LinkFinding(url=display, domain="(unreadable)", suspicious=True,
                           reasons=["The link is malformed or deliberately obscured."], message=LINK_SUSPICIOUS_MESSAGE)
    if not host:
        return LinkFinding(url=display, domain="(unreadable)", suspicious=True,
                           reasons=["The link has no readable domain."], message=LINK_SUSPICIOUS_MESSAGE)

    score, reasons = 0, []

    def add(weight: int, reason: str) -> None:
        nonlocal score
        score += weight
        reasons.append(reason)

    registrable, subs = _registrable(host)
    reg_label = registrable.split(".")[0]
    tld = host.rsplit(".", 1)[-1]

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add(3, "Uses a raw IP address instead of a domain name.")
    if host in SHORTENERS or registrable in SHORTENERS:
        add(2, "Uses a link shortener, which hides the real destination.")
    if "xn--" in host:
        add(3, "Contains encoded (punycode) characters that can imitate real domains.")
    if has_userinfo:
        add(3, "Contains an '@' that can disguise the true destination.")
    if subs >= 3:
        add(2, f"Has an unusually long chain of subdomains ({subs}).")
    elif subs == 2:
        add(1, "Has several subdomains, a trick often used to look official.")
    if tld in SUSPICIOUS_TLDS:
        add(1, f"Uses the '.{tld}' ending, which is common in throwaway scam sites.")
    if reg_label.count("-") >= 2:
        add(1, "The domain name contains several hyphens.")
    if len(host) > 35:
        add(1, "The domain name is unusually long.")
    if port not in (None, 80, 443):
        add(1, "Uses a non-standard port.")
    if explicit_http:
        add(1, "Uses HTTP instead of HTTPS (not encrypted).")

    # Look-alike detection against a small list of widely impersonated names.
    pieces = [p for p in re.split(r"[-_.]", host) if p]
    leet_pieces = [p.translate(_LEET).replace("rn", "m").replace("vv", "w") for p in pieces]
    for brand, official in BRAND_DOMAINS.items():
        if registrable in official:
            continue
        exact = any(p.startswith(brand) for p in pieces)
        disguised = any(p.startswith(brand) for p in leet_pieces)
        if exact and brand in ".".join(host.split(".")[: max(0, len(host.split(".")) - len(registrable.split(".")))]):
            add(3, f"A well-known name ('{brand}') appears as a subdomain, but the actual domain is different.")
            break
        if exact or disguised:
            add(2 if exact else 3, f"The domain imitates the name '{brand}' but is not one of its well-known domains.")
            break

    found_kw = [k for k in URL_KEYWORDS if k in (host + path).lower()]
    if found_kw:
        add(1, "Contains words often used to pressure logins or claims (" + ", ".join(found_kw[:3]) + ").")

    suspicious = score >= 2
    return LinkFinding(
        url=display, domain=host, suspicious=suspicious,
        reasons=reasons if suspicious or reasons else [],
        message=LINK_SUSPICIOUS_MESSAGE if suspicious else LINK_OK_MESSAGE,
    )


def analyze_links(text: str) -> list[LinkFinding]:
    return [analyze_url(u) for u in extract_urls(text)]


# ------------------------------------------------------------------ rule-based signals
_NEG_RE = re.compile(
    r"(?:do\s*not|don'?t|never|won'?t|will\s+not|should\s+not|shouldn'?t|cannot|can'?t|not)\s+(?:\w+\s+){0,2}$", re.I)

_CRED_NOUNS_ALL = (r"otp|one[\s-]?time\s+(?:pass(?:word|code)|code|pin)|pin|password|passcode|bvn|cvv2?|cvc|"
                   r"card\s+(?:number|details|pin)|security\s+code|verification\s+code|auth(?:entication)?\s+code|token|"
                   r"login\s+details|log-?in\s+credentials|credentials|secret\s+code|2fa\s+code|(?:transaction|atm)\s+pin|"
                   r"6[\s-]?digit\s+code")
_CRED_NOUNS_HARD = (r"password|pin|bvn|cvv2?|card\s+(?:number|details)|login\s+details|credentials|passcode|"
                    r"(?:transaction|atm)\s+pin")
_PERSONAL_NOUNS = (r"full\s+name|home\s+address|residential\s+address|address|date\s+of\s+birth|d\.?o\.?b|nin|"
                   r"national\s+id(?:entity)?(?:\s+number)?|id\s+card|passport|account\s+number|phone\s+number|"
                   r"mother'?s\s+maiden\s+name|selfie|next\s+of\s+kin")

P = {
    "cred": [
        r"\b(?:send|share|provide|give|reply|respond|tell|forward|read\s+out|disclose|supply|submit)\b[^.\n!?]{0,60}?\b(?:" + _CRED_NOUNS_ALL + r")\b",
        r"\b(?:enter|input|type|confirm|verify|validate|update|re-?enter)\b[^.\n!?]{0,40}?\b(?:" + _CRED_NOUNS_HARD + r")\b",
    ],
    "personal": [
        r"\b(?:send|provide|share|submit|fill|enter|give|supply|reply\s+with|forward|upload)\b[^.\n!?]{0,40}?\b(?:your|ur|the\s+following|following)\b[^.\n!?]{0,30}?\b(?:" + _PERSONAL_NOUNS + r")\b",
    ],
    "adv_fee": [
        r"\b(?:registration|processing|application|clearance|activation|release|delivery|courier|insurance|training|verification|admin(?:istrative)?|portal|uniform|documentation|booking|shipping|customs)\s+(?:fee|fees|charge|charges|payment)\b",
        r"\bup-?front\s+(?:fee|payment|deposit)\b",
        r"\badvance\s+(?:fee|payment)\b",
        r"\brefundable\s+(?:deposit|fee)\b",
    ],
    "unusual_pay": [
        r"\b(?:send|pay|buy|purchase|transfer|deposit|load)\b[^.\n]{0,60}\b(?:gift\s*cards?|itunes|google\s+play\s+cards?|steam\s+cards?|bitcoin|btc|usdt|western\s+union|moneygram|bank\s+wire)\b",
        r"\b(?:gift\s*cards?|itunes|google\s+play\s+cards?|steam\s+cards?|bitcoin|btc|usdt|western\s+union|moneygram)\b[^.\n]{0,60}\b(?:send|pay|buy|purchase|transfer|deposit)\b",
    ],
    "payment": [
        r"\b(?:send|transfer|pay|deposit|remit|make\s+(?:a\s+)?payment(?:\s+of)?)\b[^.\n!?]{0,50}?(?:₦|\bngn\b|\bnaira\b|\bN\s?\d|\$\s?\d|\busd\b|\b\d{1,3}(?:,\d{3})+\b|\b\d+\s?k\b)",
    ],
    "urgency": [
        r"\b(?:urgent(?:ly)?|immediately|right\s+away|asap|act\s+now|act\s+fast|last\s+chance|final\s+(?:warning|notice)|within\s+(?:the\s+next\s+)?\d+\s*(?:minutes?|mins?|hours?|hrs?)|(?:expires?|expiring|expired|ends?)\s+(?:today|tonight|soon|in\s+\d+)|before\s+midnight|today\s+only|(?:in\s+the\s+)?next\s+\d+\s*(?:minutes?|hours?)|in\s+\d{1,3}\s*(?:minutes?|mins?)|do\s+not\s+delay|without\s+delay|limited\s+time)\b",
        r"\b(?:send|transfer|pay)\b[^.\n]{0,60}\b(?:today|now|tonight|asap)\b",
    ],
    "threat": [
        r"\b(?:will\s+be\s+(?:blocked|suspended|closed|deactivated|terminated|frozen|disabled|locked|restricted|deleted|reported|prosecuted|arrested)|legal\s+action|arrest(?:ed)?|prosecut\w+|warrant|your\s+account\s+(?:has\s+been|is)\s+(?:compromised|hacked|suspended|blocked|locked))\b",
    ],
    "extortion": [
        r"\b(?:i|we)(?:'ll|\s+will)\s+(?:post|send|share|leak|expose|publish|release|forward)\b[^.\n!?]{0,60}?\b(?:photos?|videos?|nudes?|pictures?|images?|chats?|messages?|contacts?|information|secrets?|recordings?)\b",
        r"\bunless\s+you\s+pay\b",
        r"\bpay\s+(?:me|us)\s+or\b",
        r"\b(?:i|we)\s+(?:have\s+)?(?:hacked|recorded)\b[^.\n!?]{0,50}?\byour\s+(?:webcam|camera|device|phone|password|videos?|photos?)\b",
    ],
    "reward": [
        r"\b(?:you(?:'ve|\s+have)?\s+(?:won|been\s+selected|been\s+chosen)|congratulations|winner|claim\s+your\s+(?:prize|reward|gift|bonus|cash)|giveaway|lucky\s+(?:draw|winner)|free\s+(?:data|airtime|cash|money|gift|iphone)|cash\s+prize|selected\s+(?:as|for|to\s+receive))\b",
    ],
    "invest": [
        r"\bguaranteed\s+(?:returns?|profits?|income|earnings?)\b",
        r"\bdouble\s+your\s+(?:money|investment|capital|funds)\b",
        r"\b\d{2,4}\s?%\s+(?:daily|weekly|monthly|returns?|profit|roi|interest)\b",
        r"\brisk[\s-]?free\s+(?:investment|profit|returns?|trading)\b",
        r"\b(?:crypto|forex)\s+(?:trading|investment)\b[^.\n]{0,60}\b(?:earn|profit|returns?|guarantee\w*)\b",
    ],
    "remote": [
        r"\b(?:anydesk|team\s?viewer|quick\s?support|remote\s+(?:access|desktop|control)|(?:install|download)\s+(?:this|the|our)\s+(?:app|apk|application|software))\b",
        r"\.apk\b",
    ],
    "impersonation": [
        r"\b(?:this\s+is|i\s+am|i'm|we\s+are|calling\s+from|message\s+from|from\s+the)\s+(?:the\s+|your\s+|a\s+|an\s+)?[\w\s'&.-]{0,40}?\b(?:bank|customer\s+(?:care|service|support)|support\s+team|support\s+agent|security\s+team|fraud\s+(?:team|department|unit)|help\s*desk|official|agent|officer|manager|recruiter|hr\s+(?:team|department|manager)|cbn|efcc|nimc|firs|police|immigration|customs|admin(?:istrator)?)\b",
        r"\b(?:hi|hello|hey)\s+(?:mum|mom|dad|mummy|daddy|mama|papa)\b",
        r"\b(?:this\s+is\s+my\s+new\s+(?:number|phone)|(?:i\s+)?lost\s+my\s+phone|changed\s+my\s+number|new\s+(?:whatsapp\s+)?number)\b",
    ],
    "secrecy": [
        r"\b(?:do\s*n[o']?t|don'?t|never)\s+(?:tell|inform|let)\s+(?:anyone|anybody|your\s+\w+|dad|mum|mom|mummy|daddy|him|her|them)\b",
        r"\bkeep\s+(?:this|it)\s+(?:a\s+)?(?:secret|confidential|private)\b",
        r"\bbetween\s+(?:us|you\s+and\s+me)\b",
    ],
    "offplatform": [
        r"\b(?:contact|message|chat|text|reach|dm)\s+(?:me|us|him|her|our\s+\w+)\s+(?:on|via|through|at)\s+(?:whatsapp|telegram|signal)\b",
        r"\b(?:whatsapp|telegram)\s+(?:me|us|him|her)\b",
    ],
}
_ADV_CONTEXT = re.compile(
    r"\b(?:job|vacancy|hiring|hired|recruit\w*|employment|offer\s+letter|interview|shortlisted|prize|won|winner|lottery|"
    r"loan|grant|scholarship|inheritance|visa|congratulations|selected)\b", re.I)

_COMPILED = {k: [re.compile(p, re.I) for p in v] for k, v in P.items()}
_NO_NEGATION = {"secrecy", "extortion"}

SIGNAL_LABELS = {
    "credential_request": "Asks for a PIN, password, OTP or card details",
    "personal_info_request": "Asks for personal or identity details",
    "advance_fee": "Asks for an upfront fee",
    "unusual_payment": "Asks for payment by gift card, crypto or wire",
    "payment_request": "Asks for a payment or transfer",
    "urgency": "Creates time pressure",
    "threat": "Warns of account closure, arrest or legal action",
    "extortion": "Threatens to expose or harm unless paid",
    "reward": "Promises a prize, reward or giveaway",
    "investment": "Promises guaranteed or unrealistic returns",
    "remote_access": "Asks to install an app or grant remote access",
    "impersonation_claim": "Claims an identity (organisation, official or family member)",
    "secrecy": "Asks you to keep it secret",
    "off_platform": "Moves the conversation to WhatsApp or Telegram",
    "suspicious_link": "Contains a suspicious-looking link",
}


def _sentence(text: str, m: re.Match, maxlen: int = 180) -> str:
    left = max(text.rfind(".", 0, m.start()), text.rfind("\n", 0, m.start()), text.rfind("!", 0, m.start()))
    right_candidates = [i for i in (text.find(".", m.end()), text.find("\n", m.end()), text.find("!", m.end())) if i != -1]
    right = min(right_candidates) if right_candidates else len(text)
    snippet = " ".join(text[left + 1:right + 1].split())
    return snippet[:maxlen]


def _find(text: str, key: str):
    for rx in _COMPILED[key]:
        for m in rx.finditer(text):
            if key not in _NO_NEGATION and _NEG_RE.search(text[max(0, m.start() - 35):m.start()]):
                continue
            return m
    return None


def detect_signals(text: str, links: list[LinkFinding]) -> list[Signal]:
    found: dict[str, tuple[bool, str]] = {}
    mapping = [
        ("cred", "credential_request", True), ("personal", "personal_info_request", False),
        ("adv_fee", "advance_fee", False), ("unusual_pay", "unusual_payment", True),
        ("payment", "payment_request", False), ("urgency", "urgency", False), ("threat", "threat", False),
        ("extortion", "extortion", True), ("reward", "reward", False), ("invest", "investment", True),
        ("remote", "remote_access", True), ("impersonation", "impersonation_claim", False),
        ("secrecy", "secrecy", False), ("offplatform", "off_platform", False),
    ]
    for key, name, strong in mapping:
        m = _find(text, key)
        if m:
            found[name] = (strong, _sentence(text, m))
    bad_links = [l for l in links if l.suspicious]
    if bad_links:
        found["suspicious_link"] = (True, bad_links[0].url)

    # Context-dependent strength: weak signals become strong only in telling combinations.
    names = set(found)
    if "advance_fee" in found and _ADV_CONTEXT.search(text):
        found["advance_fee"] = (True, found["advance_fee"][1])
    if "personal_info_request" in found and names & {"reward", "urgency", "threat", "impersonation_claim",
                                                     "suspicious_link", "advance_fee"}:
        found["personal_info_request"] = (True, found["personal_info_request"][1])
    if "payment_request" in found and names & {"urgency", "threat"} and names & {"impersonation_claim", "suspicious_link"}:
        found["payment_request"] = (True, found["payment_request"][1])

    return [Signal(name=n, label=SIGNAL_LABELS[n], strong=s, evidence=e) for n, (s, e) in found.items()]


# ------------------------------------------------------------------------- classification
_PAYMENTISH = {"payment_request", "advance_fee", "unusual_payment"}


def _is_critical(names: set[str]) -> bool:
    if "credential_request" in names and len(names) > 1:
        return True
    if "extortion" in names:
        return True
    if "suspicious_link" in names and names & (_PAYMENTISH | {"personal_info_request", "remote_access"}):
        return True
    if "remote_access" in names and names & (_PAYMENTISH | {"credential_request"}):
        return True
    if "unusual_payment" in names and names & {"urgency", "threat", "impersonation_claim"}:
        return True
    return False


def classify(ai_level: str, signals: list[Signal], flags: list[RedFlag]) -> tuple[str, list[str]]:
    """Calibrate the AI's level with the rule-based signals. Returns (level, notes)."""
    names = {s.name for s in signals}
    strong = [s for s in signals if s.strong]
    ns, nw = len(strong), len(signals) - len(strong)
    verified_flags = sum(1 for f in flags if f.evidence_in_message)
    critical = _is_critical(names)
    notes: list[str] = []
    level = ai_level

    # Floor: what the transparent rules say is the minimum sensible level.
    if critical:
        floor = "HIGH"
    elif ns >= 2 or any(s.name == "advance_fee" for s in strong) or (ns >= 1 and len(signals) >= 3):
        floor = "HIGH"
    elif ns >= 1 or nw >= 3:
        floor = "MEDIUM"
    else:
        floor = "LOW"

    # Cap: the highest level the evidence supports.
    if critical:
        cap = "CRITICAL"
    elif ns >= 1 or verified_flags >= 3:
        cap = "HIGH"
    else:
        cap = "MEDIUM"

    if idx(level) > idx(cap):
        if ns == 0:
            notes.append("Only weak signals were found by the automated checks (for example urgency or a payment "
                         "request). Legitimate organisations use these too, so the level was limited to MEDIUM.")
        else:
            notes.append(f"The level was limited to {cap} because the evidence did not include a severe combination "
                         "such as credential theft, threats or a malicious link plus pressure.")
        level = cap

    if idx(level) < idx(floor):
        notes.append("Automated checks found strong signals ("
                     + ", ".join(s.label.lower() for s in strong[:3] or signals[:3])
                     + f"), so the level was raised from {level} to {floor}.")
        level = floor

    if critical and idx(ai_level) >= idx("HIGH") and level != "CRITICAL":
        notes.append("Severe indicators were found together, so the level was raised to CRITICAL.")
        level = "CRITICAL"
    return level, notes


# --------------------------------------------------------- actions & verification steps
_ACTIONS = {
    "credential_request": "Do not share your OTP, PIN, password or card details with anyone. Real organisations never ask for them by message or call.",
    "suspicious_link": "Do not click the link or open any attachment.",
    "money": "Do not send money or pay any fee until you have verified the request independently.",
    "remote_access": "Do not install apps or give anyone remote access to your phone or computer.",
    "extortion": "Do not pay or negotiate. Keep screenshots as evidence and report the threat.",
    "personal_info_request": "Do not send personal or identity details (such as your address, date of birth or ID number).",
    "report": "Report the message to your bank or the platform it came from, and block the sender.",
    "already_acted": "If you already shared details or paid, contact your bank immediately, change your passwords and keep records.",
    "verify": "If you are unsure, verify the sender through an official channel before taking any action.",
    "low": "Stay alert: if anything later feels off, stop and verify before you respond.",
}
_VERIFY = [
    "Contact the organisation using a phone number or website you already trust, such as the number on your card or the official website you type in yourself.",
    "Do not use the contact details, links or account numbers given in the message.",
    "Ask a trusted person, or the real person through a number you already have, if the message claims to be from someone you know.",
    "Search for the offer or company independently and check reviews and official announcements.",
]


def _dedupe(items: list[str], limit: int) -> list[str]:
    out, keys = [], set()
    for it in items:
        key = re.sub(r"[^a-z0-9 ]", "", it.lower())[:60]
        if key and key not in keys:
            keys.add(key)
            out.append(it)
        if len(out) >= limit:
            break
    return out


def build_actions(level: str, signals: list[Signal], ai_actions: list[str]) -> list[str]:
    names = {s.name for s in signals}
    extra: list[str] = []
    if "credential_request" in names:
        extra.append(_ACTIONS["credential_request"])
    if "suspicious_link" in names:
        extra.append(_ACTIONS["suspicious_link"])
    if names & _PAYMENTISH:
        extra.append(_ACTIONS["money"])
    if "remote_access" in names:
        extra.append(_ACTIONS["remote_access"])
    if "extortion" in names:
        extra.append(_ACTIONS["extortion"])
    if "personal_info_request" in names:
        extra.append(_ACTIONS["personal_info_request"])
    if idx(level) >= 2:
        extra += [_ACTIONS["report"], _ACTIONS["already_acted"]]
    elif level == "MEDIUM":
        extra.append(_ACTIONS["verify"])
    else:
        extra.append(_ACTIONS["low"])
    return _dedupe(ai_actions + extra, 8)


def build_verification(ai_steps: list[str]) -> list[str]:
    return _dedupe(ai_steps + _VERIFY, 6)


def verify_evidence(flags: list[RedFlag], text: str) -> list[RedFlag]:
    """Mark whether each quoted evidence string really appears in the message."""
    def norm(s: str) -> str:
        return re.sub(r"[\s\u2019'\"“”‘’]+", " ", s.lower()).strip(" .…")
    hay = norm(text)
    for f in flags:
        pieces = [norm(p) for p in re.split(r"…|\.\.\.", f.evidence) if len(norm(p)) >= 6]
        f.evidence_in_message = bool(pieces) and all(p in hay for p in pieces)
    return flags
