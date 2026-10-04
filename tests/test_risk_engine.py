from backend import risk_engine as re_
from backend.schemas import RedFlag

PHISH = ("EVERGREEN BANK ALERT: Your account will be BLOCKED in 30 minutes. Reply with your 6-digit OTP "
         "or verify at http://evergreenbank-verify.top/secure-login")
LEGIT = ("Evergreen Bank: Credit alert. You received ₦15,000.00 from ADAEZE O. Available balance: ₦48,230.55. "
         "Call the number on the back of your card for questions.")


def sig(text):
    links = re_.analyze_links(text)
    return re_.detect_signals(text, links), links


def names(text):
    return {s.name for s in sig(text)[0]}


def test_extract_urls_ignores_emails_and_dedupes():
    urls = re_.extract_urls("Mail me at user@gmail.com or visit bit.ly/abc and https://x.top/a, bit.ly/abc.")
    assert urls == ["bit.ly/abc", "https://x.top/a"]


def test_no_url_message():
    assert re_.analyze_links("Hello there, how are you?") == []


def test_suspicious_link_detected():
    f = re_.analyze_url("http://evergreenbank-verify.top/secure-login")
    assert f.suspicious and f.message == re_.LINK_SUSPICIOUS_MESSAGE
    assert any("HTTP" in r for r in f.reasons)


def test_shortener_and_ip_and_lookalike():
    assert re_.analyze_url("https://bit.ly/3xYz").suspicious
    assert re_.analyze_url("http://192.168.4.20/login").suspicious
    assert re_.analyze_url("https://paypa1-support.com/help").suspicious
    assert re_.analyze_url("https://paypal.com.secure-login.xyz/").suspicious


def test_normal_link_not_flagged():
    f = re_.analyze_url("https://www.paypal.com/signin")
    assert not f.suspicious and f.message == re_.LINK_OK_MESSAGE


def test_otp_request_detected_but_warning_is_not():
    assert "credential_request" in names("Please reply with your OTP to continue.")
    assert "credential_request" not in names("Your OTP is 482913. Never share your OTP with anyone.")
    assert "credential_request" not in names("Please do not give your PIN to anyone.")


def test_legit_notification_has_no_signals():
    assert sig(LEGIT)[0] == []


def test_urgency_alone_is_weak_and_capped_at_medium():
    signals, _ = sig("URGENT: your invoice is due today. Please pay N25,000 to avoid late fees.")
    assert signals and not any(s.strong for s in signals)
    level, notes = re_.classify("HIGH", signals, [])
    assert level == "MEDIUM" and notes


def test_critical_when_credentials_plus_pressure():
    signals, _ = sig(PHISH)
    level, _ = re_.classify("HIGH", signals, [])
    assert level == "CRITICAL"


def test_advance_fee_for_job_floors_high_even_if_ai_says_low():
    text = "Congratulations, you are hired! Pay a refundable registration fee of ₦15,000 to secure your job."
    signals, _ = sig(text)
    assert any(s.name == "advance_fee" and s.strong for s in signals)
    level, notes = re_.classify("LOW", signals, [])
    assert level == "HIGH" and notes


def test_giveaway_with_personal_info_is_high():
    text = ("You've been selected to receive ₦500,000 in our giveaway! To claim your prize, send your full name, "
            "home address and date of birth today.")
    signals, _ = sig(text)
    level, _ = re_.classify("HIGH", signals, [])
    assert level == "HIGH"


def test_ai_critical_without_severe_signals_is_downgraded():
    signals, _ = sig("Guaranteed returns of 40% weekly! Deposit N50,000 now.")
    level, _ = re_.classify("CRITICAL", signals, [])
    assert level == "HIGH"


def test_low_stays_low_without_signals():
    assert re_.classify("LOW", [], [])[0] == "LOW"


def test_ai_high_without_signals_or_verified_flags_is_capped():
    assert re_.classify("HIGH", [], [])[0] == "MEDIUM"
    flags = [RedFlag(indicator=str(i), evidence="x", explanation="y", evidence_in_message=True) for i in range(3)]
    assert re_.classify("HIGH", [], flags)[0] == "HIGH"


def test_verify_evidence_marks_found_and_invented_quotes():
    flags = [RedFlag(indicator="Urgency", evidence="Your account will be BLOCKED", explanation="x"),
             RedFlag(indicator="Made up", evidence="send bitcoin now", explanation="x")]
    re_.verify_evidence(flags, PHISH)
    assert flags[0].evidence_in_message is True and flags[1].evidence_in_message is False


def test_actions_always_present_and_deduped():
    signals, _ = sig(PHISH)
    actions = re_.build_actions("CRITICAL", signals, ["Do not click the link."])
    assert 3 <= len(actions) <= 8 and len(set(a.lower() for a in actions)) == len(actions)
    assert re_.build_actions("LOW", [], [])
