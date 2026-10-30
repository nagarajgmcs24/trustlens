import pytest

from services.detection_engine import analyze_message
from models.schemas import AnalysisRequest
from services.risk_scorer import compute_score


SUSPICIOUS_MESSAGES = [
    "Your bank account will be blocked today. Verify your KYC immediately using this link: https://example-bit.ly/verify-account",
    "We need your OTP to secure your account. Reply with the code immediately.",
    "Government subsidy payment is available. Official verification required before 24 hours.",
    "Guaranteed work from home income with no experience required. Pay the registration fee to get started.",
    "Click here now: https://bit.ly/offer123 and update your password to avoid suspension.",
    "Your account has been suspended due to a payment failure. Please verify your bank details now.",
]

SAFE_MESSAGES = [
    "Happy birthday! Hope you have a great day with your family and friends.",
    "The college annual fest starts next week and all students are invited to attend.",
    "Your package is out for delivery and should arrive today.",
    "I will meet you after class to discuss the shipping details.",
]


def test_suspicious_messages_are_flagged():
    for message in SUSPICIOUS_MESSAGES:
        result = analyze_message(message, channel="SMS")
        assert result["risk_level"] in {"MEDIUM RISK", "HIGH RISK"}
        assert result["risk_score"] >= 30


def test_safe_messages_remain_low_risk():
    for message in SAFE_MESSAGES:
        result = analyze_message(message, channel="WhatsApp")
        assert result["risk_level"] == "LOW RISK"
        assert "sensitive_info" not in result["detected_categories"]


def test_job_fee_and_suspension_messages_are_elevated():
    job = analyze_message("Congratulations on the guaranteed job. Pay the registration fee to begin.")
    suspension = analyze_message("Your account has been suspended. Act now to restore access.")

    assert job["risk_score"] >= 30
    assert job["risk_level"] == "MEDIUM RISK"
    assert suspension["risk_score"] >= 30
    assert suspension["risk_level"] == "MEDIUM RISK"


def test_shortener_match_uses_domain_boundaries():
    result = analyze_message("Visit https://notbit.ly.example.org/page when convenient.")
    assert result["suspicious_urls"] == []


def test_suspicious_urls_are_detected():
    result = analyze_message("Click here: http://10.0.0.1/verify and update your password immediately.")
    assert result["suspicious_urls"]
    assert any("suspicious_url" == category for category in result["detected_categories"])


def test_analysis_contains_explanations_and_recommendations():
    result = analyze_message("Your bank account will be blocked today. Verify your KYC immediately.")
    assert result["explanations"]
    assert result["recommendations"]


LANGUAGE_CASES = [
    (
        "English",
        "Your bank account will be blocked today. Update your KYC immediately and share your OTP.",
        "The college library will be closed tomorrow. Classes resume on Monday.",
    ),
    (
        "Hindi",
        "आपका बैंक खाता आज बंद किया जाएगा। तुरंत केवाईसी अपडेट करें और अपना ओटीपी साझा करें।",
        "कल कॉलेज में सांस्कृतिक कार्यक्रम है। सभी विद्यार्थी आमंत्रित हैं।",
    ),
    (
        "Kannada",
        "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ. ತಕ್ಷಣ ಕೆವೈಸಿ ನವೀಕರಿಸಿ ಮತ್ತು ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ.",
        "ನಾಳೆ ಕಾಲೇಜಿನಲ್ಲಿ ಸಾಂಸ್ಕೃತಿಕ ಕಾರ್ಯಕ್ರಮ ಇದೆ. ಎಲ್ಲ ವಿದ್ಯಾರ್ಥಿಗಳು ಭಾಗವಹಿಸಿ.",
    ),
]


def test_synthetic_phishing_and_legitimate_messages_for_each_language():
    for language, phishing_message, legitimate_message in LANGUAGE_CASES:
        phishing_result = analyze_message(phishing_message, language=language)
        legitimate_result = analyze_message(legitimate_message, language=language)

        assert phishing_result["language"] == language
        assert phishing_result["risk_score"] >= 30
        assert phishing_result["risk_level"] in {"MEDIUM RISK", "HIGH RISK"}
        assert legitimate_result["language"] == language
        assert legitimate_result["risk_score"] < 30
        assert legitimate_result["risk_level"] == "LOW RISK"

        if language != "English":
            assert "coverage is limited" in phishing_result["language_support"]
            assert "coverage is limited" in legitimate_result["language_support"]


def test_language_request_validation_and_default():
    assert AnalysisRequest(message="A sufficiently long test message").language == "English"
    assert AnalysisRequest(message="A sufficiently long test message", language="hindi").language == "Hindi"
    assert AnalysisRequest(message="A sufficiently long test message", language="KANNADA").language == "Kannada"

    with pytest.raises(ValueError):
        AnalysisRequest(message="A sufficiently long test message", language="Spanish")


THREAT_MESSAGES = [
    (
        "English",
        "Your account will be permanently suspended in 10 minutes. Take immediate action.",
        ("account_threat", "time_pressure", "urgency"),
        ("10 minutes", "immediate action"),
    ),
    (
        "Hindi",
        "आपका खाता 10 मिनट में बंद कर दिया जाएगा। तुरंत कार्रवाई करें।",
        ("account_threat", "time_pressure", "urgency"),
        ("10 मिनट में", "तुरंत कार्रवाई करें"),
    ),
    (
        "Kannada",
        "ನಿಮ್ಮ ಖಾತೆಯನ್ನು 10 ನಿಮಿಷಗಳಲ್ಲಿ ಶಾಶ್ವತವಾಗಿ ಸ್ಥಗಿತಗೊಳಿಸಲಾಗುತ್ತದೆ. ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ.",
        ("account_threat", "time_pressure", "urgency"),
        ("10 ನಿಮಿಷಗಳಲ್ಲಿ", "ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ"),
    ),
]


@pytest.mark.parametrize("language,message,categories,matched_phrases", THREAT_MESSAGES)
def test_multilingual_account_threat_time_and_urgency_evidence(
    language, message, categories, matched_phrases
):
    result = analyze_message(message, language=language)

    evidence_by_category = {item["category"]: item for item in result["evidence"]}
    assert set(categories).issubset(evidence_by_category)
    assert result["risk_score"] == 52
    assert result["risk_level"] == "MEDIUM RISK"

    for category in categories:
        item = evidence_by_category[category]
        assert item["language"] == language
        assert item["matched_phrase"]
        assert item["explanation"]
        assert item["recommended_action"]
        assert item["points_contributed"] == item["weight"]
    all_matches = " ".join(
        phrase
        for item in result["evidence"]
        for phrase in item["matched_phrases"]
    )
    for expected in matched_phrases:
        assert expected in all_matches


JOB_SCAM_CASES = [
    ("English", "Guaranteed job offer. Pay the registration fee to begin.", 40),
    ("Hindi", "गारंटीड नौकरी! नौकरी पाने के लिए पंजीकरण शुल्क जमा करें।", 40),
    ("Kannada", "ಖಚಿತ ಉದ್ಯೋಗ! ಕೆಲಸ ಪಡೆಯಲು ನೋಂದಣಿ ಶುಲ್ಕ ಪಾವತಿಸಿ.", 40),
]


@pytest.mark.parametrize("language,message,expected_score", JOB_SCAM_CASES)
def test_multilingual_job_registration_fee_scams(language, message, expected_score):
    result = analyze_message(message, language=language)

    assert {"job_reward", "upfront_payment"}.issubset(result["detected_categories"])
    assert result["risk_score"] == expected_score
    assert result["risk_level"] in {"MEDIUM RISK", "HIGH RISK"}


OTP_SCAM_CASES = [
    ("English", "We need your OTP. Share your OTP now to secure your account.", 30),
    ("Hindi", "अपना ओटीपी साझा करें और तुरंत भेजें।", 40),
    ("Kannada", "ನಿಮ್ಮ ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ ಮತ್ತು ತಕ್ಷಣ ಕಳುಹಿಸಿ.", 40),
]


@pytest.mark.parametrize("language,message,expected_score", OTP_SCAM_CASES)
def test_multilingual_otp_request_scams(language, message, expected_score):
    result = analyze_message(message, language=language)

    assert "sensitive_info" in result["detected_categories"]
    assert result["risk_score"] == expected_score
    assert any(item["category"] == "sensitive_info" for item in result["evidence"])


PRIZE_SCAM_CASES = [
    ("English", "You have won a prize! Claim your reward at https://bit.ly/claim"),
    ("Hindi", "आपने इनाम जीता है! https://bit.ly/claim पर अपना उपहार प्राप्त करें।"),
    ("Kannada", "ನೀವು ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ! https://bit.ly/claim ನಲ್ಲಿ ನಿಮ್ಮ ಉಡುಗೊರೆ ಪಡೆಯಿರಿ."),
]


@pytest.mark.parametrize("language,message", PRIZE_SCAM_CASES)
def test_multilingual_prize_scam_with_shortened_url(language, message):
    result = analyze_message(message, language=language)

    assert {"reward_scam", "suspicious_url"}.issubset(result["detected_categories"])
    assert result["risk_score"] == 30
    assert result["risk_level"] == "MEDIUM RISK"


SAFE_LANGUAGE_CASES = [
    (
        "English",
        "The college library will be closed tomorrow. Classes resume on Monday.",
        "Our company is hiring interns. Apply through the official careers portal; no fee is required.",
        "Your monthly account statement is ready in the official app.",
    ),
    (
        "Hindi",
        "कल कॉलेज में सांस्कृतिक कार्यक्रम है। सभी विद्यार्थी आमंत्रित हैं।",
        "हमारी कंपनी में इंटर्न की भर्ती है। आधिकारिक करियर पोर्टल पर आवेदन करें। कोई शुल्क नहीं है।",
        "आपका मासिक खाता विवरण आधिकारिक ऐप में उपलब्ध है।",
    ),
    (
        "Kannada",
        "ನಾಳೆ ಕಾಲೇಜಿನಲ್ಲಿ ಸಾಂಸ್ಕೃತಿಕ ಕಾರ್ಯಕ್ರಮ ಇದೆ. ಎಲ್ಲ ವಿದ್ಯಾರ್ಥಿಗಳು ಭಾಗವಹಿಸಿ.",
        "ನಮ್ಮ ಕಂಪನಿಯಲ್ಲಿ ಇಂಟರ್ನ್ ನೇಮಕಾತಿ ನಡೆಯುತ್ತಿದೆ. ಅಧಿಕೃತ ವೃತ್ತಿ ಪೋರ್ಟಲ್‌ನಲ್ಲಿ ಅರ್ಜಿ ಸಲ್ಲಿಸಿ. ಯಾವುದೇ ಶುಲ್ಕವಿಲ್ಲ.",
        "ನಿಮ್ಮ ಮಾಸಿಕ ಖಾತೆ ವಿವರ ಅಧಿಕೃತ ಆ್ಯಪ್‌ನಲ್ಲಿ ಲಭ್ಯವಿದೆ.",
    ),
]


@pytest.mark.parametrize(
    "language,college_message,job_message,account_message",
    SAFE_LANGUAGE_CASES,
)
def test_legitimate_messages_remain_low_risk(
    language, college_message, job_message, account_message
):
    for message in (college_message, job_message, account_message):
        result = analyze_message(message, language=language)
        assert result["risk_score"] == 0
        assert result["risk_score"] < 30
        assert result["risk_level"] == "LOW RISK"
        assert result["evidence"] == []


@pytest.mark.parametrize(
    "message",
    [
        "Reminder: the college meeting is on 12 May at 10:30 AM.",
        "The college meeting will be held on 12 May at 10:30 AM.",
    ],
)
def test_harmless_english_date_and_time_are_not_urgency_signals(message):
    result = analyze_message(message, language="English")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW RISK"
    assert result["evidence"] == []


SAFE_DATE_TIME_CASES = [
    ("English", "Reminder: the college meeting is on 12 May at 10:30 AM."),
    ("Hindi", "सूचना: कॉलेज की बैठक 12 मई को सुबह 10:30 बजे है।"),
    ("Kannada", "ಸೂಚನೆ: ಕಾಲೇಜಿನ ಸಭೆ ಮೇ 12 ರಂದು ಬೆಳಿಗ್ಗೆ 10:30ಕ್ಕೆ ಇದೆ."),
]


@pytest.mark.parametrize("language,message", SAFE_DATE_TIME_CASES)
def test_harmless_date_and_time_are_not_urgency_signals(language, message):
    result = analyze_message(message, language=language)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW RISK"
    assert result["evidence"] == []


FIVE_MINUTE_THREATS = [
    ("English", "Your account will be blocked in 5 minutes. Act quickly."),
    ("Hindi", "आपका खाता ५ मिनट में बंद किया जाएगा। जल्दी कार्रवाई करें।"),
    ("Kannada", "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ೫ ನಿಮಿಷಗಳಲ್ಲಿ ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. ಈಗಲೇ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ."),
]


@pytest.mark.parametrize("language,message", FIVE_MINUTE_THREATS)
def test_five_minute_deadline_variations_in_all_languages(language, message):
    result = analyze_message(message, language=language)

    assert {"account_threat", "time_pressure", "urgency"}.issubset(result["detected_categories"])
    assert result["risk_score"] == 52


@pytest.mark.parametrize(
    "language,message",
    [
        ("English", "Urgent: our class starts now; see you in the lecture hall."),
        ("Hindi", "अभी कक्षा शुरू हो रही है, मिलते हैं व्याख्यान कक्ष में।"),
        ("Kannada", "ಈಗಲೇ ತರಗತಿ ಪ್ರಾರಂಭವಾಗುತ್ತದೆ, ಉಪನ್ಯಾಸ ಕೊಠಡಿಯಲ್ಲಿ ಭೇಟಿಯಾಗೋಣ."),
    ],
)
def test_single_ordinary_urgency_phrase_never_creates_high_risk(language, message):
    result = analyze_message(message, language=language)

    assert result["risk_score"] == 10
    assert result["risk_level"] == "LOW RISK"


def test_shortened_url_alone_is_not_high_risk():
    result = analyze_message("The meeting notes are at https://bit.ly/notes")

    assert "suspicious_url" in result["detected_categories"]
    assert result["risk_score"] == 15
    assert result["risk_level"] == "LOW RISK"


def test_punctuation_spacing_and_localized_numerals_are_normalized():
    result = analyze_message(
        "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ೧೦---ನಿಮಿಷಗಳಲ್ಲಿ ಸ್ಥಗಿತಗೊಳಿಸಲಾಗುತ್ತದೆ; ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ!",
        language="Kannada",
    )

    assert {"account_threat", "time_pressure", "urgency"}.issubset(result["detected_categories"])
    assert result["risk_score"] == 52


def test_independent_category_scoring_deduplicates_and_caps():
    evidence = [
        {"category": "urgency", "weight": 10, "reason": "first urgency phrase"},
        {"category": "urgency", "weight": 10, "reason": "overlapping urgency phrase"},
        {"category": "account_threat", "weight": 30, "reason": "account threat"},
        {"category": "sensitive_info", "weight": 30, "reason": "secret request"},
        {"category": "suspicious_url", "weight": 15, "reason": "suspicious URL"},
    ]

    score, _, categories = compute_score(evidence)
    assert score == 85
    assert len(categories) == 4
    assert compute_score(evidence + [{"category": "extra", "weight": 80}])[0] == 100


ADVANCED_UNSEEN_CASES = [
    ("English", "Legitimate bank notification", "Your monthly bank statement is ready in the official app.", "LOW RISK", ()),
    ("Hindi", "Legitimate bank notification", "आपका मासिक बैंक विवरण आधिकारिक ऐप में उपलब्ध है।", "LOW RISK", ()),
    ("Kannada", "Legitimate bank notification", "ನಿಮ್ಮ ಮಾಸಿಕ ಬ್ಯಾಂಕ್ ವಿವರ ಅಧಿಕೃತ ಆ್ಯಪ್‌ನಲ್ಲಿ ಲಭ್ಯವಿದೆ.", "LOW RISK", ()),
    ("English", "Fake government benefit", "Government benefit approved. Pay the processing fee to release your grant.", "MEDIUM RISK", ("government_impersonation", "upfront_payment")),
    ("Hindi", "Fake government benefit", "सरकारी लाभ स्वीकृत। अनुदान पाने के लिए प्रोसेसिंग शुल्क जमा करें।", "MEDIUM RISK", ("government_impersonation", "upfront_payment")),
    ("Kannada", "Fake government benefit", "ಸರ್ಕಾರಿ ಸಹಾಯಧನ ಮಂಜೂರಾಗಿದೆ. ಅನುದಾನ ಪಡೆಯಲು ಪ್ರಕ್ರಿಯೆ ಶುಲ್ಕ ಪಾವತಿಸಿ.", "MEDIUM RISK", ("government_impersonation", "upfront_payment")),
    ("English", "Legitimate job interview", "You are invited to interview for the analyst position on Tuesday.", "LOW RISK", ()),
    ("Hindi", "Legitimate job interview", "विश्लेषक पद के लिए मंगलवार को साक्षात्कार हेतु आमंत्रित हैं।", "LOW RISK", ()),
    ("Kannada", "Legitimate job interview", "ವಿಶ್ಲೇಷಕ ಹುದ್ದೆಗೆ ಮಂಗಳವಾರ ಸಂದರ್ಶನಕ್ಕೆ ನಿಮ್ಮನ್ನು ಆಹ್ವಾನಿಸಲಾಗಿದೆ.", "LOW RISK", ()),
    ("English", "Lottery payment scam", "You won the national lottery. Pay the processing fee to claim your prize.", "MEDIUM RISK", ("reward_scam", "upfront_payment")),
    ("Hindi", "Lottery payment scam", "आपने लॉटरी इनाम जीता है। पुरस्कार पाने के लिए प्रोसेसिंग शुल्क जमा करें।", "MEDIUM RISK", ("reward_scam", "upfront_payment")),
    ("Kannada", "Lottery payment scam", "ನೀವು ಲಾಟರಿ ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ. ಬಹುಮಾನ ಪಡೆಯಲು ಪ್ರಕ್ರಿಯೆ ಶುಲ್ಕ ಪಾವತಿಸಿ.", "MEDIUM RISK", ("reward_scam", "upfront_payment")),
    ("English", "Password theft", "Your mailbox will be locked. Enter your password now at http://192.168.4.10/login", "MEDIUM RISK", ("sensitive_info", "suspicious_url")),
    ("Hindi", "Password theft", "आपका खाता बंद होगा। अपना पासवर्ड बताएं और अभी भेजें।", "HIGH RISK", ("account_threat", "sensitive_info")),
    ("Kannada", "Password theft", "ನಿಮ್ಮ ಖಾತೆ ಮುಚ್ಚಲಾಗುತ್ತದೆ. ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನೀಡಿ ಮತ್ತು ಈಗಲೇ ಕಳುಹಿಸಿ.", "HIGH RISK", ("account_threat", "sensitive_info")),
    ("English", "College announcement", "College registration deadline is today at 5 PM. Submit forms to the office.", "LOW RISK", ()),
    ("Hindi", "College announcement", "कॉलेज आवेदन की अंतिम तारीख आज शाम 5 बजे है। फॉर्म कार्यालय में जमा करें।", "LOW RISK", ()),
    ("Kannada", "College announcement", "ಕಾಲೇಜು ಅರ್ಜಿ ಸಲ್ಲಿಸಲು ಕೊನೆಯ ದಿನ ಇಂದು ಸಂಜೆ 5 ಗಂಟೆ. ಕಚೇರಿಗೆ ಅರ್ಜಿ ಸಲ್ಲಿಸಿ.", "LOW RISK", ()),
    ("English", "Suspicious account verification URL", "Your account needs verification. Continue at https://secure-bank-verify.com/login", "MEDIUM RISK", ("account_verification", "suspicious_url")),
    ("Hindi", "Suspicious account verification URL", "खाता सत्यापन आवश्यक है। जारी रखने के लिए https://secure-bank-verify.com/login खोलें।", "MEDIUM RISK", ("account_verification", "suspicious_url")),
    ("Kannada", "Suspicious account verification URL", "ಖಾತೆ ಪರಿಶೀಲನೆ ಅಗತ್ಯ. ಮುಂದುವರಿಸಲು https://secure-bank-verify.com/login ತೆರೆಯಿರಿ.", "MEDIUM RISK", ("account_verification", "suspicious_url")),
    ("English", "Legitimate urgency", "Urgent: please join the class call now; attendance starts in five minutes.", "LOW RISK", ()),
    ("Hindi", "Legitimate urgency", "तुरंत कक्षा की बैठक में जुड़ें, उपस्थिति पाँच मिनट में शुरू होगी।", "LOW RISK", ()),
    ("Kannada", "Legitimate urgency", "ತಕ್ಷಣ ತರಗತಿ ಕರೆ ಸೇರಿ, ಹಾಜರಾತಿ ಐದು ನಿಮಿಷಗಳಲ್ಲಿ ಆರಂಭವಾಗುತ್ತದೆ.", "LOW RISK", ()),
    ("English", "Normal URL", "Course schedule: https://college.example.edu/schedule", "LOW RISK", ()),
    ("Hindi", "Normal URL", "कक्षा समय-सारणी https://college.example.edu/schedule पर देखें।", "LOW RISK", ()),
    ("Kannada", "Normal URL", "ತರಗತಿ ವೇಳಾಪಟ್ಟಿ https://college.example.edu/schedule ನಲ್ಲಿ ಇದೆ.", "LOW RISK", ()),
    ("English", "Legitimate bank URL", "Your bank statement is ready: https://secure.bank.com/statements.", "LOW RISK", ()),
    ("Hindi", "Legitimate bank URL", "आपका बैंक विवरण देखें: https://secure.bank.com/statements.", "LOW RISK", ()),
    ("Kannada", "Legitimate bank URL", "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ವಿವರ: https://secure.bank.com/statements.", "LOW RISK", ()),
    ("English", "Mixed-language scam", "आपका खाता बंद होगा. Send OTP तुरंत at http://10.1.1.1/verify", "HIGH RISK", ("account_threat", "sensitive_info", "suspicious_url")),
    ("Hindi", "Mixed-language scam", "आपका खाता बंद होगा. Send OTP तुरंत at http://10.1.1.1/verify", "HIGH RISK", ("account_threat", "sensitive_info", "suspicious_url")),
    ("Kannada", "Mixed-language scam", "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. Send OTP ತಕ್ಷಣ at http://10.1.1.1/verify", "HIGH RISK", ("account_threat", "sensitive_info", "suspicious_url")),
    ("English", "Account suspension threat", "Your account will be blocked in 10 minutes. Act quickly.", "MEDIUM RISK", ("account_threat", "time_pressure", "urgency")),
    ("Hindi", "Account suspension threat", "आपका खाता 10 मिनट में बंद किया जाएगा। तुरंत कार्रवाई करें।", "MEDIUM RISK", ("account_threat", "time_pressure", "urgency")),
    ("Kannada", "Account suspension threat", "ನಿಮ್ಮ ಖಾತೆಯನ್ನು 10 ನಿಮಿಷಗಳಲ್ಲಿ ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ.", "MEDIUM RISK", ("account_threat", "time_pressure", "urgency")),
    ("English", "Job registration scam", "Guaranteed job offer. Pay the registration fee to begin.", "MEDIUM RISK", ("job_reward", "upfront_payment")),
    ("Hindi", "Job registration scam", "गारंटीड नौकरी! नौकरी पाने के लिए पंजीकरण शुल्क जमा करें।", "MEDIUM RISK", ("job_reward", "upfront_payment")),
    ("Kannada", "Job registration scam", "ಖಚಿತ ಉದ್ಯೋಗ! ಕೆಲಸ ಪಡೆಯಲು ನೋಂದಣಿ ಶುಲ್ಕ ಪಾವತಿಸಿ.", "MEDIUM RISK", ("job_reward", "upfront_payment")),
    ("English", "OTP theft", "We need your OTP. Share your OTP now to secure your account.", "MEDIUM RISK", ("sensitive_info",)),
    ("Hindi", "OTP theft", "अपना ओटीपी साझा करें और तुरंत भेजें।", "MEDIUM RISK", ("sensitive_info",)),
    ("Kannada", "OTP theft", "ನಿಮ್ಮ ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ ಮತ್ತು ತಕ್ಷಣ ಕಳುಹಿಸಿ.", "MEDIUM RISK", ("sensitive_info",)),
]


@pytest.mark.parametrize(
    "language,category,message,expected_level,expected_categories",
    ADVANCED_UNSEEN_CASES,
)
def test_advanced_unseen_multilingual_corpus(
    language, category, message, expected_level, expected_categories
):
    result = analyze_message(message, language=language)

    assert result["risk_level"] == expected_level, (
        f"{language} / {category}: score={result['risk_score']}, "
        f"categories={result['detected_categories']}"
    )
    assert 0 <= result["risk_score"] <= 100
    assert set(expected_categories).issubset(result["detected_categories"])


def test_evidence_records_detected_language_and_safe_action():
    message = "खाता सत्यापन आवश्यक है। जारी रखने के लिए https://secure-bank-verify.com/login खोलें।"
    result = analyze_message(message, language="English")

    evidence_by_category = {item["category"]: item for item in result["evidence"]}
    assert evidence_by_category["account_verification"]["language"] == "Hindi"
    assert evidence_by_category["account_verification"]["matched_phrase"]
    assert evidence_by_category["account_verification"]["recommended_action"]
    assert evidence_by_category["suspicious_url"]["language"] == "Language-independent"
