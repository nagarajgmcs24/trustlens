"""
test_context_engine.py — Context-aware detection tests for TRUSTLENS

Tests all Layer 2 context combination patterns, sender identity analysis,
URL obfuscation improvements, and false-positive scenarios.

These tests do NOT modify nor import from the original test_detection.py.
All existing tests in test_detection.py continue to pass unchanged.
"""

import pytest
from services.detection_engine import analyze_message
from services.context_analyzer import analyze_context, analyze_sender_identity
from services.url_analyzer import analyze_url


# ===========================================================================
# Helper
# ===========================================================================

def _categories(result):
    return set(result["detected_categories"])


def _combos(result):
    return {c["name"] for c in result.get("context_combinations", [])}


def _effective_level(result):
    return result["effective_risk_level"]


def _base_level(result):
    return result["risk_level"]


# ===========================================================================
# LAYER 1 — Legitimate messages must stay LOW RISK
# ===========================================================================

class TestLegitimateMessages:
    @pytest.mark.parametrize("language,message", [
        ("English", "Happy birthday! Hope you have a great day."),
        ("English", "The college annual fest starts next week. All students are invited."),
        ("English", "Your package will be delivered today between 2 PM and 5 PM."),
        ("English", "Meeting rescheduled to Thursday at 3 PM. Please confirm attendance."),
        ("English", "Salary credited to your account. Check the official bank app."),
        ("Hindi", "कल कॉलेज में सांस्कृतिक कार्यक्रम है। सभी आमंत्रित हैं।"),
        ("Hindi", "आपका वेतन आपके खाते में जमा हो गया है।"),
        ("Kannada", "ನಾಳೆ ಕಾಲೇಜಿನಲ್ಲಿ ಹಬ್ಬ ಇದೆ. ಎಲ್ಲರೂ ಬರಬಹುದು."),
        ("Kannada", "ನಿಮ್ಮ ಡಿಲಿವರಿ ಇಂದು ತಲುಪಲಿದೆ."),
    ])
    def test_legitimate_message_stays_low_risk(self, language, message):
        result = analyze_message(message, language=language)
        assert result["risk_score"] == 0, f"Expected 0 score for: {message[:60]}"
        assert _base_level(result) == "LOW RISK"
        assert _effective_level(result) == "LOW RISK"

    def test_legitimate_job_invite_no_fee_is_low_risk(self):
        """A real job interview invite should NOT trigger job_reward."""
        result = analyze_message(
            "You are invited to interview for the software engineer position on Friday. "
            "No payment is required. Please bring your resume."
        )
        assert result["risk_score"] < 30
        assert "job_reward" not in _categories(result)

    def test_bank_statement_notification_is_low_risk(self):
        """A routine bank notification without credential request stays LOW."""
        result = analyze_message(
            "Your monthly bank statement for October is ready. "
            "View it securely in the HDFC Bank official app."
        )
        assert _base_level(result) == "LOW RISK"
        assert "sensitive_info" not in _categories(result)

    def test_otp_received_mention_not_credential_request(self):
        """Mentioning OTP received (not asking to share) should not trigger sensitive_info."""
        result = analyze_message(
            "An OTP has been sent to your registered mobile number for login. "
            "Do not share this OTP with anyone."
        )
        # Phrase 'do not share' should not match sensitive_info because no request context
        assert "sensitive_info" not in _categories(result)


# ===========================================================================
# LAYER 2 — Context combination patterns
# ===========================================================================

class TestContextCombinations:

    def test_otp_plus_account_threat_triggers_credential_theft_cluster(self):
        """OTP request + account threat = credential_theft_cluster combination."""
        result = analyze_message(
            "Your account will be suspended. Share your OTP immediately to restore access.",
            language="English",
        )
        assert "sensitive_info" in _categories(result)
        assert "account_threat" in _categories(result)
        assert "credential_theft_cluster" in _combos(result)
        # context_score should be higher than base risk_score due to bonus
        assert result["context_score"] >= result["risk_score"]
        assert result["context_score"] > 55  # base 60 + 15 combo = would cap at 100

    def test_bank_impersonation_plus_otp_request_triggers_bank_combo(self):
        """KYC + OTP request = bank_impersonation_with_credentials combination."""
        result = analyze_message(
            "Your KYC update is required. Please share your OTP to complete bank verification.",
            language="English",
        )
        assert "financial_impersonation" in _categories(result)
        assert "sensitive_info" in _categories(result)
        assert "bank_impersonation_with_credentials" in _combos(result)

    def test_job_lure_plus_registration_fee_triggers_job_payment_scam(self):
        """Guaranteed job + registration fee = job_payment_scam combination."""
        result = analyze_message(
            "Guaranteed job offer available. Pay the registration fee of Rs 500 to begin.",
            language="English",
        )
        assert "job_reward" in _categories(result)
        assert "upfront_payment" in _categories(result)
        assert "job_payment_scam" in _combos(result)

    def test_prize_plus_payment_triggers_prize_payment_scam(self):
        """Prize claim + payment = prize_payment_scam combination."""
        result = analyze_message(
            "You have won a prize! Pay the processing fee to claim your reward.",
            language="English",
        )
        assert "reward_scam" in _categories(result)
        assert "upfront_payment" in _categories(result)
        assert "prize_payment_scam" in _combos(result)

    def test_prize_plus_shortened_url_triggers_combo(self):
        """Prize + shortened URL = prize_shortener_scam combination."""
        result = analyze_message(
            "You have won a prize! Claim your reward at https://bit.ly/claim123",
            language="English",
        )
        assert "prize_shortener_scam" in _combos(result)

    def test_government_plus_payment_triggers_gov_impersonation_combo(self):
        """Government benefit + processing fee = government_impersonation_with_payment."""
        result = analyze_message(
            "Government benefit approved! Pay the processing fee to release your grant.",
            language="English",
        )
        assert "government_impersonation" in _categories(result)
        assert "upfront_payment" in _categories(result)
        assert "government_impersonation_with_payment" in _combos(result)

    def test_triple_pressure_attack_detected(self):
        """Account threat + time pressure + OTP request = triple_pressure_attack."""
        result = analyze_message(
            "Your account will be blocked in 5 minutes. Share your OTP immediately to prevent this.",
            language="English",
        )
        assert "triple_pressure_attack" in _combos(result)
        # context_score should be significantly elevated
        assert result["context_score"] > result["risk_score"]

    def test_account_suspension_verification_url_cluster(self):
        """Account threat + verification + suspicious URL = three-signal phishing cluster."""
        result = analyze_message(
            "Your account needs verification or it will be blocked. "
            "Continue at https://secure-bank-verify.net/login",
            language="English",
        )
        assert "account_threat" in _categories(result) or "account_verification" in _categories(result)
        assert "suspicious_url" in _categories(result)

    def test_urgency_alone_does_not_trigger_combination(self):
        """Single urgency signal without other categories must not trigger any combination."""
        result = analyze_message("Please join the urgent meeting now.", language="English")
        assert _combos(result) == set()
        # urgency alone stays LOW since no independent signals
        assert result["risk_score"] <= 10

    def test_combination_narrative_appears_in_explanations(self):
        """When a combination fires, its narrative should appear in explanations."""
        result = analyze_message(
            "Your account will be suspended. Share your OTP now to restore it.",
            language="English",
        )
        has_narrative = any("credential" in exp.lower() or "otp" in exp.lower() or "account" in exp.lower()
                            for exp in result["explanations"])
        assert has_narrative

    # --- Hindi combinations ---
    def test_hindi_credential_theft_cluster(self):
        result = analyze_message(
            "आपका खाता बंद किया जाएगा। अभी अपना ओटीपी साझा करें।",
            language="Hindi",
        )
        assert "account_threat" in _categories(result)
        assert "sensitive_info" in _categories(result)
        assert "credential_theft_cluster" in _combos(result)

    def test_hindi_job_payment_scam_combination(self):
        result = analyze_message(
            "गारंटीड नौकरी मिलेगी! नौकरी पाने के लिए पंजीकरण शुल्क जमा करें।",
            language="Hindi",
        )
        assert "job_payment_scam" in _combos(result)

    # --- Kannada combinations ---
    def test_kannada_credential_theft_cluster(self):
        result = analyze_message(
            "ನಿಮ್ಮ ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. ತಕ್ಷಣ ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ.",
            language="Kannada",
        )
        assert "account_threat" in _categories(result)
        assert "sensitive_info" in _categories(result)
        assert "credential_theft_cluster" in _combos(result)

    def test_kannada_prize_shortener_combination(self):
        result = analyze_message(
            "ನೀವು ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ! https://bit.ly/prize ನಲ್ಲಿ ಪಡೆಯಿರಿ.",
            language="Kannada",
        )
        assert "prize_shortener_scam" in _combos(result)


# ===========================================================================
# LAYER 1 — Sender Identity Analysis
# ===========================================================================

class TestSenderIdentityAnalysis:

    def test_bank_claim_with_mismatched_email_domain_flagged(self):
        """Bank impersonation: message claims to be from HDFC but email is gmail."""
        result = analyze_message(
            "Your HDFC Bank KYC update is required. Click the link to verify.",
            sender_name="HDFC Bank Support",
            sender_email="hdfc.support@gmail.com",
            language="English",
        )
        sender_info = result["sender_analysis"]
        assert sender_info["is_suspicious"]
        assert "bank_domain_mismatch" in sender_info["indicators"]
        assert sender_info["bonus"] > 0
        assert result["context_score"] > result["risk_score"]

    def test_legitimate_bank_email_domain_not_flagged(self):
        """Real bank sender domain should NOT trigger domain mismatch."""
        result = analyze_message(
            "Your HDFC Bank account statement is ready.",
            sender_email="statements@hdfcbank.com",
            language="English",
        )
        sender_info = result["sender_analysis"]
        assert "bank_domain_mismatch" not in sender_info["indicators"]

    def test_government_claim_with_non_gov_domain_is_suspicious(self):
        """Government benefit message from a non-.gov.in domain is suspicious."""
        result = analyze_message(
            "Government subsidy has been approved for your account. Verify now.",
            sender_email="scheme@govt-subsidy-india.com",
            language="English",
        )
        sender_info = result["sender_analysis"]
        assert "gov_domain_mismatch" in sender_info["indicators"]

    def test_missing_sender_info_does_not_add_risk(self):
        """Missing sender details alone are not evidence of impersonation."""
        result = analyze_message(
            "Bank verification required. Update your KYC immediately.",
            sender_name=None,
            sender_email=None,
            language="English",
        )
        sender_info = result["sender_analysis"]
        assert "missing_sender_provenance" not in sender_info["indicators"]
        assert sender_info["bonus"] == 0
        assert result["context_score"] == result["risk_score"]

    def test_no_email_no_suspicious_claim_no_sender_flag(self):
        """Message with no impersonation claim and no sender info = no sender flag."""
        result = analyze_message(
            "Happy birthday! Hope you have a wonderful day.",
            sender_name=None,
            sender_email=None,
            language="English",
        )
        sender_info = result["sender_analysis"]
        assert not sender_info["is_suspicious"]

    def test_analyze_sender_identity_unit_bank_mismatch(self):
        """Unit test for analyze_sender_identity with bank + non-bank domain."""
        sa = analyze_sender_identity(
            message="SBI Bank account verification required",
            sender_name=None,
            sender_email="support@totallynotbank.ru",
            detected_categories={"financial_impersonation"},
        )
        assert sa["is_suspicious"]
        assert "bank_domain_mismatch" in sa["indicators"]
        assert sa["bonus"] > 0

    def test_analyze_sender_identity_unit_sbi_domain_ok(self):
        """Unit test: sbi.co.in domain should be considered legitimate."""
        sa = analyze_sender_identity(
            message="Your SBI account statement is ready.",
            sender_name="SBI Customer Service",
            sender_email="service@sbi.co.in",
            detected_categories=set(),
        )
        assert "bank_domain_mismatch" not in sa["indicators"]


# ===========================================================================
# LAYER 3 — Risk Classification correctness
# ===========================================================================

class TestRiskClassification:

    def test_multiple_strong_signals_reach_high_context_risk(self):
        """OTP + account threat + time pressure should together reach HIGH effective risk."""
        result = analyze_message(
            "Your bank account will be blocked in 5 minutes. "
            "Share your OTP and password immediately to prevent permanent suspension.",
            language="English",
        )
        assert _effective_level(result) == "HIGH RISK"

    def test_single_otp_request_alone_not_automatically_high(self):
        """OTP request alone should be MEDIUM, not automatically HIGH."""
        result = analyze_message(
            "We need your OTP. Share your OTP now to secure your account.",
            language="English",
        )
        # base risk_level should be MEDIUM (score 30 per existing tests)
        assert _base_level(result) == "MEDIUM RISK"
        # effective level MAY be MEDIUM or HIGH based on combinations, but base stays MEDIUM

    def test_single_shortened_url_alone_is_low_risk(self):
        """A shortened URL by itself must remain LOW RISK (score 15)."""
        result = analyze_message("The meeting notes are at https://bit.ly/notes")
        assert result["risk_score"] == 15
        assert _base_level(result) == "LOW RISK"
        assert _combos(result) == set()

    def test_job_ad_without_fee_is_low_risk(self):
        """A normal job advertisement without a fee request must be LOW RISK."""
        result = analyze_message(
            "Hiring software engineers for our Bengaluru office. "
            "Apply online at careers.company.com. No fee required.",
            language="English",
        )
        assert _base_level(result) == "LOW RISK"

    def test_urgency_phrase_in_college_context_is_low_risk(self):
        """Urgency word in a class-attendance context must stay LOW RISK."""
        result = analyze_message(
            "Urgent: please join the class call now; attendance starts in five minutes.",
            language="English",
        )
        assert result["risk_score"] == 10
        assert _base_level(result) == "LOW RISK"

    def test_prize_plus_shortened_url_is_medium_not_low(self):
        """Prize with shortened URL should be at least MEDIUM risk."""
        result = analyze_message(
            "You have won a prize! Claim your reward at https://bit.ly/claim",
            language="English",
        )
        assert result["risk_score"] >= 30
        # context_score should be at least MEDIUM
        assert result["context_score"] >= 30


# ===========================================================================
# LAYER 4 — Explainability output fields
# ===========================================================================

class TestExplainabilityOutput:

    def test_signal_summary_populated_for_suspicious_message(self):
        """signal_summary should list each category and any combo bonuses."""
        result = analyze_message(
            "Your account will be suspended. Share your OTP immediately.",
            language="English",
        )
        assert isinstance(result["signal_summary"], list)
        assert len(result["signal_summary"]) > 0
        # Should contain category names
        summary_text = " ".join(result["signal_summary"])
        assert "account_threat" in summary_text or "sensitive_info" in summary_text

    def test_context_combinations_field_is_list(self):
        result = analyze_message("Happy birthday!", language="English")
        assert isinstance(result["context_combinations"], list)

    def test_context_narratives_field_is_list(self):
        result = analyze_message("Happy birthday!", language="English")
        assert isinstance(result["context_narratives"], list)

    def test_sender_analysis_field_present(self):
        result = analyze_message("Test message for field check.", language="English")
        sa = result["sender_analysis"]
        assert "is_suspicious" in sa
        assert "indicators" in sa
        assert "bonus" in sa
        assert "reasons" in sa

    def test_context_score_field_present_and_gte_base(self):
        result = analyze_message(
            "Your account will be blocked. Share your OTP.",
            language="English",
        )
        assert "context_score" in result
        assert result["context_score"] >= result["risk_score"]

    def test_effective_risk_level_field_present(self):
        result = analyze_message("Test message.", language="English")
        assert "effective_risk_level" in result
        assert result["effective_risk_level"] in {"LOW RISK", "MEDIUM RISK", "HIGH RISK"}

    def test_evidence_has_explanation_and_action_fields(self):
        result = analyze_message(
            "Your account will be blocked today. Verify your KYC immediately.",
            language="English",
        )
        for item in result["evidence"]:
            assert "explanation" in item
            assert "recommended_action" in item
            assert "category" in item
            assert "matched_phrase" in item

    def test_combo_narrative_in_explanations_for_triple_pressure(self):
        """Triple-pressure combo narrative must appear in explanations."""
        result = analyze_message(
            "Your account will be blocked in 5 minutes. Share your OTP immediately.",
            language="English",
        )
        combined_text = " ".join(result["explanations"]).lower()
        # Narrative from triple_pressure_attack should reference credential
        assert "credential" in combined_text or "triple" in combined_text or "pressure" in combined_text


# ===========================================================================
# LAYER 5 — Multilingual context combinations
# ===========================================================================

class TestMultilingualContextCombinations:

    @pytest.mark.parametrize("language,message", [
        (
            "English",
            "Government subsidy approved. Pay the processing fee to release the grant.",
        ),
        (
            "Hindi",
            "सरकारी लाभ स्वीकृत। अनुदान पाने के लिए प्रोसेसिंग शुल्क जमा करें।",
        ),
        (
            "Kannada",
            "ಸರ್ಕಾರಿ ಸಹಾಯಧನ ಮಂಜೂರಾಗಿದೆ. ಬಹುಮಾನ ಪಡೆಯಲು ಪ್ರಕ್ರಿಯೆ ಶುಲ್ಕ ಪಾವತಿಸಿ.",
        ),
    ])
    def test_government_payment_scam_detected_in_all_languages(self, language, message):
        result = analyze_message(message, language=language)
        assert "government_impersonation" in _categories(result), \
            f"{language}: government_impersonation not in {result['detected_categories']}"
        assert "upfront_payment" in _categories(result), \
            f"{language}: upfront_payment not in {result['detected_categories']}"
        assert "government_impersonation_with_payment" in _combos(result), \
            f"{language}: combo not fired"

    @pytest.mark.parametrize("language,message", [
        (
            "English",
            "Guaranteed job! Pay the registration fee to begin work from home.",
        ),
        (
            "Hindi",
            "गारंटीड नौकरी! घर से काम करने के लिए पंजीकरण शुल्क जमा करें।",
        ),
        (
            "Kannada",
            "ಖಚಿತ ಉದ್ಯೋಗ! ಮನೆಯಿಂದ ಕೆಲಸ ಮಾಡಲು ನೋಂದಣಿ ಶುಲ್ಕ ಪಾವತಿಸಿ.",
        ),
    ])
    def test_job_payment_scam_detected_in_all_languages(self, language, message):
        result = analyze_message(message, language=language)
        assert "job_reward" in _categories(result)
        assert "upfront_payment" in _categories(result)
        assert "job_payment_scam" in _combos(result)

    @pytest.mark.parametrize("language,message", [
        (
            "English",
            "You have won a prize! Claim your reward at https://bit.ly/claim",
        ),
        (
            "Hindi",
            "आपने इनाम जीता है! https://bit.ly/claim पर अपना उपहार प्राप्त करें।",
        ),
        (
            "Kannada",
            "ನೀವು ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ! https://bit.ly/claim ನಲ್ಲಿ ಪಡೆಯಿರಿ.",
        ),
    ])
    def test_prize_shortener_combination_in_all_languages(self, language, message):
        result = analyze_message(message, language=language)
        assert "reward_scam" in _categories(result)
        assert "suspicious_url" in _categories(result)
        assert "prize_shortener_scam" in _combos(result)

    @pytest.mark.parametrize("language,message", [
        ("English", "आपका खाता बंद होगा. Share your OTP तुरंत at http://10.1.1.1/verify"),
        ("Hindi", "आपका खाता बंद होगा. Share OTP तुरंत at http://10.1.1.1/verify"),
        ("Kannada", "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. Send OTP ತಕ್ಷಣ at http://10.1.1.1/verify"),
    ])
    def test_mixed_language_triple_signal_is_high_risk(self, language, message):
        """Mixed-language messages with three signals should hit HIGH effective risk."""
        result = analyze_message(message, language=language)
        assert _effective_level(result) == "HIGH RISK"
        assert "sensitive_info" in _categories(result)
        assert "account_threat" in _categories(result)
        assert "suspicious_url" in _categories(result)


# ===========================================================================
# LAYER 6 — URL obfuscation improvements
# ===========================================================================

class TestUrlObfuscation:

    def test_homograph_punycode_domain_is_suspicious(self):
        """Punycode-encoded domains should be flagged as suspicious."""
        result_url = analyze_url("https://xn--hdfc-bank-0ub.com/login")
        assert result_url["is_suspicious"]
        assert any("punycode" in r.lower() or "homograph" in r.lower() for r in result_url["reasons"])

    def test_excessive_subdomain_depth_is_suspicious(self):
        """A URL with 3+ subdomains should trigger the obfuscation flag."""
        result_url = analyze_url("https://a.b.c.evil.com/login")
        assert result_url["is_suspicious"]
        assert any("subdomain" in r.lower() for r in result_url["reasons"])

    def test_numeric_heavy_domain_is_suspicious(self):
        """A domain like 1234567890.com should be flagged."""
        result_url = analyze_url("https://1234567890.com/verify")
        assert result_url["is_suspicious"]
        assert any("numeric" in r.lower() for r in result_url["reasons"])

    def test_expanded_shortener_rb_gy_is_detected(self):
        """rb.gy is in the expanded shortener list and should be flagged."""
        result_url = analyze_url("https://rb.gy/abcdef")
        assert result_url["is_suspicious"]
        assert any("shortener" in r.lower() for r in result_url["reasons"])

    def test_normal_https_url_not_suspicious(self):
        """Normal HTTPS URL with no red flags should NOT be flagged."""
        result_url = analyze_url("https://college.example.edu/schedule")
        assert not result_url["is_suspicious"]

    def test_ip_address_destination_still_detected(self):
        """IP-address URL detection must still work after refactor."""
        result_url = analyze_url("http://192.168.1.1/login")
        assert result_url["is_suspicious"]
        assert any("IP address" in r for r in result_url["reasons"])

    def test_shortener_boundary_not_false_positive(self):
        """notbit.ly.example.org must NOT be flagged as a bit.ly shortener."""
        result = analyze_message("Visit https://notbit.ly.example.org/page when convenient.")
        assert result["suspicious_urls"] == []

    @pytest.mark.parametrize("url", [
        "https://rb.gy/abcd",
        "https://ouo.io/xyz",
        "https://za.gl/test",
        "https://snip.ly/page",
        "https://shorturl.at/qrs",
    ])
    def test_expanded_shorteners_are_detected(self, url):
        result = analyze_message(f"Check this: {url}")
        assert result["suspicious_urls"], f"Expected {url} to be detected as suspicious"


# ===========================================================================
# FALSE-POSITIVE PREVENTION
# ===========================================================================

class TestFalsePositivePrevention:

    def test_bank_mention_without_request_or_threat_is_low_risk(self):
        """Mentioning a bank (e.g. HDFC) in a statement context should not trigger high risk."""
        result = analyze_message(
            "Your HDFC Bank account statement for September is now available in the app.",
            language="English",
        )
        # Should not contain sensitive_info or account_threat
        assert "sensitive_info" not in _categories(result)
        assert "account_threat" not in _categories(result)
        assert _base_level(result) == "LOW RISK"

    def test_government_scheme_advertisement_is_low_risk(self):
        """A neutral mention of a government scheme (no fee/threat) should be low risk."""
        result = analyze_message(
            "The government has launched a new scholarship scheme for students. "
            "Apply at the official university portal.",
            language="English",
        )
        # government_impersonation may fire but without upfront_payment it should be low
        if "government_impersonation" in _categories(result):
            assert "upfront_payment" not in _categories(result)
        assert _base_level(result) in {"LOW RISK", "MEDIUM RISK"}

    def test_prize_without_payment_or_url_is_medium_not_high(self):
        """Prize message without a payment request or URL should be MEDIUM at most."""
        result = analyze_message(
            "You have won a prize in the office raffle! Collect it from HR.",
            language="English",
        )
        # No upfront_payment, no suspicious_url → no prize_payment_scam or prize_shortener_scam combo
        assert "prize_payment_scam" not in _combos(result)
        assert "prize_shortener_scam" not in _combos(result)

    def test_college_deadline_today_not_urgency_threat(self):
        """'Today' deadline in college context must NOT create urgency risk."""
        result = analyze_message(
            "College registration deadline is today at 5 PM. Submit forms to the office.",
            language="English",
        )
        assert result["risk_score"] == 0
        assert _base_level(result) == "LOW RISK"

    def test_otp_warning_not_sharing_is_low_risk(self):
        """A message cautioning users about OTP safety (without a request phrase) is low risk.

        Note: The phrase-based engine does not understand negation, so messages containing
        'share your OTP' (even prefixed by 'NEVER') will still trigger sensitive_info.
        This test uses phrasing that does NOT contain any sensitive_info trigger phrases.
        """
        result = analyze_message(
            "Security alert: An OTP was sent to your registered number. "
            "Protect this code. Do not disclose it to anyone, including support staff.",
            language="English",
        )
        # 'disclose' is not in the sensitive_info phrase list, so no match is expected
        assert "sensitive_info" not in _categories(result)

    def test_every_job_ad_not_automatically_high(self):
        """A regular job advertisement must not be HIGH RISK."""
        result = analyze_message(
            "We are hiring! Remote job opportunity for freshers. "
            "Strong communication skills required. Apply by Friday.",
            language="English",
        )
        assert _effective_level(result) != "HIGH RISK"

    def test_hr_email_with_joining_date_is_low_risk(self):
        """An HR joining date message must not be flagged.

        Note: Messages containing 'advance payment' or 'payment required' will trigger
        upfront_payment / payment_request categories even in a negation context ('No payment
        required') because the phrase matcher does not understand negation. This test uses
        phrasing that avoids those trigger phrases entirely.
        """
        result = analyze_message(
            "Congratulations! Your joining date is confirmed for 15 November. "
            "Please report to HR at 9 AM. No documents or fees are needed before joining.",
            language="English",
        )
        assert _base_level(result) == "LOW RISK"


# ===========================================================================
# analyze_context unit tests
# ===========================================================================

class TestAnalyzeContextUnit:

    def test_empty_categories_no_combinations(self):
        ctx = analyze_context([], "test message", None, None)
        assert ctx["combinations"] == []
        assert ctx["context_bonus"] == 0

    def test_single_category_no_combination(self):
        ctx = analyze_context(["urgency"], "urgent test", None, None)
        assert ctx["combinations"] == []

    def test_two_required_categories_fires_combo(self):
        ctx = analyze_context(
            ["sensitive_info", "account_threat"],
            "account blocked share OTP",
            None, None,
        )
        names = {c["name"] for c in ctx["combinations"]}
        assert "credential_theft_cluster" in names

    def test_context_bonus_is_non_negative(self):
        ctx = analyze_context(["urgency"], "urgent", None, None)
        assert ctx["context_bonus"] >= 0

    def test_superset_categories_fires_multiple_combos(self):
        """account_threat + sensitive_info + urgency fires both single and triple combos."""
        ctx = analyze_context(
            ["account_threat", "sensitive_info", "urgency", "time_pressure"],
            "account blocked share OTP in 5 mins",
            None, None,
        )
        names = {c["name"] for c in ctx["combinations"]}
        assert "credential_theft_cluster" in names
        assert "high_pressure_credential_theft" in names
        assert "triple_pressure_attack" in names


class TestContextualMultilingualEvaluation:

    @pytest.mark.parametrize("language,message", [
        (
            "English",
            "Your account will be blocked in 10 minutes. Share your OTP immediately.",
        ),
        (
            "Hindi",
            "आपका खाता 10 मिनट में बंद कर दिया जाएगा। तुरंत अपना ओटीपी भेजें।",
        ),
        (
            "Kannada",
            "ನಿಮ್ಮ ಖಾತೆಯನ್ನು 10 ನಿಮಿಷಗಳಲ್ಲಿ ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ. ತಕ್ಷಣ ನಿಮ್ಮ ಓಟಿಪಿ ಕಳುಹಿಸಿ.",
        ),
    ])
    def test_account_threat_time_pressure_and_credential_request(self, language, message):
        result = analyze_message(message, language=language)

        assert {"account_threat", "time_pressure", "sensitive_info"} <= _categories(result)
        assert result["effective_risk_score"] == 97
        assert result["effective_risk_level"] == "HIGH RISK"
        assert sum(
            item["points_contributed"]
            for item in result["context_combinations"]
        ) == 15
        assert any(
            item["language"] == language
            for item in result["evidence"]
            if item["category"] in {"account_threat", "sensitive_info"}
        )

    @pytest.mark.parametrize("language,message", [
        ("English", "Guaranteed job! Pay the registration fee before starting."),
        ("Hindi", "गारंटीड नौकरी! काम शुरू करने से पहले पंजीकरण शुल्क जमा करें।"),
        ("Kannada", "ಖಚಿತ ಉದ್ಯೋಗ! ಕೆಲಸ ಆರಂಭಿಸುವ ಮೊದಲು ನೋಂದಣಿ ಶುಲ್ಕ ಪಾವತಿಸಿ."),
    ])
    def test_job_lure_and_registration_fee_combine(self, language, message):
        result = analyze_message(message, language=language)

        assert {"job_reward", "upfront_payment"} <= _categories(result)
        assert "job_payment_scam" in _combos(result)
        assert result["effective_risk_score"] >= result["risk_score"]

    @pytest.mark.parametrize("language,message", [
        ("English", "Please share your OTP to complete the verification."),
        ("Hindi", "अपना ओटीपी साझा करें।"),
        ("Kannada", "ನಿಮ್ಮ ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ."),
    ])
    def test_direct_otp_request_detected(self, language, message):
        result = analyze_message(message, language=language)

        assert "sensitive_info" in _categories(result)
        assert any(
            item["category"] == "sensitive_info" and item["language"] == language
            for item in result["evidence"]
        )

    @pytest.mark.parametrize("language,message", [
        ("English", "You have won a prize! Claim your reward at https://bit.ly/claim"),
        ("Hindi", "आपने इनाम जीता है! https://bit.ly/claim पर अपना उपहार प्राप्त करें।"),
        ("Kannada", "ನೀವು ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ! https://bit.ly/claim ನಲ್ಲಿ ನಿಮ್ಮ ಉಡುಗೊರೆ ಪಡೆಯಿರಿ."),
    ])
    def test_prize_claim_and_shortened_url_combine(self, language, message):
        result = analyze_message(message, language=language)

        assert {"reward_scam", "suspicious_url"} <= _categories(result)
        assert "prize_shortener_scam" in _combos(result)

    @pytest.mark.parametrize("language,message", [
        ("English", "Security reminder: Never share your OTP with anyone."),
        ("Hindi", "सुरक्षा सूचना: कभी नहीं अपना ओटीपी साझा करें।"),
        (
            "Kannada",
            "ಸುರಕ್ಷತಾ ಸೂಚನೆ: ನಿಮ್ಮ ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ ಎಂದು ಎಂದಿಗೂ ಹೇಳುವುದಿಲ್ಲ.",
        ),
    ])
    def test_negated_credential_request_is_not_flagged(self, language, message):
        result = analyze_message(message, language=language)

        assert "sensitive_info" not in _categories(result)
        assert result["risk_score"] == 0
        assert result["risk_level"] == "LOW RISK"

    @pytest.mark.parametrize("language,message", [
        ("English", "No registration fee is required for this position."),
        ("Hindi", "नौकरी के लिए कोई पंजीकरण शुल्क नहीं देना होगा।"),
        ("Kannada", "ನೋಂದಣಿ ಶುಲ್ಕ ಪಾವತಿಸುವ ಅಗತ್ಯವಿಲ್ಲ."),
    ])
    def test_negated_fee_request_is_not_flagged(self, language, message):
        result = analyze_message(message, language=language)

        assert "upfront_payment" not in _categories(result)
        assert result["risk_score"] == 0
        assert result["risk_level"] == "LOW RISK"

    @pytest.mark.parametrize("language,message", [
        ("English", "Your HDFC Bank account statement is ready."),
        ("Hindi", "आपके HDFC बैंक खाते का विवरण तैयार है।"),
        ("Kannada", "ನಿಮ್ಮ HDFC ಬ್ಯಾಂಕ್ ಖಾತೆಯ ವಿವರ ಸಿದ್ಧವಾಗಿದೆ."),
    ])
    def test_claimed_organization_domain_mismatch_is_reported(self, language, message):
        result = analyze_message(
            message,
            language=language,
            claimed_organization="HDFC Bank",
            sender_email="support@sbi.co.in",
        )

        assert "bank_domain_mismatch" in result["sender_analysis"]["indicators"]
        assert result["risk_score"] == 0
        assert result["effective_risk_score"] == 10

    def test_matching_claimed_bank_domain_is_not_flagged(self):
        result = analyze_message(
            "Your HDFC Bank statement is available.",
            claimed_organization="HDFC Bank",
            sender_email="statements@hdfcbank.com",
        )

        assert "bank_domain_mismatch" not in result["sender_analysis"]["indicators"]
        assert result["effective_risk_score"] == 0

    def test_api_request_accepts_claimed_organization_and_stores_effective_history(self, monkeypatch):
        from routes import analysis as analysis_routes
        from models.schemas import AnalysisRequest
        import asyncio

        saved_records = []
        monkeypatch.setattr(analysis_routes, "save_history_record", saved_records.append)
        payload = AnalysisRequest(
            message="Your HDFC Bank account will be blocked. Share your OTP immediately.",
            claimed_organization="HDFC Bank",
            sender_email="support@gmail.com",
        )
        result = asyncio.run(analysis_routes.analyze_message_endpoint(payload))

        assert result["claimed_organization"] == "HDFC Bank"
        assert result["effective_risk_level"] == "HIGH RISK"
        assert saved_records[0]["risk_level"] == result["effective_risk_level"]
        assert saved_records[0]["risk_score"] == result["effective_risk_score"]
        assert "message" not in saved_records[0]
        assert "sender_email" not in saved_records[0]
