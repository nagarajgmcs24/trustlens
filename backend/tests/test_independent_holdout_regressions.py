import pytest

from services.detection_engine import analyze_message


@pytest.mark.parametrize(
    "language,message",
    [
        (
            "English",
            "Read the six digits sent to your phone aloud to the courier.",
        ),
        (
            "Hindi",
            "फोन पर आए छह अंकों का नंबर एजेंट को बताना होगा।",
        ),
        (
            "Kannada",
            "ಫೋನ್‌ಗೆ ಬಂದ ಆರು ಅಂಕಿಗಳನ್ನು ಚಾಲಕನಿಗೆ ಓದಿ ಹೇಳಿ.",
        ),
    ],
)
def test_indirect_requests_for_one_time_codes_are_detected(language, message):
    result = analyze_message(message, language=language)

    assert "sensitive_info" in result["detected_categories"]
    assert result["effective_risk_level"] != "LOW RISK"


@pytest.mark.parametrize(
    "language,message",
    [
        (
            "English",
            "If a message asks for your password, ignore its link and use the official app.",
        ),
        (
            "Kannada",
            "ಅಪರಿಚಿತ ಸಂದೇಶವು ಗುಪ್ತಪದ ಕೇಳಿದರೆ ಅದರ ವಿಳಾಸ ತೆರೆಯಬೇಡಿ; ಅಧಿಕೃತ ಅಪ್ಲಿಕೇಶನ್ ಬಳಸಿ.",
        ),
    ],
)
def test_conditional_credential_safety_advice_stays_low(language, message):
    result = analyze_message(message, language=language)

    assert result["effective_risk_level"] == "LOW RISK"
    assert "sensitive_info" not in result["detected_categories"]


@pytest.mark.parametrize(
    "language,message",
    [
        (
            "Hindi",
            "आपकी सेवा वापसी तैयार है; आज रात इसे पाने के लिए सेवा खर्च भेजें।",
        ),
        (
            "Kannada",
            "ನಿಮ್ಮ ಪಾವತಿ ಮರಳಿಕೆ ಸಿದ್ಧವಾಗಿದೆ; ಅದನ್ನು ಪಡೆಯಲು ಇಂದೇ ಸೇವಾ ವೆಚ್ಚ ವರ್ಗಾಯಿಸಿ.",
        ),
    ],
)
def test_payment_request_with_deadline_is_elevated(language, message):
    result = analyze_message(message, language=language)

    assert result["effective_risk_level"] == "MEDIUM RISK"


def test_job_placement_with_required_purchase_is_elevated():
    result = analyze_message(
        "A factory placement is guaranteed after you buy the required safety badge."
    )

    assert result["effective_risk_level"] != "LOW RISK"
    assert {"job_reward", "upfront_payment"} <= set(result["detected_categories"])


def test_government_benefit_with_fee_is_elevated_in_kannada():
    result = analyze_message(
        "ಪಿಂಚಣಿ ಯೋಜನೆಯ ಹಣ ಮಂಜೂರಾಗಿದೆ; ಬಿಡುಗಡೆಗೆ ಕಡತದ ಶುಲ್ಕ ಕಳುಹಿಸಿ.",
        language="Kannada",
    )

    assert result["effective_risk_level"] != "LOW RISK"
    assert {"government_impersonation", "upfront_payment"} <= set(
        result["detected_categories"]
    )


def test_code_switched_prize_message_with_account_digits_is_elevated():
    result = analyze_message(
        "Shopping drawನಲ್ಲಿ you are a winner; bank account digits text ಮಾಡಿ."
    )

    assert result["effective_risk_level"] != "LOW RISK"
