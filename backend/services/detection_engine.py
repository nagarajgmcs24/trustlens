import re
import unicodedata
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from services.context_analyzer import analyze_context
from services.risk_scorer import CATEGORY_WEIGHTS, classify_risk, compute_score
from services.url_analyzer import analyze_url, extract_urls

LANGUAGE_SUPPORT = {
    "English": "English phrase rules are enabled; limited Hindi and Kannada phrases are also checked for mixed-language text. This is not full language detection and coverage is not comprehensive.",
    "Hindi": "Hindi and English phrase rules are enabled; Kannada phrases are also checked for mixed-language text. Hindi/Kannada coverage is limited and no automatic language detection is performed.",
    "Kannada": "Kannada and English phrase rules are enabled; Hindi phrases are also checked for mixed-language text. Hindi/Kannada coverage is limited and no automatic language detection is performed.",
}

RULES: dict[str, dict[str, dict[str, Any]]] = {
    "English": {
        "account_threat": {
            "phrases": (
                "account will be blocked",
                "account will be suspended",
                "account has been suspended",
                "account has been blocked",
                "account will be permanently suspended",
                "account will be permanently blocked",
                "account is permanently suspended",
                "your account will be blocked soon",
                "your account will be suspended soon",
                "your account will be disabled",
                "account access will be revoked",
                "account will be terminated",
            ),
            "explanation": "A threat to block, suspend, or disable an account can pressure the recipient into unsafe action.",
            "action": "Do not use links or contact details in the message; verify account status through the organization’s official app or website.",
        },
        "urgency": {
            "phrases": (
                "immediately",
                "immediate action",
                "take immediate action",
                "urgent",
                "urgent action required",
                "right now",
                "act quickly",
                "act fast",
                "last chance",
                "last warning",
                "act now",
                "within 24 hours",
                "before 24 hours",
            ),
            "contextual_phrases": ("today", "before midnight"),
            "explanation": "Urgent or deadline-driven wording can be used to discourage careful verification.",
            "action": "Pause and verify the request independently before acting.",
        },
        "time_pressure": {
            "regexes": (),
            "phrases": (
                "within five minutes",
                "within ten minutes",
                "in five minutes",
                "in ten minutes",
            ),
            "explanation": "A short, specific deadline is a time-pressure signal, especially when paired with a threat or request.",
            "action": "Do not rush; confirm the claim using a known official contact method.",
        },
        "sensitive_info": {
            "phrases": (
                "share your otp",
                "share otp",
                "send your otp",
                "send otp",
                "send us your otp",
                "we need your otp",
                "enter your otp",
                "enter otp",
                "reply with your otp",
                "reply with the code",
                "provide your otp",
                "share your password",
                "update your password",
                "enter your password",
                "provide your password",
                "share your pin",
                "provide your pin",
                "share your cvv",
                "provide your cvv",
                "share your bank details",
                "send your bank details",
                "verify your bank details",
                "share your account number",
                "send your account number",
                "verify your bank account",
            ),
            "explanation": "The message asks the recipient to disclose or enter a one-time code, password, or banking secret.",
            "action": "Never share OTPs, passwords, PINs, CVVs, or full banking details in response to a message.",
        },
        "financial_impersonation": {
            "phrases": (
                "bank verification",
                "kyc update",
                "update your kyc",
                "verify your kyc",
                "kyc verification",
                "payment failure",
                "refund processing",
                "account reactivation",
                "verify your bank account",
            ),
            "explanation": "A bank, payment, refund, or KYC claim may be impersonating a financial institution.",
            "action": "Check the claim in the official banking app or by calling the number printed on your card.",
        },
        "account_verification": {
            "phrases": (
                "account verification required",
                "account needs verification",
                "verify your account to continue",
                "account must be verified",
            ),
            "explanation": "An unsolicited account-verification request can lead to credential theft, especially when paired with a link.",
            "action": "Do not follow the message link; check the account using its known official app or website.",
        },
        "government_impersonation": {
            "phrases": (
                "government subsidy",
                "government grant",
                "tax refund",
                "official verification",
                "government notice",
                "department verification",
                "government benefit",
                "government benefit approved",
            ),
            "explanation": "A government benefit or verification claim can be used to impersonate a public agency.",
            "action": "Verify benefits or notices on the agency’s official website; do not pay an unsolicited processing fee.",
        },
        "job_reward": {
            "phrases": (
                "guaranteed job",
                "guaranteed employment",
                "work from home income",
                "remote job offer",
                "job offer with no experience",
                "easy money",
            ),
            "explanation": "Unusually guaranteed work or income is a common lure in job scams.",
            "action": "Research the employer independently and do not pay to secure a job.",
        },
        "upfront_payment": {
            "phrases": (
                "registration fee",
                "pay the registration fee",
                "pay a registration fee",
                "processing fee",
                "pay the processing fee",
                "advance payment",
                "pay an advance",
                "make a deposit",
                "pay to start",
            ),
            "explanation": "An upfront fee or deposit is requested before a promised service, job, prize, or benefit.",
            "action": "Do not send money to claim an offer; verify the organization through independent channels.",
        },
        "reward_scam": {
            "phrases": (
                "you have won a prize",
                "you won a prize",
                "prize winner",
                "claim your reward",
                "claim your gift",
                "free gift",
                "lottery reward",
                "national lottery",
                "lottery winner",
                "claim your lottery winnings",
                "processing fee to claim",
                "winner notification",
            ),
            "explanation": "An unsolicited prize, reward, or gift claim may be bait to collect money or personal information.",
            "action": "Do not pay a fee or provide personal information to claim an unexpected prize.",
        },
        "payment_request": {
            "phrases": (
                "send payment",
                "pay now",
                "transfer the money",
                "send money",
                "payment required",
                "transfer fee",
            ),
            "explanation": "The message asks the recipient to transfer money or make a payment.",
            "action": "Confirm any payment request directly with the intended recipient using a trusted contact method.",
        },
    },
    "Hindi": {
        "account_threat": {
            "phrases": (
                "खाता बंद किया जाएगा",
                "खाता बंद कर दिया जाएगा",
                "खाता बंद होगा",
                "खाता निलंबित कर दिया जाएगा",
                "खाता जल्द ही बंद कर दिया जाएगा",
                "आपका खाता जल्द ही बंद कर दिया जाएगा",
                "बैंक खाता बंद",
                "खाता अवरुद्ध कर दिया जाएगा",
            ),
            "regexes": (
                r"(?<!\w)(?:आपका\s+)?खाता.{0,45}(?:बंद|निलंबित|अवरुद्ध).{0,30}(?:जाएगा|दिया जाएगा|कर दिया जाएगा)(?!\w)",
            ),
            "explanation": "खाता बंद या निलंबित करने की धमकी देकर तुरंत कार्रवाई का दबाव बनाया जा सकता है।",
            "action": "संदेश के लिंक या नंबर का उपयोग न करें; आधिकारिक ऐप या वेबसाइट पर खाते की स्थिति जाँचें।",
        },
        "urgency": {
            "phrases": (
                "तुरंत",
                "अभी",
                "अभी कार्रवाई करें",
                "जल्दी कार्रवाई करें",
                "जल्दी करें",
                "अंतिम मौका",
                "तुरंत कार्रवाई आवश्यक है",
                "तुरंत कार्रवाई करें",
                "अभी कार्रवाई आवश्यक है",
                "आखिरी मौका",
            ),
            "contextual_phrases": ("आज ही", "आज रात", "आधी रात से पहले"),
            "explanation": "तत्काल कार्रवाई या समय-सीमा की भाषा सोच-समझकर जाँच करने से रोक सकती है।",
            "action": "रुकें और कार्रवाई से पहले दावे की स्वतंत्र रूप से पुष्टि करें।",
        },
        "time_pressure": {
            "regexes": (
                r"(?<!\w)(?:[0-9०-९]{1,2}|पाँच|पांच|दस)\s*(?:मिनट|मिनटों)\s*(?:में|के\s*अंदर)?(?!\w)",
            ),
            "phrases": (
                "5 मिनट में",
                "१० मिनट में",
                "5 मिनटों में",
                "10 मिनटों में",
            ),
            "explanation": "कम समय की स्पष्ट समय-सीमा, खासकर धमकी या अनुरोध के साथ, दबाव का संकेत है।",
            "action": "जल्दबाजी न करें; ज्ञात आधिकारिक संपर्क माध्यम से दावे की पुष्टि करें।",
        },
        "sensitive_info": {
            "phrases": (
                "अपना ओटीपी साझा करें",
                "ओटीपी साझा करें",
                "अपना ओटीपी भेजें",
                "ओटीपी भेजें",
                "ओटीपी बताएं",
                "अपना पासवर्ड साझा करें",
                "पासवर्ड दर्ज करें",
                "पासवर्ड बताएं",
                "पासवर्ड भेजें",
                "पासवर्ड दें",
                "अपना पासवर्ड दें",
                "अपना पिन बताएं",
                "बैंक विवरण साझा करें",
                "बैंक विवरण भेजें",
                "बैंक खाता सत्यापित करें",
                "अपना खाता नंबर भेजें",
            ),
            "explanation": "संदेश OTP, पासवर्ड, PIN या बैंकिंग जानकारी माँग रहा है।",
            "action": "संदेश के जवाब में OTP, पासवर्ड, PIN या बैंक विवरण साझा न करें।",
        },
        "financial_impersonation": {
            "phrases": (
                "केवाईसी अपडेट",
                "केवाईसी सत्यापन",
                "केवाईसी सत्यापित करें",
                "बैंक खाता सत्यापित",
                "भुगतान विफल",
                "रिफंड प्रक्रिया",
                "खाता फिर से चालू",
            ),
            "explanation": "बैंक, भुगतान, रिफंड या KYC का दावा वित्तीय संस्था की नकल हो सकता है।",
            "action": "दावे को आधिकारिक बैंक ऐप या कार्ड पर दिए गए नंबर से जाँचें।",
        },
        "account_verification": {
            "phrases": (
                "खाता सत्यापन आवश्यक",
                "खाते का सत्यापन आवश्यक",
                "खाता सत्यापित करें",
                "खाते को सत्यापित करें",
            ),
            "explanation": "अनचाहा खाता-सत्यापन अनुरोध, खासकर लिंक के साथ, पासवर्ड चुराने का प्रयास हो सकता है।",
            "action": "संदेश के लिंक पर न जाएँ; आधिकारिक ऐप या ज्ञात वेबसाइट से खाते की जाँच करें।",
        },
        "government_impersonation": {
            "phrases": (
                "सरकारी सब्सिडी",
                "सरकारी सहायता",
                "सरकारी लाभ",
                "सरकारी लाभ स्वीकृत",
                "लाभ स्वीकृत",
                "सरकारी अनुदान",
                "टैक्स रिफंड",
                "आधिकारिक सत्यापन",
                "सरकारी योजना",
                "विभागीय सत्यापन",
            ),
            "explanation": "सरकारी लाभ या सत्यापन का दावा किसी सार्वजनिक एजेंसी की नकल हो सकता है।",
            "action": "लाभ या नोटिस को संबंधित विभाग की आधिकारिक वेबसाइट पर जाँचें; अनचाहा शुल्क न दें।",
        },
        "job_reward": {
            "phrases": (
                "गारंटीड नौकरी",
                "पक्की नौकरी",
                "घर से काम करके कमाई",
                "वर्क फ्रॉम होम नौकरी",
                "बिना अनुभव नौकरी",
                "आसान कमाई",
            ),
            "explanation": "गारंटीड नौकरी या असामान्य कमाई का वादा नौकरी घोटाले का संकेत हो सकता है।",
            "action": "नियोक्ता की स्वतंत्र जाँच करें और नौकरी पाने के लिए पैसे न दें।",
        },
        "upfront_payment": {
            "phrases": (
                "पंजीकरण शुल्क",
                "रजिस्ट्रेशन फीस",
                "प्रोसेसिंग फीस",
                "प्रोसेसिंग शुल्क",
                "प्रोसेसिंग शुल्क जमा करें",
                "अग्रिम भुगतान",
                "जमा राशि भेजें",
                "शुरू करने के लिए भुगतान करें",
            ),
            "explanation": "नौकरी, इनाम या लाभ देने से पहले शुल्क या जमा राशि माँगी जा रही है।",
            "action": "ऑफर पाने के लिए पैसे न भेजें; संस्था की स्वतंत्र रूप से पुष्टि करें।",
        },
        "reward_scam": {
            "phrases": (
                "आपने इनाम जीता है",
                "आपने पुरस्कार जीता",
                "लॉटरी जीती",
                "लॉटरी का इनाम",
                "लॉटरी पुरस्कार",
                "इनाम का दावा करें",
                "अपना उपहार प्राप्त करें",
                "मुफ्त उपहार",
                "लॉटरी इनाम",
                "विजेता घोषित",
            ),
            "explanation": "अनचाहा इनाम या उपहार व्यक्तिगत जानकारी या पैसे लेने का लालच हो सकता है।",
            "action": "अप्रत्याशित इनाम पाने के लिए शुल्क न दें और निजी जानकारी न दें।",
        },
        "payment_request": {
            "phrases": (
                "अभी भुगतान करें",
                "पैसे भेजें",
                "भुगतान आवश्यक है",
                "राशि ट्रांसफर करें",
            ),
            "explanation": "संदेश में पैसे भेजने या भुगतान करने का अनुरोध है।",
            "action": "भुगतान से पहले भरोसेमंद संपर्क माध्यम से प्राप्तकर्ता की पुष्टि करें।",
        },
    },
    "Kannada": {
        "account_threat": {
            "phrases": (
                "ಖಾತೆ ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ",
                "ಖಾತೆ ಸ್ಥಗಿತಗೊಳಿಸಲಾಗುತ್ತದೆ",
                "ಖಾತೆ ಮುಚ್ಚಲಾಗುತ್ತದೆ",
                "ನಿಮ್ಮ ಖಾತೆ ಮುಚ್ಚಲಾಗುತ್ತದೆ",
                "ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ",
                "ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ",
                "ಖಾತೆಯನ್ನು ಶಾಶ್ವತವಾಗಿ ಸ್ಥಗಿತಗೊಳಿಸಲಾಗುತ್ತದೆ",
                "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ಶೀಘ್ರದಲ್ಲೇ ನಿರ್ಬಂಧಿಸಲಾಗುತ್ತದೆ",
                "ಬ್ಯಾಂಕ್ ಖಾತೆ ಸ್ಥಗಿತ",
            ),
            "regexes": (
                r"(?<!\w)(?:ನಿಮ್ಮ\s+)?ಖಾತೆ(?:ಯನ್ನು|ಯು|ಯ)?[\s\S]{0,55}?(?:ಸ್ಥಗಿತ|ನಿರ್ಬಂಧ|ಮುಚ್ಚಿ)[\s\S]{0,30}?(?:ಗೊಳಿಸಲಾಗುತ್ತದೆ|ಲಾಗುತ್ತದೆ|ಮಾಡಲಾಗುತ್ತದೆ|ವಾಗುತ್ತದೆ|ಲಾಗಿದೆ)(?!\w)",
            ),
            "explanation": "ಖಾತೆ ನಿರ್ಬಂಧಿಸುವ ಅಥವಾ ಸ್ಥಗಿತಗೊಳಿಸುವ ಬೆದರಿಕೆ ತುರ್ತು ಕ್ರಮಕ್ಕೆ ಒತ್ತಡ ಹೇರುವ ತಂತ್ರವಾಗಿರಬಹುದು.",
            "action": "ಸಂದೇಶದ ಲಿಂಕ್ ಅಥವಾ ಸಂಖ್ಯೆಯನ್ನು ಬಳಸದೆ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್‌ನಲ್ಲಿ ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ.",
        },
        "urgency": {
            "phrases": (
                "ತಕ್ಷಣ",
                "ಈಗಲೇ",
                "ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ",
                "ತ್ವರಿತವಾಗಿ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ",
                "ಕೊನೆಯ ಅವಕಾಶ",
                "ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಬೇಕು",
                "ತಕ್ಷಣ ಕ್ರಮ ಅಗತ್ಯ",
            ),
            "contextual_phrases": ("ಇಂದು", "ಇಂದೇ", "ಮಧ್ಯರಾತ್ರಿಯ ಮೊದಲು"),
            "explanation": "ತುರ್ತು ಅಥವಾ ಗಡುವಿನ ಭಾಷೆ ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸುವುದನ್ನು ತಡೆಯಬಹುದು.",
            "action": "ಯಾವುದೇ ಕ್ರಮಕ್ಕೂ ಮೊದಲು ತಿಳಿದಿರುವ ಅಧಿಕೃತ ಸಂಪರ್ಕ ಮಾರ್ಗದ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
        },
        "time_pressure": {
            "regexes": (
                r"(?<!\w)(?:[0-9೦-೯]{1,2}|ಐದು|ಹತ್ತು)\s*ನಿಮಿಷ(?:ಗಳಲ್ಲಿ|ದಲ್ಲಿ|ದೊಳಗೆ)?(?!\w)",
            ),
            "phrases": (
                "5 ನಿಮಿಷಗಳಲ್ಲಿ",
                "10 ನಿಮಿಷಗಳಲ್ಲಿ",
                "5 ನಿಮಿಷದಲ್ಲಿ",
                "10 ನಿಮಿಷದಲ್ಲಿ",
            ),
            "explanation": "ಅತ್ಯಲ್ಪ ಸಮಯದ ಗಡುವು, ವಿಶೇಷವಾಗಿ ಬೆದರಿಕೆ ಅಥವಾ ವಿನಂತಿಯೊಂದಿಗೆ ಬಂದರೆ, ಒತ್ತಡದ ಸೂಚನೆ.",
            "action": "ಆತುರಪಡಬೇಡಿ; ತಿಳಿದಿರುವ ಅಧಿಕೃತ ಸಂಪರ್ಕದ ಮೂಲಕ ಹೇಳಿಕೆಯನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.",
        },
        "sensitive_info": {
            "phrases": (
                "ನಿಮ್ಮ ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ",
                "ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ",
                "ಓಟಿಪಿ ಕಳುಹಿಸಿ",
                "ನಿಮ್ಮ ಓಟಿಪಿ ಕಳುಹಿಸಿ",
                "ಓಟಿಪಿ ತಿಳಿಸಿ",
                "ಪಾಸ್‌ವರ್ಡ್ ಹಂಚಿಕೊಳ್ಳಿ",
                "ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ",
                "ನಿಮ್ಮ ಪಿನ್ ತಿಳಿಸಿ",
                "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನೀಡಿ",
                "ಪಾಸ್‌ವರ್ಡ್ ನೀಡಿ",
                "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಕಳುಹಿಸಿ",
                "ಪಾಸ್‌ವರ್ಡ್ ಕಳುಹಿಸಿ",
                "ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಿ",
                "ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ಕಳುಹಿಸಿ",
                "ಬ್ಯಾಂಕ್ ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ",
                "ಖಾತೆ ಸಂಖ್ಯೆಯನ್ನು ಕಳುಹಿಸಿ",
            ),
            "explanation": "ಸಂದೇಶವು OTP, ಪಾಸ್‌ವರ್ಡ್, PIN ಅಥವಾ ಬ್ಯಾಂಕಿಂಗ್ ಮಾಹಿತಿಯನ್ನು ಕೇಳುತ್ತದೆ.",
            "action": "ಸಂದೇಶಕ್ಕೆ ಪ್ರತಿಯಾಗಿ OTP, ಪಾಸ್‌ವರ್ಡ್, PIN ಅಥವಾ ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
        },
        "financial_impersonation": {
            "phrases": (
                "ಕೆವೈಸಿ ನವೀಕರಿಸಿ",
                "ಕೆವೈಸಿ ಪರಿಶೀಲಿಸಿ",
                "ಕೆವೈಸಿ ಪರಿಶೀಲನೆ",
                "ಬ್ಯಾಂಕ್ ಖಾತೆ ಪರಿಶೀಲಿಸಿ",
                "ಪಾವತಿ ವಿಫಲ",
                "ಮರುಪಾವತಿ ಪ್ರಕ್ರಿಯೆ",
                "ಖಾತೆಯನ್ನು ಮರುಸಕ್ರಿಯಗೊಳಿಸಿ",
            ),
            "explanation": "ಬ್ಯಾಂಕ್, ಪಾವತಿ, ಮರುಪಾವತಿ ಅಥವಾ KYC ಹೇಳಿಕೆ ಹಣಕಾಸು ಸಂಸ್ಥೆಯ ಸೋಗಾಗಿರಬಹುದು.",
            "action": "ಅಧಿಕೃತ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ಅಥವಾ ಕಾರ್ಡ್‌ನಲ್ಲಿರುವ ಸಂಖ್ಯೆಯ ಮೂಲಕ ಹೇಳಿಕೆಯನ್ನು ಪರಿಶೀಲಿಸಿ.",
        },
        "account_verification": {
            "phrases": (
                "ಖಾತೆ ಪರಿಶೀಲನೆ ಅಗತ್ಯ",
                "ಖಾತೆಯ ಪರಿಶೀಲನೆ ಅಗತ್ಯ",
                "ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ",
                "ಖಾತೆ ಪರಿಶೀಲಿಸಿ",
            ),
            "explanation": "ಅನಿರೀಕ್ಷಿತ ಖಾತೆ ಪರಿಶೀಲನೆ ವಿನಂತಿ, ವಿಶೇಷವಾಗಿ ಲಿಂಕ್‌ನೊಂದಿಗೆ ಬಂದರೆ, ಪಾಸ್‌ವರ್ಡ್ ಕದಿಯುವ ಪ್ರಯತ್ನವಾಗಿರಬಹುದು.",
            "action": "ಸಂದೇಶದ ಲಿಂಕ್ ಬಳಸಬೇಡಿ; ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ಪರಿಚಿತ ವೆಬ್‌ಸೈಟ್ ಮೂಲಕ ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ.",
        },
        "government_impersonation": {
            "phrases": (
                "ಸರ್ಕಾರಿ ಸಬ್ಸಿಡಿ",
                "ಸರ್ಕಾರದ ಸಹಾಯಧನ",
                "ಸರ್ಕಾರಿ ಅನುದಾನ",
                "ಸರ್ಕಾರಿ ಸಹಾಯಧನ",
                "ಸರ್ಕಾರಿ ನೆರವು",
                "ಸಹಾಯಧನ ಮಂಜೂರಾಗಿದೆ",
                "ತೆರಿಗೆ ಮರುಪಾವತಿ",
                "ಅಧಿಕೃತ ಪರಿಶೀಲನೆ",
                "ಸರ್ಕಾರಿ ಯೋಜನೆ",
                "ಇಲಾಖೆಯ ಪರಿಶೀಲನೆ",
            ),
            "explanation": "ಸರ್ಕಾರಿ ಲಾಭ ಅಥವಾ ಪರಿಶೀಲನೆ ಎಂಬ ಹೇಳಿಕೆ ಸಾರ್ವಜನಿಕ ಸಂಸ್ಥೆಯ ಸೋಗಾಗಿರಬಹುದು.",
            "action": "ಸಂಬಂಧಿತ ಇಲಾಖೆಯ ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ನಲ್ಲಿ ಪರಿಶೀಲಿಸಿ; ಅಪರಿಚಿತ ಶುಲ್ಕ ಪಾವತಿಸಬೇಡಿ.",
        },
        "job_reward": {
            "phrases": (
                "ಖಚಿತ ಉದ್ಯೋಗ",
                "ಖಾತರಿ ಉದ್ಯೋಗ",
                "ಮನೆಯಿಂದ ಕೆಲಸ ಮಾಡಿ ಆದಾಯ",
                "ಮನೆಯಿಂದ ಕೆಲಸದ ಉದ್ಯೋಗ",
                "ಅನುಭವವಿಲ್ಲದೆ ಉದ್ಯೋಗ",
                "ಸುಲಭ ಹಣ",
            ),
            "explanation": "ಖಚಿತ ಉದ್ಯೋಗ ಅಥವಾ ಅಸಾಮಾನ್ಯ ಆದಾಯದ ಭರವಸೆ ಉದ್ಯೋಗ ವಂಚನೆಯ ಸೂಚನೆಯಾಗಿರಬಹುದು.",
            "action": "ಉದ್ಯೋಗದಾತರನ್ನು ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸಿ; ಉದ್ಯೋಗ ಪಡೆಯಲು ಹಣ ಪಾವತಿಸಬೇಡಿ.",
        },
        "upfront_payment": {
            "phrases": (
                "ನೋಂದಣಿ ಶುಲ್ಕ",
                "ರಿಜಿಸ್ಟ್ರೇಶನ್ ಶುಲ್ಕ",
                "ಪ್ರಕ್ರಿಯೆ ಶುಲ್ಕ",
                "ಸಂಸ್ಕರಣಾ ಶುಲ್ಕ",
                "ಮುಂಗಡ ಪಾವತಿ",
                "ಠೇವಣಿ ಪಾವತಿಸಿ",
                "ಕೆಲಸ ಆರಂಭಿಸಲು ಪಾವತಿಸಿ",
            ),
            "explanation": "ಉದ್ಯೋಗ, ಬಹುಮಾನ ಅಥವಾ ಸೇವೆ ನೀಡುವ ಮೊದಲು ಶುಲ್ಕ ಅಥವಾ ಠೇವಣಿ ಕೇಳಲಾಗುತ್ತಿದೆ.",
            "action": "ಆಫರ್ ಪಡೆಯಲು ಹಣ ಕಳುಹಿಸಬೇಡಿ; ಸಂಸ್ಥೆಯನ್ನು ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸಿ.",
        },
        "reward_scam": {
            "phrases": (
                "ನೀವು ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ",
                "ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ",
                "ಬಹುಮಾನ ಪಡೆಯಿರಿ",
                "ನಿಮ್ಮ ಉಡುಗೊರೆ ಪಡೆಯಿರಿ",
                "ಉಚಿತ ಉಡುಗೊರೆ",
                "ಲಾಟರಿ ಬಹುಮಾನ",
                "ಲಾಟರಿ ಗೆದ್ದಿದ್ದೀರಿ",
                "ವಿಜೇತರಿಗೆ ಸೂಚನೆ",
            ),
            "explanation": "ಅನಿರೀಕ್ಷಿತ ಬಹುಮಾನ ಅಥವಾ ಉಡುಗೊರೆ ಹಣ ಅಥವಾ ವೈಯಕ್ತಿಕ ಮಾಹಿತಿ ಪಡೆಯುವ ಆಮಿಷವಾಗಿರಬಹುದು.",
            "action": "ಅನಿರೀಕ್ಷಿತ ಬಹುಮಾನ ಪಡೆಯಲು ಶುಲ್ಕ ಪಾವತಿಸಬೇಡಿ ಅಥವಾ ವೈಯಕ್ತಿಕ ಮಾಹಿತಿ ನೀಡಬೇಡಿ.",
        },
        "payment_request": {
            "phrases": (
                "ಈಗ ಪಾವತಿಸಿ",
                "ಹಣ ಕಳುಹಿಸಿ",
                "ಪಾವತಿ ಅಗತ್ಯವಿದೆ",
                "ಹಣ ವರ್ಗಾಯಿಸಿ",
            ),
            "explanation": "ಸಂದೇಶವು ಹಣ ವರ್ಗಾಯಿಸಲು ಅಥವಾ ಪಾವತಿಸಲು ಕೇಳುತ್ತದೆ.",
            "action": "ಪಾವತಿಸುವ ಮೊದಲು ವಿಶ್ವಾಸಾರ್ಹ ಸಂಪರ್ಕದ ಮೂಲಕ ಸ್ವೀಕರಿಸುವವರನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.",
        },
    },
}

_TIME_REGEX = {
    "English": (
        r"(?<!\w)(?:within|in)[\s\W_]+(?:[0-9]{1,2}|five|ten)[\s\W_]+minutes?(?!\w)",
    ),
    "Hindi": (
        r"(?<!\w)(?:[0-9०-९]{1,2}|पाँच|पांच|दस)[\s\W]*(?:मिनट|मिनटों)[\s\W]*(?:में|के[\s\W]*अंदर)?(?!\w)",
    ),
    "Kannada": (
        r"(?<!\w)(?:[0-9೦-೯]{1,2}|ಐದು|ಹತ್ತು)[\s\W]*ನಿಮಿಷ(?:ಗಳಲ್ಲಿ|ದಲ್ಲಿ|ದೊಳಗೆ)?(?!\w)",
    ),
}


def normalize_message(message: str) -> str:
    normalized = unicodedata.normalize("NFKC", message).casefold()
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
    )
    return re.sub(r"\s+", " ", normalized.strip())


def _is_word_character(character: str) -> bool:
    return (
        character == "_"
        or unicodedata.category(character)[0] in {"L", "N", "M"}
    )


def _compile_phrase(phrase: str) -> re.Pattern[str]:
    tokens = phrase.casefold().split()
    flexible_phrase = r"[\s\W_]+".join(re.escape(token) for token in tokens)
    return re.compile(flexible_phrase)


def _find_matches(
    text: str,
    phrases: tuple[str, ...] = (),
    regexes: tuple[str, ...] = (),
) -> list[str]:
    candidates: list[tuple[int, int, str]] = []
    for phrase in phrases:
        pattern = _compile_phrase(normalize_message(phrase))
        candidates.extend(
            (match.start(), match.end(), match.group())
            for match in pattern.finditer(text)
        )
    for expression in regexes:
        pattern = re.compile(expression)
        candidates.extend(
            (match.start(), match.end(), match.group())
            for match in pattern.finditer(text)
        )

    candidates.sort(key=lambda candidate: (candidate[0], -(candidate[1] - candidate[0])))
    matches: list[tuple[int, int, str]] = []
    for start, end, value in candidates:
        if start > 0 and _is_word_character(text[start - 1]):
            continue
        if end < len(text) and _is_word_character(text[end]):
            continue
        if any(start < existing_end and end > existing_start for existing_start, existing_end, _ in matches):
            continue
        matches.append((start, end, value))
    return [value for _, _, value in matches]


def _message_has_request_context(text: str, language: str) -> bool:
    request_phrases = {
        "English": (
            "share", "send", "provide", "enter", "reply", "give us", "we need",
            "verify", "confirm", "update", "submit",
        ),
        "Hindi": (
            "साझा करें", "भेजें", "बताएं", "दर्ज करें", "माँग", "मांग", "सत्यापित करें",
            "अपडेट करें", "जमा करें", "दे",
        ),
        "Kannada": (
            "ಹಂಚಿಕೊಳ್ಳಿ", "ಕಳುಹಿಸಿ", "ತಿಳಿಸಿ", "ನಮೂದಿಸಿ", "ಕೇಳಿ", "ಪರಿಶೀಲಿಸಿ",
            "ನವೀಕರಿಸಿ", "ಸಲ್ಲಿಸಿ", "ನೀಡಿ",
        ),
    }
    return bool(_find_matches(text, request_phrases[language]))


_NEGATION_PATTERNS = {
    "English": {
        "sensitive_info": re.compile(
            r"\b(?:never|do not|don't|does not|doesn't|must not|should not|"
            r"cannot|can't|without)\b.{0,50}\b(?:share|send|provide|enter|"
            r"reply with|disclose|give)\b",
            re.IGNORECASE,
        ),
        "payment": re.compile(
            r"\b(?:no|not|without)\s+(?:any\s+)?(?:(?:registration|processing|"
            r"advance|application)\s+)?(?:payment|fee|fees|charge|deposit)\b|"
            r"\b(?:payment|fee|fees|charge|deposit)\s+(?:is\s+)?"
            r"(?:not required|not needed|unnecessary)\b",
            re.IGNORECASE,
        ),
    },
    "Hindi": {
        "sensitive_info": re.compile(
            r"(?:ओटीपी|otp|पासवर्ड|password|पिन|pin|बैंक विवरण)"
            r".{0,45}(?:नहीं|मत|न)\s*(?:साझा|भेज|बत|दर्ज|दे)|"
            r"(?:कभी\s+(?:भी\s+)?)?(?:नहीं|मत|न)\s+.{0,30}"
            r"(?:ओटीपी|otp|पासवर्ड|password|पिन|pin|बैंक विवरण)"
            r".{0,30}(?:साझा|भेज|बत|दर्ज|दे)",
            re.IGNORECASE,
        ),
        "payment": re.compile(
            r"(?:शुल्क|फीस|भुगतान|पैसे|जमा राशि).{0,35}"
            r"(?:नहीं|मत|बिना|आवश्यकता नहीं|ज़रूरत नहीं|जरूरत नहीं)|"
            r"(?:कोई|बिना).{0,20}(?:शुल्क|फीस|भुगतान|पैसे)",
            re.IGNORECASE,
        ),
    },
    "Kannada": {
        "sensitive_info": re.compile(
            r"(?:ಓಟಿಪಿ|otp|ಪಾಸ್‌ವರ್ಡ್|ಪಾಸ್ವರ್ಡ್|password|ಪಿನ್|pin|ಬ್ಯಾಂಕ್ ವಿವರ)"
            r".{0,45}(?:ಹಂಚಿಕೊಳ್ಳಬೇಡಿ|ಕಳುಹಿಸಬೇಡಿ|ನೀಡಬೇಡಿ|ಹೇಳಬೇಡಿ|ಬೇಡ)|"
            r"(?:ಓಟಿಪಿ|otp|ಪಾಸ್‌ವರ್ಡ್|ಪಾಸ್ವರ್ಡ್|password|ಪಿನ್|pin|ಬ್ಯಾಂಕ್ ವಿವರ)"
            r".{0,30}(?:ಹಂಚಿಕೊಳ್ಳಿ|ಕಳುಹಿಸಿ|ನೀಡಿ|ತಿಳಿಸಿ)"
            r".{0,25}(?:ಎಂದಿಗೂ|ಎಂದೂ|ಹೇಳುವುದಿಲ್ಲ|ಮಾಡಬೇಡಿ|ಬೇಡ)",
            re.IGNORECASE,
        ),
        "payment": re.compile(
            r"(?:ಶುಲ್ಕ|ಪಾವತಿ|ಹಣ|ಠೇವಣಿ).{0,35}"
            r"(?:ಇಲ್ಲ|ಬೇಡ|ಬೇಡಿ|ಅಗತ್ಯವಿಲ್ಲ|ಅಗತ್ಯ ಇಲ್ಲ|ಪಾವತಿಸಬೇಡಿ)",
            re.IGNORECASE,
        ),
    },
}


_CONTEXTUAL_SIGNAL_PATTERNS = {
    "English": {
        "credential_terms": re.compile(
            r"\b(?:otp|one[-\s]?time code|login code|verification (?:code|digits)|"
            r"security code|passcode|recovery code|recovery digits|six digits|pass(?:word|phrase)|"
            r"pin|cvv|card security code|bank credentials?|bank login|"
            r"account details|bank account digits|six[-\s]?digit (?:code|number)|"
            r"six numbers|digits)\b",
            re.IGNORECASE,
        ),
        "credential_actions": re.compile(
            r"\b(?:send|share|read(?: it)?(?: back)?|reply|type|enter|provide|"
            r"give|tell|submit|hand|say|upload|ask(?:ed)? for|need(?:ed)?|"
            r"भेज|लिख|बत|भर|डाल|दर्ज|साझा|पढ़कर|कह|माँग|मांग|चाह|"
            r"ಕಳುಹಿ|ಹೇಳಿ|ಹೇಳ|ನಮೂದಿ|ತುಂಬಿ|ಹಾಕ[ುಿ]|ಹಂಚಿ|ಕೇಳಿ|ಓದಿ|ಟೈಪ್|ನೀಡಿ|"
            r"text[\s\W]+ಮಾಡಿ)",
            re.IGNORECASE,
        ),
        "credential_negation": re.compile(
            r"\b(?:never|will never|will not|won't|do not|don't|does not|"
            r"doesn't|should not|must not)\b.{0,65}"
            r"\b(?:ask|request|need|share|send|text|read|reply|enter|provide|"
            r"give|tell|disclose|type|submit)\b|"
            r"\b(?:cannot|can't)\s+(?:ask|request|need|require)\b|"
            r"\b(?:if|when)\b.{0,100}\b(?:ask|request|urge)\w*\b.{0,60}"
            r"\b(?:password|passcode|otp|code|pin)\b.{0,100}"
            r"\b(?:ignore|avoid|do not click|don't click|do not open|don't open)\b",
            re.IGNORECASE,
        ),
        "payment_terms": re.compile(
            r"\b(?:fee|charge|amount|payment|money|funds|cost|bill|tax|"
            r"certificate|kit|badge|onboarding|wallet|deposit|customs|reservation|penalty|"
            r"fine|dues|parcel|package|seat)\b",
            re.IGNORECASE,
        ),
        "payment_actions": re.compile(
            r"\b(?:pay|transfer|send|remit|deposit|purchase|buy|submit|"
            r"wire|reimburse|demand\w*|transferred|transfer(?:red|ring)?)\b",
            re.IGNORECASE,
        ),
        "job_context": re.compile(
            r"\b(?:job|role|position|recruit(?:er|ment)?|employment|hiring|"
            r"onboard\w*|work[\s-]?from[\s-]?home|shift|appointment letter|"
            r"applicants?|workplace|placement|factory|interview|contract)\b",
            re.IGNORECASE,
        ),
        "government_context": re.compile(
            r"\b(?:government|govt|district welfare office|welfare office|"
            r"tax department|tax office|public assistance|revenue office|"
            r"benefits? office|municipal office|administration|county assistance office|"
            r"pension desk|ಸರ್ಕಾರಿ|सरकारी)\b",
            re.IGNORECASE,
        ),
        "benefit_context": re.compile(
            r"\b(?:allowance|subsidy|grant|refund|relief|benefit|welfare|"
            r"family assistance|reimbursement|aid|rebate|household rebate|pension|"
            r"scholarship|राशि|लाभ|ನೆರವು|ಪಿಂಚಣಿ|ಸಹಾಯಧನ)\b",
            re.IGNORECASE,
        ),
        "reward_context": re.compile(
            r"\b(?:prize|lottery|award|win|won|winner|draw|gift|hamper|"
            r"reward|winnings|ಉಡುಗೊರೆ|ಬಹುಮಾನ|पुरस्कार|विजेता)\b",
            re.IGNORECASE,
        ),
        "bank_context": re.compile(
            r"\b(?:bank|banking|hdfc|icici|sbi|axis|kotak|pnb|canara|"
            r"credit union|card services)\b",
            re.IGNORECASE,
        ),
        "account_subject": re.compile(
            r"\b(?:account|profile|card|access|wallet|mobile banking|ಡಿಜಿಟಲ್ ಪರ್ಸ್)\b",
            re.IGNORECASE,
        ),
        "account_state": re.compile(
            r"\b(?:freeze|frozen|lock|locked|hold|held|suspend|suspended|"
            r"disable|disabled|close|closed|block|blocked|restrict|restricted|"
            r"take(?:n)? over|unauthori[sz]ed device)\b",
            re.IGNORECASE,
        ),
    },
    "Hindi": {
        "credential_terms": re.compile(
            r"(?:ओटीपी|ओ\.टी\.पी|एक बार का कोड|सत्यापन अंक|लॉगिन कोड|"
            r"सुरक्षा कोड|गुप्त कोड|रिकवरी कोड|गुप्त शब्द|पासवर्ड|पिन|"
            r"कार्ड सुरक्षा अंक|बैंक विवरण|बैंक लॉगिन|खाता संख्या|सुरक्षा अंक|"
            r"छह अंकों(?: का)? नंबर|छह अंकों|अंक|otp|one[-\s]?time code|"
            r"login code|password|passcode|pin|recovery code|bank login)",
            re.IGNORECASE,
        ),
        "credential_actions": re.compile(
            r"(?:भेज|लिख|बत|भर|डाल|दर्ज|साझा|पढ़कर|कह|माँग|मांग|चाह|"
            r"submit|send|share|reply|enter|tell|type|read|provide|"
            r"ಕಳುಹಿ|ಹೇಳಿ|ಹೇಳ|ನಮೂದಿ|ತುಂಬಿ|ಹಾಕ[ುಿ]|ಹಂಚಿ|ಕೇಳಿ|ಓದಿ|ಟೈಪ್|ನೀಡಿ)",
            re.IGNORECASE,
        ),
        "credential_negation": re.compile(
            r"(?:कभी(?:\s+भी)?|नहीं|मत|कदापि).{0,65}"
            r"(?:माँग|मांग|भेज|साझा|बत|दर्ज|भर|दे|लिख|कह|पूछ)|"
            r"(?:अगर|यदि).{0,80}(?:पासवर्ड|कोड|ओटीपी).{0,80}"
            r"(?:लिंक न खोलें|लिंक मत खोलें|अनदेखा करें)",
            re.IGNORECASE,
        ),
        "payment_terms": re.compile(
            r"(?:शुल्क|फीस|रकम|खर्च|भुगतान|पैसे|किट|बैज|वॉलेट|प्रमाणपत्र|"
            r"उपकरण|(?<![\u0900-\u097f])कर(?![\u0900-\u097f])|सीमा शुल्क|"
            r"जमा राशि|किस्त|fee|charge|amount|"
            r"payment|money|wallet|certificate|package|seat|tax|penalty|badge|kit|deposit)",
            re.IGNORECASE,
        ),
        "payment_actions": re.compile(
            r"(?:भेज|जमा|भुगतान|खरीद|भर|हस्तांतरित|ट्रांसफर|अदा|चुक|जोड़|"
            r"माँग|मांग|माँगा|मांगा|pay|transfer|send|remit|deposit|buy|submit)",
            re.IGNORECASE,
        ),
        "job_context": re.compile(
            r"(?:नौकरी|भर्ती|काम|पद|नियुक्ति|रोजगार|उम्मीदवार|"
            r"वर्क\s*फ्रॉम\s*होम|साक्षात्कार|जॉइनिंग|प्रशिक्षण|"
            r"job|interview|placement|factory|recruiter|contract|onboarding)",
            re.IGNORECASE,
        ),
        "government_context": re.compile(
            r"(?:आयकर विभाग|जिला कल्याण कार्यालय|जिला राहत कार्यालय|पेंशन सहायता केंद्र|"
            r"कल्याण कार्यालय|सरकारी|"
            r"सरकार|कर विभाग|कल्याण विभाग|जिला कार्यालय|जनकल्याण|"
            r"प्रशासन|विभागीय कार्यालय|county assistance office|pension desk|"
            r"ಸರ್ಕಾರಿ|ತಾಲೂಕು ನೆರವು ಕಚೇರಿ)",
            re.IGNORECASE,
        ),
        "benefit_context": re.compile(
            r"(?:सहायता|भत्ता|सब्सिडी|अनुदान|वापसी|रिफंड|राहत|लाभ|"
            r"कल्याण|परिवार सहायता|मुआवजा|पेंशन|राशि|rebate|benefit|"
            r"ಸಹಾಯಧನ|ಪಿಂಚಣಿ|ನೆರವು|scholarship|ಪರಿಹಾರ)",
            re.IGNORECASE,
        ),
        "reward_context": re.compile(
            r"(?:इनाम|पुरस्कार|लॉटरी|जीता|जीते|विजेता|उपहार|नकद पुरस्कार|"
            r"रिवॉर्ड|चुना गया|prize|lottery|award|winner|gift|reward|hamper|"
            r"ಬಹುಮಾನ|ಉಡುಗೊರೆ|ಗೆದ್ದ|ವಿಜೇತ|shopping draw)",
            re.IGNORECASE,
        ),
        "bank_context": re.compile(
            r"(?:बैंक|बैंकिंग|एचडीएफसी|आईसीआईसीआई|एसबीआई|कार्ड सेवा|"
            r"hdfc|icici|sbi|bank)",
            re.IGNORECASE,
        ),
        "account_subject": re.compile(
            r"(?:खाता|अकाउंट|कार्ड|प्रवेश|पहुँच|वॉलेट|बैंकिंग|account|wallet|profile)",
            re.IGNORECASE,
        ),
        "account_state": re.compile(
            r"(?:जमा|रोक|बंद|स्थगित|निलंबित|अवरुद्ध|फ्रीज|फ्रिज|लॉक|"
            r"निष्क्रिय|सीमित|कब्जा|नियंत्रण)",
            re.IGNORECASE,
        ),
    },
    "Kannada": {
        "credential_terms": re.compile(
            r"(?:ಓಟಿಪಿ|ಒಮ್ಮೆ ಬಳಕೆಯ ಕೋಡ್|ದೃಢೀಕರಣ ಸಂಖ್ಯೆ|ಪ್ರವೇಶ ಕೋಡ್|"
            r"ಗುಪ್ತಪದ|ಪಾಸ್‌ವರ್ಡ್|ಪಾಸ್ವರ್ಡ್|ಪಿನ್|ಮರುಪಡೆಯುವ ಕೋಡ್|"
            r"ಮರುಪಡೆಯುವ ಗುಪ್ತ ಸಂಖ್ಯೆ|ಗುಪ್ತ ಸಂಖ್ಯೆ|ಗುಪ್ತ ಕೋಡ್|ಆರು ಅಂಕಿ|"
            r"ಖಾತೆ ಸಂಖ್ಯೆ|ರಹಸ್ಯ ಅಂಕ|ಭದ್ರತಾ ಸಂಖ್ಯೆ|ಬ್ಯಾಂಕ್ ವಿವರ|ಬ್ಯಾಂಕ್ ಪ್ರವೇಶ ಮಾಹಿತಿ|"
            r"ಕೋಡ್|verification code|one[-\s]?time code|bank login|"
            r"otp|login code|password|passcode|pin|recovery code|security code)",
            re.IGNORECASE,
        ),
        "credential_actions": re.compile(
            r"(?:ಕಳುಹಿ|ಕಳುಹಿಸ|ಬರೆ|ತಿಳಿ|ಹೇಳಿ|ಹೇಳ|ನಮೂದಿ|ತುಂಬಿ|ಹಾಕ[ುಿ]|ಹಂಚಿ|ಕೇಳಿ|ಓದಿ|ಟೈಪ್|ನೀಡಿ|ಕೊಡಿ|"
            r"reply|send|share|enter|read|tell|give|submit|provide|text)",
            re.IGNORECASE,
        ),
        "credential_negation": re.compile(
            r"(?:ಎಂದಿಗೂ|ಎಂದೂ|ಬೇಡ|ಬೇಡಿ|ಮಾಡಬೇಡಿ|ಕೇಳುವುದಿಲ್ಲ|ಹೇಳುವುದಿಲ್ಲ|"
            r"ಹಂಚಿಕೊಳ್ಳಬೇಡಿ).{0,65}"
            r"(?:ಕೇಳ|ಕಳುಹಿ|ಹಂಚಿ|ತಿಳಿ|ನಮೂದಿ|ನೀಡಿ|ತುಂಬಿ|ಹೇಳಿ)|"
            r"(?:ಅಪರಿಚಿತ|ಅನುಮಾನಾಸ್ಪದ).{0,50}(?:ಗುಪ್ತಪದ|ಪಾಸ್‌ವರ್ಡ್)"
            r".{0,40}(?:ಕೇಳಿದರೆ|ಕೇಳುತ್ತದೆ).{0,80}(?:ತೆರೆಯಬೇಡಿ|ಬೇಡ|ಪರಿಶೀಲಿಸಿ)",
            re.IGNORECASE,
        ),
        "payment_terms": re.compile(
            r"(?:ಶುಲ್ಕ|ಪಾವತಿ|ಹಣ|ಮೊತ್ತ|ವೆಚ್ಚ|ವಾಲೆಟ್|ಪ್ರಮಾಣಪತ್ರ|"
            r"ಉಪಕರಣ|ಗುರುತು ಕಿಟ್|ಬ್ಯಾಡ್ಜ್|ತೆರಿಗೆ|ಸುಂಕ|ಠೇವಣಿ|ಕಂತು|fee|charge|amount|payment|"
            r"money|wallet|certificate|package|seat|tax|penalty|fine|parcel|kit|badge|deposit)",
            re.IGNORECASE,
        ),
        "payment_actions": re.compile(
            r"(?:ಕಳುಹಿ|ಕಳುಹಿಸ|ಜಮಾ|ಪಾವತಿ|ಖರೀದಿ|ತುಂಬಿ|ವರ್ಗಾಯಿಸಿ|ಪಾವತಿಸಿ|"
            r"ವರ್ಗಾಯ|ಕೊಡು|ಕೊಟ್ಟ|ಕೊಡಿ|ಹಾಕ[ುಿ]|pay|transfer|send|remit|deposit|buy|submit|give)",
            re.IGNORECASE,
        ),
        "job_context": re.compile(
            r"(?:ಉದ್ಯೋಗ|ಕೆಲಸ|ನೇಮಕ|ಹುದ್ದೆ|ಅಭ್ಯರ್ಥಿ|ಸಂದರ್ಶನ|ನೇಮಕಾತಿ|"
            r"ಮನೆಯಿಂದ ಕೆಲಸ|ಪಾಳಿ|ತರಬೇತಿ|job|interview|placement|factory|"
            r"recruiter|contract|onboarding|ನೇಮಕ ಪತ್ರ|ಕೆಲಸದ ಸ್ಥಾನ)",
            re.IGNORECASE,
        ),
        "government_context": re.compile(
            r"(?:ಜಿಲ್ಲಾ ಕಲ್ಯಾಣ ಕಚೇರಿ|ತಾಲೂಕು ನೆರವು ಕಚೇರಿ|ಪಿಂಚಣಿ ಕೇಂದ್ರ|"
            r"ಪಿಂಚಣಿ ಯೋಜನೆ|ಜಿಲ್ಲಾ|ಕಲ್ಯಾಣ ಕಚೇರಿ|ಸರ್ಕಾರಿ|ಸರ್ಕಾರದ|"
            r"ಆದಾಯ ತೆರಿಗೆ|ತೆರಿಗೆ ಇಲಾಖೆ|ಕಲ್ಯಾಣ ಇಲಾಖೆ|ಜಿಲ್ಲಾ ಕಚೇರಿ|"
            r"ಆಡಳಿತ|ಸಾರ್ವಜನಿಕ ನೆರವು|government|county assistance office|pension desk|"
            r"सरकारी|जिला राहत कार्यालय|पेंशन सहायता केंद्र)",
            re.IGNORECASE,
        ),
        "benefit_context": re.compile(
            r"(?:ಸಹಾಯಧನ|ಸಹಾಯ|ಭತ್ಯೆ|ಸಬ್ಸಿಡಿ|ಅನುದಾನ|ಮರುಪಾವತಿ|"
            r"ಪರಿಹಾರ|ಲಾಭ|ಕುಟುಂಬ ನೆರವು|ಕಲ್ಯಾಣ|ಪಿಂಚಣಿ|ನೆರವು|ರಿಯಾಯಿತಿ|"
            r"benefit|rebate|scholarship|ಸರ್ಕಾರಿ ನೆರವು|सहायता|लाभ|पेंशन)",
            re.IGNORECASE,
        ),
        "reward_context": re.compile(
            r"(?:ಬಹುಮಾನ|ಲಾಟರಿ|ಗೆದ್ದ|ವಿಜೇತ|ಉಡುಗೊರೆ|ನಗದು ಬಹುಮಾನ|"
            r"ಪಾರಿತೋಷಕ|ಆಯ್ಕೆ ಮಾಡಲಾಗಿದೆ|prize|lottery|award|winner|gift|reward|hamper|"
            r"पुरस्कार|विजेता|उपहार|shopping draw)",
            re.IGNORECASE,
        ),
        "bank_context": re.compile(
            r"(?:ಬ್ಯಾಂಕ್|ಬ್ಯಾಂಕಿಂಗ್|ಎಚ್‌ಡಿಎಫ್‌ಸಿ|ಐಸಿಐಸಿಐ|ಎಸ್‌ಬಿಐ|ಕಾರ್ಡ್ ಸೇವೆ|"
            r"hdfc|icici|sbi|bank|ಬ್ಯಾಂಕ್)",
            re.IGNORECASE,
        ),
        "account_subject": re.compile(
            r"(?:ಖಾತೆ|ಅಕೌಂಟ್|ಕಾರ್ಡ್|ಪ್ರವೇಶ|ವಾಲೆಟ್|ಬ್ಯಾಂಕಿಂಗ್|ಪರ್ಸ್|wallet|account|profile)",
            re.IGNORECASE,
        ),
        "account_state": re.compile(
            r"(?:ಸ್ಥಗಿತ|ನಿರ್ಬಂಧ|ಮುಚ್ಚ|ತಡೆ|ನಿಲ್ಲಿ|ನಿಲ್ಲಿಸ|ಹೋಲ್ಡ್|ಫ್ರೀಜ್|ಲಾಕ್|"
            r"ನಿಷ್ಕ್ರಿಯ|ನಿಯಂತ್ರಣ|ಸ್ವಾಧೀನ)",
            re.IGNORECASE,
        ),
    },
}


def _contextual_pair(
    text: str,
    term_pattern: re.Pattern[str],
    action_pattern: re.Pattern[str],
    negation_patterns: tuple[re.Pattern[str], ...],
) -> str | None:
    for clause in re.split(r"(?<=[.!?;।॥])\s+|\n+", text):
        if any(pattern.search(clause) for pattern in negation_patterns):
            continue
        terms = list(term_pattern.finditer(clause))
        actions = list(action_pattern.finditer(clause))
        for term in terms:
            for action in actions:
                gap = max(0, max(term.start(), action.start()) - min(term.end(), action.end()))
                if gap <= 100:
                    return f"{term.group()} + {action.group()}"
    return None


def _contextual_evidence_matches(text: str, language: str) -> dict[str, list[str]]:
    patterns = _CONTEXTUAL_SIGNAL_PATTERNS[language]
    credential_negations = tuple(
        candidate["credential_negation"]
        for candidate in _CONTEXTUAL_SIGNAL_PATTERNS.values()
    ) + tuple(
        negations["sensitive_info"] for negations in _NEGATION_PATTERNS.values()
    )
    payment_negations = tuple(
        negations["payment"] for negations in _NEGATION_PATTERNS.values()
    )
    matches: dict[str, list[str]] = {}
    credential_match = _contextual_pair(
        text,
        patterns["credential_terms"],
        patterns["credential_actions"],
        credential_negations,
    )
    payment_match = _contextual_pair(
        text,
        patterns["payment_terms"],
        patterns["payment_actions"],
        payment_negations,
    )

    def add(category: str, phrase: str | None) -> None:
        if phrase:
            matches.setdefault(category, []).append(phrase)

    add("sensitive_info", credential_match)
    if patterns["account_subject"].search(text) and patterns["account_state"].search(text):
        add("account_threat", "account or access status + restriction")

    has_job_context = bool(patterns["job_context"].search(text))
    has_government_context = bool(
        patterns["government_context"].search(text)
        and patterns["benefit_context"].search(text)
    )
    has_reward_context = bool(patterns["reward_context"].search(text))

    if credential_match and patterns["bank_context"].search(text):
        add("financial_impersonation", "financial institution + credential request")
    if has_government_context:
        add("government_impersonation", "public agency + benefit or refund")
    if has_job_context and payment_match:
        add("job_reward", "employment offer + requested payment")
    if has_reward_context and (payment_match or credential_match):
        add("reward_scam", "prize or gift claim + requested payment or credential")
    if payment_match:
        if has_job_context or has_government_context or has_reward_context:
            add("upfront_payment", payment_match)
        else:
            add("payment_request", payment_match)

    return matches


def _has_unnegated_occurrence(
    text: str,
    phrase: str,
    language: str,
    category: str,
) -> bool:
    pattern = _compile_phrase(phrase)
    negation_rules = _NEGATION_PATTERNS[language]
    negation_pattern = (
        negation_rules["sensitive_info"]
        if category == "sensitive_info"
        else negation_rules["payment"]
    )
    sentence_pattern = re.compile(r"[.!?;\n।॥]")

    for match in pattern.finditer(text):
        prefix_start = max(0, match.start() - 90)
        suffix_end = min(len(text), match.end() + 55)
        prefix = text[prefix_start:match.start()]
        suffix = text[match.end():suffix_end]
        previous_boundary = list(sentence_pattern.finditer(prefix))
        following_boundary = sentence_pattern.search(suffix)
        clause_prefix = prefix[previous_boundary[-1].end():] if previous_boundary else prefix
        clause_suffix = suffix[:following_boundary.start()] if following_boundary else suffix
        clause = f"{clause_prefix} {match.group()} {clause_suffix}"
        if not negation_pattern.search(clause):
            return True
    return False


def _evidence_item(
    category: str,
    language: str,
    matched_phrases: list[str],
    rule: dict[str, Any],
) -> dict[str, Any]:
    display_phrases = list(OrderedDict.fromkeys(matched_phrases))
    phrase_text = ", ".join(display_phrases)
    return {
        "category": category,
        "matched_phrase": phrase_text,
        "matched_phrases": display_phrases,
        "language": language,
        "weight": CATEGORY_WEIGHTS[category],
        "points_contributed": CATEGORY_WEIGHTS[category],
        "explanation": rule["explanation"],
        "recommended_action": rule["action"],
        "reason": f'{rule["explanation"]} Matched phrase: {phrase_text}.',
    }


def analyze_message(
    message: str,
    channel: str = "Other",
    sender_name: str | None = None,
    sender_email: str | None = None,
    language: str = "English",
    claimed_organization: str | None = None,
) -> dict[str, Any]:
    if language not in RULES:
        raise ValueError("Language must be English, Hindi, or Kannada.")

    normalized_text = normalize_message(message)
    extracted_urls = extract_urls(message)
    suspicious_urls: list[str] = []
    url_reasons: list[str] = []
    for url in extracted_urls:
        url_analysis = analyze_url(url)
        if url_analysis["is_suspicious"]:
            suspicious_urls.append(url)
            url_reasons.extend(url_analysis["reasons"])

    evidence: list[dict[str, Any]] = []
    suspicious_keywords: set[str] = set()
    independent_categories = {
        "account_threat",
        "account_verification",
        "sensitive_info",
        "financial_impersonation",
        "government_impersonation",
        "job_reward",
        "upfront_payment",
        "reward_scam",
        "payment_request",
    }

    for detected_language, rules in RULES.items():
        matched_by_category: dict[str, list[str]] = {}
        for category, rule in rules.items():
            matches = _find_matches(
                normalized_text,
                tuple(rule.get("phrases", ())),
                tuple(rule.get("regexes", ())),
            )
            if category == "time_pressure":
                matches.extend(_find_matches(normalized_text, regexes=_TIME_REGEX[detected_language]))
            if category == "urgency":
                matches.extend(_find_matches(normalized_text, tuple(rule.get("contextual_phrases", ()))))
            if category in {"sensitive_info", "upfront_payment", "payment_request"}:
                negation_category = "sensitive_info" if category == "sensitive_info" else "payment"
                matches = [
                    phrase
                    for phrase in matches
                    if _has_unnegated_occurrence(
                        normalized_text, phrase, detected_language, negation_category
                    )
                ]
            if category == "sensitive_info" and not _message_has_request_context(normalized_text, detected_language):
                matches = []
            if matches:
                matched_by_category[category] = list(OrderedDict.fromkeys(matches))

        for category, matches in _contextual_evidence_matches(
            normalized_text, detected_language
        ).items():
            if category not in matched_by_category:
                matched_by_category[category] = matches

        has_independent_signal = bool(independent_categories.intersection(matched_by_category))
        if not has_independent_signal:
            matched_by_category.pop("time_pressure", None)
            contextual_urgency = rules["urgency"].get("contextual_phrases", ())
            excluded_urgency = set(_find_matches(normalized_text, tuple(contextual_urgency)))
            if excluded_urgency and "urgency" in matched_by_category:
                matched_by_category["urgency"] = [
                    phrase
                    for phrase in matched_by_category["urgency"]
                    if phrase not in excluded_urgency
                ]
                if not matched_by_category["urgency"]:
                    matched_by_category.pop("urgency")

        for category, matches in matched_by_category.items():
            evidence.append(_evidence_item(category, detected_language, matches, rules[category]))
            suspicious_keywords.update(matches)

    if suspicious_urls:
        url_rule = {
            "explanation": (
                "A URL pattern is suspicious (for example, a shortener or an insecure URL); "
                "this alone is not proof of fraud."
            ),
            "action": "Do not open the URL; verify the destination through a trusted official source.",
        }
        evidence.append(
            _evidence_item(
                "suspicious_url",
                "Language-independent",
                suspicious_urls,
                url_rule,
            )
        )

    if any(item["category"] == "upfront_payment" for item in evidence):
        evidence = [
            item for item in evidence if item["category"] != "payment_request"
        ]

    score, reasons, detected_categories = compute_score(evidence)
    final_score = min(max(score, 0), 100)
    risk_level = classify_risk(final_score)

    # ------------------------------------------------------------------
    # Layer 2: Context Analysis
    # Evaluate signal combinations and sender identity separately so that
    # the base risk_score remains stable (preserving existing test parity).
    # context_score reflects the full picture including combination bonuses.
    # ------------------------------------------------------------------
    context_result = analyze_context(
        detected_categories=detected_categories,
        message=message,
        sender_name=sender_name,
        sender_email=sender_email,
        claimed_organization=claimed_organization,
    )
    context_bonus = context_result["context_bonus"]
    context_score = min(final_score + context_bonus, 100)
    effective_risk_level = classify_risk(context_score)

    recommendations = [
        "Verify the sender and claim through an official channel before responding.",
        "Do not share OTPs, passwords, PINs, or banking details in response to a message.",
    ]
    if suspicious_urls:
        recommendations.insert(0, "Do not open or interact with the suspicious URLs identified in the message.")
    if "upfront_payment" in detected_categories or "payment_request" in detected_categories:
        recommendations.insert(0, "Do not send money until the request and recipient are independently verified.")
    # Use effective_risk_level (includes context bonuses) for recommendation tone
    if effective_risk_level == "HIGH RISK":
        recommendations.insert(0, "Treat this message as potentially deceptive; pause before taking any requested action.")
    elif effective_risk_level == "MEDIUM RISK":
        recommendations.insert(0, "Proceed cautiously and verify the message using a trusted source.")

    if not evidence:
        reasons = [
            "No major phishing, impersonation, or suspicious URL patterns were identified by the selected rule set."
        ]
        recommendations = [
            "No strong risk indicators matched; this does not guarantee that the message is safe.",
            "Verify the sender independently if the message involves money, account access, or personal information.",
        ]

    explanation_list = list(OrderedDict.fromkeys(
        reasons + url_reasons + context_result["context_narratives"]
    ))

    # Build summary of how signals contributed to the classification
    signal_summary: list[str] = []
    for cat in detected_categories:
        weight = CATEGORY_WEIGHTS.get(cat, 0)
        signal_summary.append(f"{cat} (+{weight} pts)")
    if context_result["combinations"]:
        for combo in context_result["combinations"]:
            if combo["bonus_applied"]:
                signal_summary.append(
                    f"{combo['name']} combination bonus (+{combo['points_contributed']} pts)"
                )
    if context_result["sender_analysis"]["bonus"] > 0:
        signal_summary.append(
            f"sender identity mismatch (+{context_result['sender_analysis']['bonus']} pts)"
        )

    return {
        "analysis_id": f"TRUST-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "language": language,
        "language_support": LANGUAGE_SUPPORT[language],
        "sender_name": sender_name,
        "sender_email": sender_email,
        "claimed_organization": claimed_organization,
        # risk_score and risk_level are the BASE scores (stable, test-compatible)
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_category": risk_level,
        # context_score and effective_risk_level incorporate combination bonuses
        "context_score": context_score,
        "effective_risk_level": effective_risk_level,
        "effective_risk_score": context_score,
        "detected_categories": detected_categories,
        "suspicious_keywords": sorted(suspicious_keywords),
        "suspicious_urls": suspicious_urls,
        "explanations": explanation_list,
        "recommendations": recommendations,
        "evidence": evidence,
        # Layer 2 context analysis output
        "context_combinations": context_result["combinations"],
        "context_narratives": context_result["context_narratives"],
        "sender_analysis": context_result["sender_analysis"],
        "signal_summary": signal_summary,
        "summary": "This is a rule-based risk assessment, not a confirmed fraud determination or calibrated probability.",
    }
