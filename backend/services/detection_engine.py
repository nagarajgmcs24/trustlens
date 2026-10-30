import re
import unicodedata
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

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
            "contextual_phrases": ("आज ही", "आधी रात से पहले"),
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
            "contextual_phrases": ("ಇಂದು", "ಮಧ್ಯರಾತ್ರಿಯ ಮೊದಲು"),
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
            if category == "sensitive_info" and not _message_has_request_context(normalized_text, detected_language):
                matches = []
            if matches:
                matched_by_category[category] = list(OrderedDict.fromkeys(matches))

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

    score, reasons, detected_categories = compute_score(evidence)
    final_score = min(max(score, 0), 100)
    risk_level = classify_risk(final_score)

    recommendations = [
        "Verify the sender and claim through an official channel before responding.",
        "Do not share OTPs, passwords, PINs, or banking details in response to a message.",
    ]
    if suspicious_urls:
        recommendations.insert(0, "Do not open or interact with the suspicious URLs identified in the message.")
    if "upfront_payment" in detected_categories or "payment_request" in detected_categories:
        recommendations.insert(0, "Do not send money until the request and recipient are independently verified.")
    if risk_level == "HIGH RISK":
        recommendations.insert(0, "Treat this message as potentially deceptive; pause before taking any requested action.")
    elif risk_level == "MEDIUM RISK":
        recommendations.insert(0, "Proceed cautiously and verify the message using a trusted source.")

    if not evidence:
        reasons = [
            "No major phishing, impersonation, or suspicious URL patterns were identified by the selected rule set."
        ]
        recommendations = [
            "No strong risk indicators matched; this does not guarantee that the message is safe.",
            "Verify the sender independently if the message involves money, account access, or personal information.",
        ]

    explanation_list = list(OrderedDict.fromkeys(reasons + url_reasons))
    return {
        "analysis_id": f"TRUST-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "language": language,
        "language_support": LANGUAGE_SUPPORT[language],
        "sender_name": sender_name,
        "sender_email": sender_email,
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_category": risk_level,
        "detected_categories": detected_categories,
        "suspicious_keywords": sorted(suspicious_keywords),
        "suspicious_urls": suspicious_urls,
        "explanations": explanation_list,
        "recommendations": recommendations,
        "evidence": evidence,
        "summary": "This is a rule-based risk assessment, not a confirmed fraud determination or calibrated probability.",
    }
