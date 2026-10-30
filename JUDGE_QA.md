# TRUSTLENS — Judge Q&A

## 1. Why TRUSTLENS?

It helps users pause and understand suspicious messages before clicking links, paying fees, or sharing sensitive information.

## 2. What problem does it solve?

Phishing and social engineering imitate trusted organizations and pressure people into unsafe actions. TRUSTLENS highlights common warning signs and suggests safer verification steps.

## 3. How does phishing detection work?

The backend uses deterministic phrase and pattern rules for urgency, sensitive data, financial and government impersonation, job/reward scams, payment requests, and suspicious URL structures.

## 4. How is the risk score calculated?

Each detected category adds a configured weight. Repeated matches in a category do not stack, and the total is capped at 100. Scores map to low (0–29), medium (30–59), and high (60–100) labels.

## 5. Is the score a probability?

No. It is a transparent heuristic score, not a calibrated probability or guarantee of fraud.

## 6. Why FastAPI?

FastAPI makes it straightforward to define JSON endpoints, validate request data with Pydantic, and expose API documentation.

## 7. Why React?

React supports a responsive interface with reusable pages and components, such as the analyzer, results report, and dashboard.

## 8. Why MongoDB?

MongoDB stores flexible analysis metadata as documents and supports Atlas-hosted persistence. The app also works without a database connection.

## 9. Is TRUSTLENS using machine learning?

No. The initial version uses hand-authored Python rules and URL parsing. It does not train or call an ML model.

## 10. What information is saved?

When MongoDB is connected, it stores analysis ID, timestamp, channel, score, risk level, and detected categories. It does not store the original message in the analysis history.

## 11. Does TRUSTLENS send text to an AI service?

No. Analysis is performed by the TRUSTLENS backend using local rule logic; no external AI API is called.

## 12. Does it open suspicious links?

No. URLs are extracted and parsed as text only. The analyzer does not fetch or navigate to them.

## 13. How are suspicious URLs detected?

The current checks look for known shorteners, IP-address hosts, HTTP rather than HTTPS, malformed structures, and some verification-themed host patterns. These checks are caution signals, not reputation verification.

## 14. Can it guarantee a safe or dangerous verdict?

No. It can miss novel scams or flag benign messages that share risky words. Users should independently verify important requests.

## 15. What causes false positives?

Legitimate messages may mention urgency, banks, account access, or payments. Keyword rules can lack the context needed to distinguish normal service messages.

## 16. What causes false negatives?

Scammers can use new wording, images, non-text content, language variants, or clean-looking URLs that current rules do not recognize.

## 17. How does it protect privacy?

It avoids external AI calls and does not automatically visit URLs. MongoDB history stores metadata rather than message content; the current message is shown in the result view without saving it as history.

## 18. Why include a dashboard?

It summarizes available analysis history and risk counts. It uses backend history when available and local browser history as a fallback.

## 19. What happens when MongoDB is offline?

Message analysis continues. History uses a backend in-memory fallback, which is not durable across backend restarts; the browser can also fall back to its own local result history.

## 20. How can the detection engine be improved?

Evaluate it on a larger, carefully labeled synthetic and consented dataset, measure false positives and negatives, add contextual rules and multilingual coverage, and maintain explainable outputs.

## 21. What makes TRUSTLENS different from a simple spam label?

It presents categories, matched keywords, URL findings, explanations, and recommendations so users can understand what triggered a result.

## 22. Is TRUSTLENS ready for production banking use?

No. It is a hackathon/demo application. Production use would require security review, robust abuse controls, extensive evaluation, privacy/legal review, reliability measures, and operational monitoring.

## 23. How is input validated?

The API uses a Pydantic model with a required message length range of 10–5000 characters and bounded optional sender fields. Validation is not a substitute for deployment-level abuse controls.

## 24. What is the next major technical step?

Build an automated test/evaluation corpus, measure and improve error rates, then add deployment and operational hardening without presenting heuristic scores as probabilities.
