# TRUSTLENS — 3-Minute Hackathon Demo

## 0:00–0:30 — Problem

"Scam messages are designed to look familiar and make people act quickly. They impersonate banks, government services, employers, and delivery companies, then ask for money, credentials, or a click. People need more than a red warning—they need to understand why a message deserves caution."

## 0:30–1:00 — Solution

"TRUSTLENS is a privacy-conscious message screening app. It uses a transparent Python rule engine—not a trained machine-learning model and not an external AI service. It checks message wording and URL structure, then explains the signals and recommends safer next steps. It never opens links."

## 1:00–2:15 — Live demonstration

1. Open the landing page and point out the privacy and explainability goals.
2. Select **Analyze** and choose SMS.
3. Paste this synthetic message:

   > Your bank account will be blocked today. Update your KYC immediately at https://bit.ly/secure-update

4. Click **Analyze Message**. Show the real backend-generated score, risk classification, urgency/KYC categories, shortened URL finding, explanation, and recommendations.
5. Open **Dashboard** and show the analysis metadata in recent history.
6. Analyze a neutral announcement:

   > The college annual fest starts next week. All students are invited to attend.

7. Show its low-risk assessment, then return to the dashboard to show the updated history and counts.

## Synthetic examples and expected behavior

Expected outcomes are illustrative and can change with rule updates; these are not accuracy guarantees.

| Synthetic message | Expected behavior |
|---|---|
| "Your bank account will be blocked today. Verify your KYC immediately using https://bit.ly/secure-update" | Elevated risk: urgency, financial/KYC indicators, and shortened URL; recommend independent verification. |
| "Reply with your OTP immediately or your account will be suspended." | Elevated risk: sensitive information request and urgency/account threat. |
| "Government subsidy approved. Pay the processing fee now to receive your tax refund." | Elevated risk: government/reward language and payment request. |
| "The college annual fest starts next week. All students are invited to attend." | Low risk: no strong heuristic indicators expected. |
| "Your package is out for delivery and should arrive today." | Low risk: routine delivery wording without a suspicious URL or sensitive request. |

## 2:15–2:45 — Technical architecture

"The browser is a React/Vite app. It sends the message to a FastAPI endpoint. Pydantic validates the input; Python rules and URL parsing produce the explainable score. If MongoDB Atlas is configured, we store only analysis metadata in `trustlens.analysis_history`. The app continues to analyze if the database is unavailable."

## 2:45–3:00 — Conclusion

"TRUSTLENS turns suspicious messages into understandable signals and practical actions. It is an assistive heuristic—not proof of fraud—so users should verify important messages through official, independently obtained channels."

## Demo safety

- Use synthetic examples only; do not paste real personal, banking, or account messages.
- Avoid displaying environment files, credentials, or Atlas connection strings.
- Do not click or open suspicious URLs.
- Confirm backend health before presenting; if Atlas is offline, explain that analysis still works and history uses the runtime fallback.
