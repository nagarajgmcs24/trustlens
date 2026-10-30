# TRUSTLENS Detection Quality Report

## Summary

The advanced synthetic validation corpus contains **42 previously unseen messages**: 14 each evaluated with English, Hindi, and Kannada selected. Expected labels were set from each message's intended legitimate or scam scenario before checking the observed risk level.

| Measure | Result |
|---|---:|
| Total cases | 42 |
| Correct risk classifications | 42 / 42 |
| Incorrect risk classifications | 0 |
| False positives (legitimate samples classified MEDIUM/HIGH) | 0 / 18 |
| False negatives (scam samples classified LOW) | 0 / 24 |

These are results on a small, hand-authored synthetic corpus, not a measured real-world accuracy estimate.

## Results by language

| Selected language | Cases | Correct | Legitimate cases | Scam cases | False positives | False negatives |
|---|---:|---:|---:|---:|---:|---:|
| English | 14 | 14 | 6 | 8 | 0 | 0 |
| Hindi | 14 | 14 | 6 | 8 | 0 | 0 |
| Kannada | 14 | 14 | 6 | 8 | 0 | 0 |

The detector evaluates curated rules for all three languages, allowing mixed-language phrase evidence even when a user selects one language. The selected language remains the request language; evidence labels show the phrase language. URL evidence is language-independent. This is phrase matching, not automatic language identification or translation.

## Results by scenario and actual score

Risk thresholds: LOW 0–29, MEDIUM 30–59, HIGH 60–100.

| Scenario | English | Hindi | Kannada |
|---|---|---|---|
| Legitimate bank notification | 0 LOW | 0 LOW | 0 LOW |
| Legitimate bank URL (`secure.bank.com`) | 0 LOW | 0 LOW | 0 LOW |
| Fake government benefit + processing fee | 45 MEDIUM | 45 MEDIUM | 45 MEDIUM |
| Legitimate job interview | 0 LOW | 0 LOW | 0 LOW |
| Lottery/reward claim + processing fee | 40 MEDIUM | 40 MEDIUM | 40 MEDIUM |
| Password theft attempt | 45 MEDIUM | 70 HIGH | 70 HIGH |
| Normal college announcement/deadline | 0 LOW | 0 LOW | 0 LOW |
| Account-verification request + suspicious URL | 30 MEDIUM | 30 MEDIUM | 30 MEDIUM |
| Legitimate urgency/time reference | 10 LOW | 10 LOW | 10 LOW |
| Ordinary HTTPS schedule URL | 0 LOW | 0 LOW | 0 LOW |
| Mixed-language account/OTP/IP-link scam | 85 HIGH | 85 HIGH | 85 HIGH |
| Account-block threat + 10-minute deadline | 52 MEDIUM | 52 MEDIUM | 52 MEDIUM |
| Job offer + registration fee | 40 MEDIUM | 40 MEDIUM | 40 MEDIUM |
| OTP request | 30 MEDIUM | 40 MEDIUM | 40 MEDIUM |

All 39 cases were also run through the live `POST /api/analyze` endpoint. Each returned HTTP 200 and the scores/classifications shown above. The same 39 cases are maintained in `backend/tests/test_detection.py`.

## Confirmed weaknesses found and addressed

An initial run of the unseen corpus exposed missed Hindi and Kannada government-benefit terms, localized processing-fee/password phrases, account-verification links, mixed-language combinations, and certain Kannada Unicode joiner variants. It also emitted time-pressure evidence for ordinary class reminders.

The detector now:

- Adds confirmed phrase variants for benefit scams, job fees, prizes, account verification, password requests, and account threats.
- Normalizes Unicode compatibility forms and format characters before matching, and permits punctuation/spacing variations between phrase tokens.
- Checks all three curated language rule sets on each message so mixed-language threats can contribute evidence; records the matched phrase's language.
- Suppresses stand-alone time-pressure evidence unless another independent threat/request signal exists.
- Treats a suspicious URL as a low-weight signal alone, and recognizes a registered domain combining account-security/verification terms.
- Deduplicates scores by category, caps the total at 100, and includes the actual matched phrase, language, explanation, points, and recommended action in evidence.

## False-positive and false-negative review

- **False positives:** No legitimate sample crossed into MEDIUM/HIGH. Normal bank notices, interview invitations, college announcements, ordinary HTTPS URLs, and class-related urgency remained LOW.
- **False negatives:** No scam sample was LOW after the changes. Government-benefit fees, prize-processing fees, password/OTP theft, account verification links, account suspension threats, registration-fee jobs, and mixed-language scams were elevated.
- **Calibration:** A shortened URL or ordinary urgency word alone does not produce HIGH risk. Observed scores were LOW (15 or below) in those isolated-signal checks. Combined scam evidence increases the score.

## Automated and integration validation

| Validation | Result |
|---|---|
| Full backend test suite, including the 39-case corpus and security tests | PASS — 83 passed |
| Frontend production build | PASS |
| Frontend lint | PASS — 0 warnings, 0 errors |
| Live API corpus | PASS — 42/42 HTTP 200, expected level and score |
| Browser dashboard history | PASS — API history rendered with counts and recent analyses |
| Results evidence | PASS — matched phrase, category, detected phrase language, points, explanation, and safe action verified |
| Existing security tests | PASS — production history guards, CORS validation, and no-message-persistence check remain covered |

## Limitations

- The corpus is synthetic, small, and written to exercise known rules. The 100% corpus result must not be interpreted as expected accuracy on real messages.
- Hindi and Kannada coverage remains limited to curated phrase variants. Dialect, transliteration, misspellings, code-switching beyond known phrases, grammar, negation, and context can still evade or trigger rules.
- The application does not automatically identify the message's primary language; the selection is user-provided. It checks the three supported phrase sets for mixed text.
- URL checks are static heuristics and do not resolve redirects, inspect page content, or query reputation services. A clean-looking URL may still be malicious.
- Risk scores are explainable rule weights, not probabilities or calibrated severity estimates.
- No production deployment was performed.
