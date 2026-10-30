# TRUSTLENS Detection Quality Report

## Independent holdout validation (2026-10-31)

### Dataset and method

Authored a separate **100-message synthetic corpus** in `backend/tests/fixtures/independent_holdout_messages.json`: 25 each for English, Hindi, Kannada, and mixed-language messages. Every language group contains 13 suspicious and 12 legitimate messages. The fixture labels are evaluation-only; the detector does not import or use them. The evaluator classifies MEDIUM/HIGH as suspicious and LOW as legitimate, using the backend's effective risk level.

The corpus is not copied from the earlier 120-message development corpus. Baseline measurements, including all case scores/evidence and every error, are preserved in `backend/tests/fixtures/independent_holdout_baseline.json`. Post-fix measurements are in `backend/tests/fixtures/independent_holdout_postfix.json`.

### Baseline, before detector edits

| Measure | Baseline |
|---|---:|
| Cases | 100 |
| True positives | 28 |
| True negatives | 46 |
| False positives | 2 |
| False negatives | 24 |
| Precision | 0.9333 |
| Recall | 0.5385 |
| F1 | 0.6829 |
| Confusion matrix `[[TP, FN], [FP, TN]]` | `[[28, 24], [2, 46]]` |

| Language group | Cases | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| English | 25 | 7 | 11 | 1 | 6 | 0.8750 | 0.5385 | 0.6667 |
| Hindi | 25 | 6 | 12 | 0 | 7 | 1.0000 | 0.4615 | 0.6316 |
| Kannada | 25 | 6 | 11 | 1 | 7 | 0.8571 | 0.4615 | 0.6000 |
| Mixed | 25 | 9 | 12 | 0 | 4 | 1.0000 | 0.6923 | 0.8182 |

### Post-fix measurements

| Measure | Post-fix |
|---|---:|
| Cases | 100 |
| True positives | 52 |
| True negatives | 48 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 | 1.0000 |
| Confusion matrix `[[TP, FN], [FP, TN]]` | `[[52, 0], [0, 48]]` |

| Language group | Cases | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| English | 25 | 13 | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Hindi | 25 | 13 | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Kannada | 25 | 13 | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Mixed | 25 | 13 | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

### Category-wise counts

| Category | Cases | Baseline TP/TN/FP/FN | Post-fix TP/TN/FP/FN |
|---|---:|---:|---:|
| OTP theft | 4 | 0/0/0/4 | 4/0/0/0 |
| Password theft | 4 | 4/0/0/0 | 4/0/0/0 |
| Bank impersonation | 4 | 4/0/0/0 | 4/0/0/0 |
| Account takeover | 4 | 3/0/0/1 | 4/0/0/0 |
| Account threat | 4 | 2/0/0/2 | 4/0/0/0 |
| Government impersonation | 8 | 0/0/0/8 | 8/0/0/0 |
| Registration-fee scam | 4 | 2/0/0/2 | 4/0/0/0 |
| Job-fee scam | 4 | 4/0/0/0 | 4/0/0/0 |
| Prize scam | 8 | 6/0/0/2 | 8/0/0/0 |
| Suspicious URL | 4 | 2/0/0/2 | 4/0/0/0 |
| Payment scam | 4 | 1/0/0/3 | 4/0/0/0 |
| Bank notification | 8 | 0/8/0/0 | 0/8/0/0 |
| College announcement | 8 | 0/8/0/0 | 0/8/0/0 |
| Job notification | 8 | 0/8/0/0 | 0/8/0/0 |
| Safety warning | 8 | 0/6/2/0 | 0/8/0/0 |
| Payment notification | 4 | 0/4/0/0 | 0/4/0/0 |
| Normal URL | 4 | 0/4/0/0 | 0/4/0/0 |
| Normal message | 4 | 0/4/0/0 | 0/4/0/0 |
| Account notification | 4 | 0/4/0/0 | 0/4/0/0 |

### Baseline error analysis

Every baseline error is listed below. No cases had sender metadata, so sender analysis was not a cause. On the URL cases below, the URL analyzer did identify the risky URL; the main failure was that a 15-point URL-only signal (or URL plus missed message context) remained below the MEDIUM threshold.

| ID | Error | Cause |
|---|---|---|
| ho-en-21 | False positive | Context matcher treated “text” as a credential-request action in conditional security advice; negation/safe-warning context was insufficient. |
| ho-kn-21 | False positive | Conditional password advice was interpreted as a request plus account verification; Kannada safe-warning negation was incomplete. |
| ho-en-01 | False negative | “Six numbers” and “read … aloud” were not recognized as a code disclosure request; English credential intent coverage. |
| ho-en-05 | False negative | County assistance/rebate and bank-login language were outside government, benefit, and credential context vocabulary; suspicious URL alone scored LOW. |
| ho-en-06 | False negative | Factory placement and required safety-badge purchase were outside job/payment context vocabulary. |
| ho-en-09 | False negative | “Passcode” was absent from credential terms; the shortened URL alone scored LOW. |
| ho-en-10 | False negative | Passive “must be transferred” wording and “before midnight” did not combine into enough risk evidence. |
| ho-en-12 | False negative | Pension-desk benefit language was absent from government context; payment evidence alone scored LOW. |
| ho-hi-01 | False negative | Courier and six-digit-number paraphrase did not match Hindi OTP/code request vocabulary. |
| ho-hi-05 | False negative | District relief, benefit amount, and bank-login terms were missing from Hindi context rules; suspicious URL alone scored LOW. |
| ho-hi-06 | False negative | Guaranteed appointment and uniform-kit payment language were outside Hindi job/payment context vocabulary. |
| ho-hi-09 | False negative | Hindi secret-code/login request wording was not recognized; the shortener alone scored LOW. |
| ho-hi-10 | False negative | Payment evidence matched, but “आज रात” was not treated as contextual urgency, leaving the score below threshold. |
| ho-hi-12 | False negative | Pension assistance was not linked to government/benefit context; payment evidence alone scored LOW. |
| ho-hi-13 | False negative | Hindi winner, bank-account, and security-digit request paraphrase was not linked to prize/credential intent. |
| ho-kn-01 | False negative | Kannada “six digits” and read/tell request forms were not covered by credential context rules. |
| ho-kn-04 | False negative | New-device/account-control and recovery-secret wording was outside Kannada account-takeover vocabulary. |
| ho-kn-05 | False negative | Taluk assistance, relief funds, and bank-access terms were outside Kannada government/credential contexts; URL alone scored LOW. |
| ho-kn-10 | False negative | Payment evidence matched, but today/deadline phrasing did not add contextual urgency. |
| ho-kn-11 | False negative | Digital-purse restriction and PIN wording did not produce account-threat/credential evidence; payment context alone scored LOW. |
| ho-kn-12 | False negative | Pension-scheme context was not recognized as government impersonation; payment evidence alone scored LOW. |
| ho-kn-13 | False negative | Kannada prize-draw and bank-secret-digit request forms were outside the existing reward/credential patterns. |
| ho-mx-01 | False negative | Code-switching split the credential term and request action across English/Hindi; only KYC impersonation evidence was found. |
| ho-mx-05 | False negative | Kannada government and English bank-login/Hindi request vocabulary did not combine; suspicious URL alone scored LOW. |
| ho-mx-11 | False negative | English wallet, Hindi block/verification, and PIN request were not joined across language patterns. |
| ho-mx-12 | False negative | Kannada district/pension context and English fee terms were not combined as government-payment impersonation. |

### Generalisable fixes and evaluation caveat

The detector changes were reusable vocabulary/context improvements: broadened credential and code expressions, job/payment and government/benefit context, account restriction and prize language, Kannada/Hindi inflections, mixed-language action pairing, and deadline handling alongside payment requests. The two safe-warning false positives were addressed by removing ambiguous “text” action matching and recognizing conditional credential-safety advice. No exact holdout message or ID was added to production rules.

The post-fix result is **not an untouched final test**: this holdout was used to guide and verify detector changes and is now development data. Its 100% post-fix score is a result on this small, hand-authored synthetic set only. It is not real-world accuracy or an independently validated estimate. Keep a separately authored holdout untouched for any further tuning.

### Live browser verification

The existing TRUSTLENS UI was exercised through the browser at `http://127.0.0.1:5173`, with the backend at `http://127.0.0.1:8000`. Each submission returned HTTP 200 from `POST /api/analyze`, navigated to the results page, and displayed the API's effective score/level. The results page also rendered the first evidence item and a recommended action; legitimate samples showed the no-evidence state and safe generic recommendations.

| Browser scenario | API effective score / level | Expected | Result page |
|---|---:|---|---|
| English phishing | 100 / HIGH RISK | Suspicious | PASS — score, level, evidence and recommendation matched |
| Hindi phishing | 100 / HIGH RISK | Suspicious | PASS — score, level, evidence and recommendation matched |
| Kannada phishing | 100 / HIGH RISK | Suspicious | PASS — score, level, evidence and recommendation matched |
| Mixed-language phishing | 90 / HIGH RISK | Suspicious | PASS — score, level, evidence and recommendation matched |
| Legitimate OTP safety warning | 0 / LOW RISK | Legitimate | PASS — score, level, no-evidence state and recommendations rendered |
| Legitimate college announcement | 0 / LOW RISK | Legitimate | PASS — score, level, no-evidence state and recommendations rendered |

The default backend CORS origins permit ports 5173 (localhost and loopback), not 5175. The initial test at 5175 could not submit; validation was rerun on the existing TRUSTLENS frontend at the configured default origin 5173. If using a custom frontend port, configure `CORS_ORIGINS` explicitly.

### Current regression checks

| Check | Result |
|---|---|
| Full backend suite | PASS — 203 tests |
| Frontend lint (`npm run lint`) | PASS — 0 warnings, 0 errors |
| Frontend production build (`npm run build`) | PASS — Vite production build completed |
| Independent holdout baseline | Captured before detector changes |
| Post-fix holdout evaluation | PASS — 100/100, 0 FP, 0 FN |

## Latest generalisation run: 120-message corpus

The new corpus contains **120 synthetic messages**: 30 each in English, Hindi, Kannada, and code-switched mixed language. Each group has 15 suspicious and 15 legitimate samples. Final predictions use the backend's effective risk level; LOW is treated as legitimate, and MEDIUM/HIGH as suspicious.

| Measure | Final result |
|---|---:|
| Cases | 120 |
| True positives | 60 |
| True negatives | 60 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| Confusion matrix (TP, FN; FP, TN) | `[[60, 0], [0, 60]]` |

| Language group | Cases | TP | TN | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| English | 30 | 15 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Hindi | 30 | 15 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Kannada | 30 | 15 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Mixed | 30 | 15 | 15 | 0 | 0 | 1.000 | 1.000 | 1.000 |

All 60 suspicious cases were detected across these scam categories: OTP theft (8/8), account takeover (4/4), bank impersonation (8/8), fake job (4/4), government impersonation (8/8), password theft (4/4), prize scam (8/8), registration-fee scam (8/8), and suspicious URL (8/8). All 60 legitimate cases were correctly LOW: bank notifications, account notifications, college announcements, legitimate job offers, normal URLs, normal messages, payment notifications, and safety warnings.

The effective-score distribution was **13 HIGH**, **47 MEDIUM**, and **60 LOW**. These are rule-based risk scores, not calibrated probabilities.

### Error review and confirmed fixes

Final false-positive list: **none**. Final false-negative list: **none**.

The first run on this corpus produced 2 true positives, 60 true negatives, 0 false positives, and 58 false negatives. Follow-up checks exposed and fixed general logic defects rather than adding exact sample-message rules:

- Expanded cross-language context pairs and common English/code-switched terms/actions for credentials, payments, jobs, benefits, rewards, and Kannada verb forms.
- Avoided false credential/payment evidence when a negation appears in another language; constrained Hindi `कर` matching so it does not match inside unrelated words.
- Avoided splitting a sentence at periods inside numeric IP addresses, which had separated a payment request from its nearby context.
- Avoided counting the same fee request as both `upfront_payment` and `payment_request`.

**Evaluation caveat:** the messages were new when the corpus was created, but the corpus was then used to find and fix the reported failures. The final 100% result is therefore a development-set result, not an untouched holdout and not a real-world accuracy estimate. No real user messages were used. A separately authored, untouched corpus is needed for an unbiased follow-up evaluation.

The reproducible corpus is `backend/tests/fixtures/generalisation_messages.json`; run `backend/evaluate_generalisation.py` from the backend directory to recalculate metrics and per-case scores. Per-case output includes the base score, effective score, and final risk level; any false-positive or false-negative output also includes its matched evidence.

### Earlier generalisation validation

| Validation | Result |
|---|---|
| Independent-corpus evaluator | PASS — 120/120 classifications, 0 FP, 0 FN |
| Backend automated tests | PASS — 193 passed |
| Frontend lint | PASS — 0 warnings, 0 errors |
| Frontend production build | PASS |
| Effective result field consistency | PASS — API returns effective score/level; regression test confirms saved history uses them, and ResultsPage renders these fields |
| Live browser run after the detector changes | NOT RUN |

## Summary

Historical earlier validation: the advanced synthetic corpus contained **42 messages**: 14 each evaluated with English, Hindi, and Kannada selected. These results predate the 120-message generalisation work below and must not be combined with its measurements.

| Measure | Result |
|---|---:|
| Total cases | 42 |
| Correct risk classifications | 42 / 42 |
| Incorrect risk classifications | 0 |
| False positives (legitimate samples classified MEDIUM/HIGH) | 0 / 18 |
| False negatives (scam samples classified LOW) | 0 / 24 |

These are results on a small, hand-authored synthetic corpus, not a measured real-world accuracy estimate.

## Additional contextual and negation validation

A separate live API matrix exercised four suspicious scenarios and two legitimate scenarios in each selected language. The expected classes were assigned from the synthetic scenario labels before comparing them with the API response.

| Measure | Result |
|---|---:|
| Live API cases | 18 |
| Correct classifications | 18 / 18 |
| False positives | 0 / 6 legitimate cases |
| False negatives | 0 / 12 suspicious cases |
| HTTP success responses | 18 / 18 |

| Scenario | English | Hindi | Kannada |
|---|---|---|---|
| Account threat + 10-minute deadline + OTP | 97 HIGH (evidence 82) | 97 HIGH (evidence 82) | 97 HIGH (evidence 82) |
| Guaranteed job + registration fee | 45 MEDIUM (evidence 40) | 45 MEDIUM (evidence 40) | 45 MEDIUM (evidence 40) |
| Direct OTP request | 30 MEDIUM | 30 MEDIUM | 30 MEDIUM |
| Prize claim + shortened URL | 35 MEDIUM (evidence 30) | 35 MEDIUM (evidence 30) | 35 MEDIUM (evidence 30) |
| Routine bank notice | 0 LOW | 0 LOW | 0 LOW |
| Legitimate interview notification | 0 LOW | 0 LOW | 0 LOW |

Additional automated checks covered six explicitly negated examples (credential-safety reminders and fee-not-required statements); all remained at score 0 / LOW. Three wrong HDFC-claim/sender-domain pairs received a +10 contextual mismatch bonus, while the matching HDFC sender domain received no bonus. Missing sender information alone contributes no points.

Those six negation cases and four sender-domain cases also passed through the live API (10/10 HTTP 200). The browser results page displayed the final 97/100 score, HIGH RISK, selected language/channel, and matching-language evidence for all three account-threat languages. Context evidence shows one applied +15 bonus; other overlapping patterns are still explained but do not add duplicate points. Dashboard history rendered the offline fallback's actual 31 test records with 6 HIGH, 9 MEDIUM, and 16 LOW classifications and the effective 97 score. The fallback stored analysis metadata only, not message content. The 22 records created during earlier Atlas-connected checks were removed by exact ID.

This 18-message matrix and the six negation cases are synthetic, narrow regression checks. They do not establish generalization or real-world precision/recall.

## Results by language

| Selected language | Cases | Correct | Legitimate cases | Scam cases | False positives | False negatives |
|---|---:|---:|---:|---:|---:|---:|
| English | 14 | 14 | 6 | 8 | 0 | 0 |
| Hindi | 14 | 14 | 6 | 8 | 0 | 0 |
| Kannada | 14 | 14 | 6 | 8 | 0 | 0 |

The detector evaluates curated rules for all three languages, allowing mixed-language phrase evidence even when a user selects one language. The selected language remains the request language; evidence labels show the phrase language. URL evidence is language-independent. This is phrase matching, not automatic language identification or translation.

## Earlier corpus evidence-only scores

The table below preserves the 42-case corpus measurements from the earlier validation run. Its score column records `risk_score` (the evidence-only score), not the contextual `effective_risk_score` introduced in the current validation. Use the contextual table above for current effective scores. Risk thresholds: LOW 0–29, MEDIUM 30–59, HIGH 60–100.

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

## Historical automated and integration validation (earlier build)

| Validation | Result |
|---|---|
| Backend automated tests (`backend`: `python.exe -m pytest -q tests`) | PASS at that earlier revision — 192 passed; latest revision: 193 passed |
| Frontend production build | PASS |
| Frontend lint | PASS — 0 warnings, 0 errors |
| Current live API matrix | PASS — 18/18 HTTP 200, expected classes and measured scores |
| Current live negation/sender API checks | PASS — 10/10 HTTP 200, expected scores and mismatch signals |
| Current browser results checks | PASS — three languages displayed final 97/100 score, level, language and evidence |
| Dashboard offline-fallback check | PASS — 31 actual test records summarized as 6 HIGH, 9 MEDIUM, 16 LOW |
| Existing security tests | PASS — production history guards, CORS validation, and no-message-persistence check remain covered |
| MongoDB test data cleanup | PASS — removed only 22 exact synthetic API/browser record IDs; no history-wide deletion |

The root-level `pytest` command is not the supported invocation: it attempts to collect `backend/test_existing_results.txt`, a UTF-16 pytest output artifact, and fails decoding it. Running the test suite from the backend directory avoids that unrelated artifact and passes all 192 tests.

## Limitations

- The corpus is synthetic, small, and written to exercise known rules. The 100% corpus result must not be interpreted as expected accuracy on real messages.
- Hindi and Kannada coverage remains limited to curated phrase variants. Targeted negation patterns cover only a small set of constructions; dialect, transliteration, misspellings, code-switching beyond known phrases, grammar, negation, and context can still evade or trigger rules.
- The application does not automatically identify the message's primary language; the selection is user-provided. It checks the three supported phrase sets for mixed text.
- URL checks are static heuristics and do not resolve redirects, inspect page content, or query reputation services. A clean-looking URL may still be malicious.
- Risk scores are explainable rule weights plus small contextual bonuses, not probabilities or calibrated severity estimates.
- No production deployment was performed.
