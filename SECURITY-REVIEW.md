# TRUSTLENS Security Review

## Scope and outcome

Reviewed the FastAPI routes, CORS configuration, environment loading, MongoDB persistence, and frontend API configuration. The identified history-access issue is mitigated for production: history read/delete routes return 404 outside development. Authentication and per-user history ownership are not implemented, so history remains a single-user development feature and must not be exposed on a shared network.

## Finding

| Severity | Finding | Status |
|---|---|---|
| MEDIUM | The history read/delete API has no authentication or user scoping. | Production exposure mitigated; remains unauthenticated in development. |

`GET /api/history` and `DELETE /api/history` use shared storage without an identity filter. `APP_ENV=production` disables both routes, even if `ENABLE_HISTORY_API=true`; production configuration also requires explicit CORS origins. Do not enable/expose history publicly until authenticated, user-scoped access is implemented.

## Fixes and controls

- Development binds to `127.0.0.1` by default; `HOST` and `PORT` permit deployment-specific binding.
- Production history routes are disabled and respond with 404.
- Production requires an explicit `CORS_ORIGINS` list. Wildcards, paths, credentials, and invalid ports are rejected. CORS does not replace API authentication.
- Credentialed CORS is disabled; only the required HTTP methods and `Content-Type` header are allowed.
- Backend `.env` files are ignored by `backend/.gitignore`; frontend environment files are ignored while `.env.example` remains trackable.
- MongoDB persistence receives analysis metadata only; the original message is not included in the persisted record.
- The frontend API base URL can be configured with `VITE_API_BASE_URL`; it is public configuration, not a place for secrets.
- MongoDB failure logging reports exception types, not connection strings or credentials.

## Validation results

| Check | Result |
|---|---|
| Backend test suite | PASS — 12 passed |
| Frontend production build | PASS |
| Frontend lint | PASS — 0 warnings, 0 errors |
| `backend/.env` exists | PASS — presence checked without reading contents |
| `.env` ignore rule | PASS — backend and frontend ignore rules are present |
| Git tracked-secret status | NOT TESTED — `C:\TRUSTLENS` is not a Git repository |
| Source scan for common hard-coded credential formats | PASS — no matches in application source; dependency virtualenv excluded |
| Production API and CORS runtime checks | NOT TESTED — config parsing and route guards were unit-tested |

## Remaining limitations

- There is no authentication or user separation. History is suitable only for local development; production history is intentionally unavailable.
- `/api/analyze` is unauthenticated and has no rate limiting. Add abuse controls before exposing the service publicly.
- A Git repository may not be present in this workspace; if so, tracked-file and history scans cannot be certified from this checkout.
