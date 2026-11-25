# Authentication implementation alignment

The source interface is `Documentation/Communication/Api/authentication.openapi.yaml`, revision 0.2.0 (proposed). The implementation's exported OpenAPI is `api/authentication.openapi.json`, revision 1.0.0. All twelve canonical routes and operation IDs are preserved; no full OpenID Provider or OAuth password grant is advertised.

The implementation resolves the source's open settings as follows:

- Local passwords require completed email verification. Registration and challenge requests return generic 202. Login, refresh and OIDC callback retain the TokenPair wire shape; the workload response additionally returns standard `scope`.
- Workload scope-to-audience mappings support the current User Management client's combined `identity.validate school.profile-provisioning confirmations.validate` request. Resource services must independently enforce their own allowlists and scopes.
- SMTP is an Authentication challenge-delivery adapter. Existing school-scoped Notifications operations are unchanged; no undocumented Notifications dependency is assumed.
- OIDC redirect URIs point to a frontend callback that forwards code/state by JSON POST with the server-issued cookie. State/browser/nonce/PKCE are bound to a single ten-minute request. A failed exchange requires a fresh request. Subject/email claims never merge accounts.
- Single-session revocation persists successful and authenticated not-found outcomes. A rejected requested target need not exist or belong to the caller, so the technical ledger retains its UUID without a target-ownership FK; its source caller/session FK remains mandatory. Replay of a completed self-logout is restricted to that exact receipt, not general admission for a revoked session. Changed operation binding returns 409 even after a retained rejection.
- The canonical 59-column, eight-table domain DDL is frozen byte-for-byte in the initial migration. Two technical tables provide operation receipts and encrypted challenge delivery. Runtime grants extend the original overlay only for those tables. No production baseline or populated-database upgrade is assumed.
- External correlation IDs remain safe strings up to 128 characters; security events retain their canonical UUID field. Structured logging records the mapping to the internal security correlation UUID.
- Error responses use `application/problem+json` with stable `code` and `correlationId`. OAuth clients already rely on non-success status; source `PROVIDER_REJECTED` examples are replaced by explicit validation/authentication/scope codes. Additional 415/429/500 outcomes describe actual HTTP/abuse/failure behavior.

The original Documentation files are inputs and have not been rewritten or relabeled as implemented. The service README, exported OpenAPI and VALIDATION.md describe the implementation and the limits of verification.
