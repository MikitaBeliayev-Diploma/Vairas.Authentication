# Vairas Authentication

Local identity and token authority (ASP.NET Core 10, PostgreSQL, EF Core/Npgsql): credentials, sessions, refresh
tokens, verified-email challenges, allowlisted OIDC sign-in, RS256 user and workload (client-credentials) tokens,
delegated read-preview and confirmed-lesson-action tokens, and a JWKS endpoint. Other services only validate
tokens; they never share its database.

## Projects

| Project | Responsibility |
|---|---|
| `Vairas.Authentication` | HTTP API: controllers, `Configuration/Configure*`, token issuing, OIDC, SMTP challenge delivery, workers |
| `Vairas.Authentication.Business` | Authentication and verified-email services, ports |
| `Vairas.Authentication.Domain` | Identity, session and credential entities |
| `Vairas.Authentication.Persistance` | `AuthDbContext`, migrations, stores |
| `Vairas.Authentication.Tests` | NUnit tests (PostgreSQL via Testcontainers, token and key lifecycle) |

## Dependencies

PostgreSQL 17, an SMTP relay (a local capture sink in the e2e stack) and a protected key-ring directory. Local origin
`https://localhost:7100`.

## Essential configuration

Options are bound and validated at startup (`Configuration/ConfigureOptions.cs`). Use `__` in environment variables.

| Section | Notes |
|---|---|
| `ConnectionStrings:Authentication` | required, restricted runtime role |
| `Authentication` | HTTPS `Issuer` (no trailing slash), user/workload audiences, `WorkloadClients` (Argon2id secret hashes and scopes), `ScopeAudiences`, `OidcProviders`, `BrowserOrigins`, signing certificate |
| `Protection` | absolute `KeyRingPath`; certificate for key encryption on non-Windows hosts |
| `Smtp` | host, port, `Security`, sender, HTTPS `ChallengePage`; unencrypted SMTP only for loopback in Development/Testing |
| `RateLimits:RequestsPerMinute` | optional override of the per-address budget |

Hash a workload secret without placing it on the command line:
`'<32-256 characters>' | dotnet run --project Vairas.Authentication -- hash-secret`

## Run locally

```powershell
dotnet run --project Vairas.Authentication --launch-profile https
```

The complete local stack is started from `../local/Start.ps1`. Database roles and grants: `database/`; migrations
are applied by the migration role, never on startup.

## Tests

```powershell
dotnet test Vairas.Authentication.slnx          # Docker required for PostgreSQL tests
./scripts/verify.ps1 -SkipIntegration           # unit tests with the coverage gate
```

Contract notes: [CONTRACT-NOTES.md](CONTRACT-NOTES.md). API exports: `api/`. Extended notes, validation reports and
evidence: `../../Documentation/Backend/Vairas.Authentication/`.
