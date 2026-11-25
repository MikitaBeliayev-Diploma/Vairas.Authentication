# Vairas.Authentication — code coverage

**Line coverage 86.74 %** (1361/1569 executable lines), branch coverage 64.99 % — threshold 70 % **met**. Generated 2026-11-25.

| Assembly | Line % | Lines | Branch % |
|---|---:|---:|---:|
| Vairas.Authentication | 84.52 | 863/1021 | 57.04 |
| Vairas.Authentication.Business | 94.63 | 335/354 | 93.43 |
| Vairas.Authentication.Domain | 100.0 | 1/1 | 100.0 |
| Vairas.Authentication.Persistance | 83.94 | 162/193 | 54.76 |

## How it was measured

- Tool: coverlet (`XPlat Code Coverage`) driven by `Backend/local/coverage.py`; settings `Vairas.Authentication/coverage.runsettings` (migrations and test assemblies excluded).
- Test projects: `Vairas.Authentication.Tests`; line hits of all test projects of the service are merged (maximum per line), so shared code is never counted twice.
- Filter: `TestCategory!=Broker`. Broker tests need the Service Bus emulator and are executed (and passed) separately by `local/test_all.py`.
- The numbers are measured line coverage, not a statement about functional completeness; acceptance status is tracked in `Documentation/Final-Verification/AC-Traceability-Matrix.xlsx`.

## Reproduce

```powershell
cd Backend
py -3 local/coverage.py --services Vairas.Authentication --filter "TestCategory!=Broker" --threshold 70
```

## Files

`coverage-summary.json` (machine-readable, per file) and `index.html` (per-file table, lowest coverage first) are in this folder.

## Least covered files

| File | Line % | Lines |
|---|---:|---:|
| `Vairas.Authentication.Business/ForbiddenException.cs` | 0.0 | 0/1 |
| `Vairas.Authentication.Business/UnprocessableEntityException.cs` | 0.0 | 0/1 |
| `Vairas.Authentication.Business/VerifiedEmailService.cs` | 0.0 | 0/10 |
| `Controllers/VerifiedEmailController.cs` | 0.0 | 0/2 |
| `Vairas.Authentication.Persistance/DesignTimeFactory.cs` | 0.0 | 0/5 |
| `Vairas.Authentication.Persistance/PersistenceFailureException.cs` | 0.0 | 0/1 |
| `Vairas.Authentication.Persistance/DatabaseExceptionTranslator.cs` | 10.71 | 3/28 |
| `Security/ReadPreviewDelegation.cs` | 26.25 | 21/80 |
