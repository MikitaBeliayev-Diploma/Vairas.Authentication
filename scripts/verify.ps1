param([string]$Configuration = 'Release', [switch]$SkipIntegration)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    if (!$SkipIntegration -and !(Test-Path '../Vairas.UserManagement/Vairas.UserManagement/Vairas.UserManagement.csproj')) {
        throw 'Full interoperability verification needs the sibling User Management source. Use -SkipIntegration for standalone build/unit verification.'
    }
    dotnet restore Vairas.Authentication.slnx
    if ($LASTEXITCODE -ne 0) { throw 'Restore or NuGet security audit failed.' }
    dotnet tool restore
    if ($LASTEXITCODE -ne 0) { throw 'EF tool restore failed.' }
    dotnet build Vairas.Authentication.slnx --no-restore --nologo -c $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    dotnet ef migrations has-pending-model-changes --project Vairas.Authentication.Persistance --startup-project Vairas.Authentication.Persistance --no-build --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'EF model differs from the migration snapshot.' }
    $run = Join-Path (Get-Location) ('Vairas.Authentication.Tests/TestResults/verification-' + [Guid]::NewGuid().ToString('N'))
    $unitResults = Join-Path $run 'unit'
    dotnet test Vairas.Authentication.Tests --no-build --no-restore --nologo -c $Configuration --filter 'TestCategory=Unit' --settings coverage.runsettings --collect:'XPlat Code Coverage' --results-directory $unitResults --logger 'trx;LogFileName=unit.trx'
    if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed.' }
    [xml]$unitRun = Get-Content -Raw -LiteralPath (Join-Path $unitResults 'unit.trx')
    if ([int]$unitRun.TestRun.ResultSummary.Counters.executed -le 0) { throw 'No unit tests were executed.' }
    $reports = @(Get-ChildItem -LiteralPath $unitResults -Directory | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -File -Filter coverage.cobertura.xml
    })
    if ($reports.Count -ne 1) { throw "Expected one unit-only coverage report, found $($reports.Count)." }
    $report = $reports[0]
    [xml]$coverage = Get-Content -Raw -LiteralPath $report.FullName
    $business = $coverage.coverage.packages.package | Where-Object name -eq 'Vairas.Authentication.Business'
    if (!$business) { throw 'Business assembly is missing from coverage.' }
    $rate = [double]::Parse($business.'line-rate', [Globalization.CultureInfo]::InvariantCulture)
    if ($rate -lt 0.70) { throw "Unit-only Business line coverage is below 70%: $rate" }
    Write-Output ('Unit-only Business line coverage: {0:P2}' -f $rate)
    Write-Output $report.FullName
    if ($SkipIntegration) {
        Write-Output 'Integration/component tests NOT RUN: unit-only verification requested.'
        return
    }
    # Database/HTTP/component tests retain their own run; they cannot inflate the unit coverage gate.
    $integrationResults = Join-Path $run 'integration'
    dotnet test Vairas.Authentication.Tests --no-build --no-restore --nologo -c $Configuration --filter 'TestCategory!=Unit' --results-directory $integrationResults --logger 'trx;LogFileName=integration.trx'
    if ($LASTEXITCODE -ne 0) { throw 'Integration/component tests failed.' }
    [xml]$integrationRun = Get-Content -Raw -LiteralPath (Join-Path $integrationResults 'integration.trx')
    if ([int]$integrationRun.TestRun.ResultSummary.Counters.executed -le 0) { throw 'No integration/component tests were executed.' }
} finally { Pop-Location }
