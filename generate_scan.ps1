# -----------------------------------------------------------------------------
# Security Scan Generator
# -----------------------------------------------------------------------------

param(
    [string]$OutputPath = ".\results",
    [switch]$PrettyOutput,
    [switch]$DetailedAnalysis
)

# Import the module
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# Get the script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptDir "Invoke-SecureOps.psd1"

# Import module
Import-Module $modulePath -Force -Verbose

# Create timestamp for unique results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Ensure output path exists and get its full path
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$resultsPath = Join-Path $OutputPath "scan_$timestamp"

# Create results directory if it doesn't exist
if (-not (Test-Path $resultsPath)) {
    New-Item -ItemType Directory -Path $resultsPath -Force | Out-Null
}

Write-Host "Starting security scan at $(Get-Date)" -ForegroundColor Green

# Run various security tests
$tests = @(
    @{
        Name = "Test-SuspiciousConnections"
        Params = @{
            OutputPath = Join-Path $resultsPath "suspicious_connections.json"
            PrettyOutput = [bool]$PrettyOutput
            DetailedAnalysis = [bool]$DetailedAnalysis
            CollectEvidence = $true
        }
    },
    @{
        Name = "Test-AMSIBypass"
        Params = @{
            OutputPath = Join-Path $resultsPath "amsi_bypass.json"
            PrettyOutput = [bool]$PrettyOutput
            DetailedAnalysis = [bool]$DetailedAnalysis
            CollectEvidence = $true
        }
    },
    @{
        Name = "Test-AuthenticationControls"
        Params = @{
            OutputPath = Join-Path $resultsPath "auth_controls.json"
            PrettyOutput = [bool]$PrettyOutput
            DetailedAnalysis = [bool]$DetailedAnalysis
            CollectEvidence = $true
        }
    }
)

# Run each test
foreach ($test in $tests) {
    Write-Host "Running $($test.Name)..." -ForegroundColor Cyan
    try {
        $params = $test.Params
        & $test.Name @params
        Write-Host "Completed $($test.Name)" -ForegroundColor Green
    }
    catch {
        Write-Error "Error running $($test.Name): $_"
        continue
    }
}

# Generate summary report
$summaryPath = Join-Path $resultsPath "summary.json"
$summary = @{
    ScanTime = Get-Date
    Tests = @()
}

foreach ($test in $tests) {
    $resultFile = $test.Params.OutputPath
    if (Test-Path $resultFile) {
        try {
            $result = Get-Content $resultFile | ConvertFrom-Json
            $summary.Tests += @{
                Name = $test.Name
                Status = $result.Status
                RiskLevel = $result.RiskLevel
                FindingsCount = ($result.Findings | Measure-Object).Count
            }
        }
        catch {
            Write-Warning "Could not process results for $($test.Name): $_"
        }
    }
}

# Save summary
$summary | ConvertTo-Json -Depth 10 | Set-Content $summaryPath

Write-Host "`nScan completed at $(Get-Date)" -ForegroundColor Green
Write-Host "Results saved to: $resultsPath" -ForegroundColor Yellow
Write-Host "Summary report: $summaryPath" -ForegroundColor Yellow 