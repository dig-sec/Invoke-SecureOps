# Invoke-SecureOps.ps1
# Comprehensive Windows Security Assessment and Remediation Toolkit
# Version 2.0.0

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Categories = @(),
    
    [Parameter()]
    [switch]$RunAll,
    
    [Parameter()]
    [string]$OutputPath = ".\security_assessment.json",
    
    [Parameter()]
    [switch]$PrettyOutput,
    
    [Parameter()]
    [switch]$AutoFix,
    
    [Parameter()]
    [switch]$WhatIf
)

# Import required modules
$ModulePath = Join-Path $PSScriptRoot "Invoke-SecureOps.psm1"
Import-Module $ModulePath -Force

# Initialize assessment info
$assessmentInfo = @{
    StartTime = Get-Date
    Version = $ModuleVersion
    Categories = $Categories
    RunAll = $RunAll
    TestResults = @()
    Findings = @()
    Summary = @{
        TotalTests = 0
        PassedTests = 0
        FailedTests = 0
        Warnings = 0
        CriticalIssues = 0
    }
}

# Define test categories and their functions
$testCategories = @{
    "PowerShellSecurity" = @(
        "Test-PowerShellSecurity",
        "Test-PowerShellLogging"
    )
    "Defender" = @(
        "Test-DefenderStatus"
    )
    "CredentialProtection" = @(
        "Test-CredentialProtection"
    )
    "Firewall" = @(
        "Test-FirewallStatus",
        "Test-NetworkSecurityProtocols"
    )
    "SystemSecurity" = @(
        "Test-SystemSecurity",
        "Test-OS_EOL",
        "Test-PatchManagement",
        "Test-TimeConfiguration"
    )
    "Storage" = @(
        "Test-StorageEncryption",
        "Test-DirectoryPermissions"
    )
}

# Determine which tests to run
$testsToRun = @()
if ($RunAll) {
    $testsToRun = $testCategories.Values | ForEach-Object { $_ }
} else {
    foreach ($category in $Categories) {
        if ($testCategories.ContainsKey($category)) {
            $testsToRun += $testCategories[$category]
        } else {
            Write-Warning "Unknown category: $category"
        }
    }
}

# Run selected tests
foreach ($test in $testsToRun) {
    Write-Host "Running $test..."
    try {
        $result = & $test -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        $assessmentInfo.TestResults += $result
        
        # Update summary
        $assessmentInfo.Summary.TotalTests++
        if ($result.Status -eq "Pass") {
            $assessmentInfo.Summary.PassedTests++
        } else {
            $assessmentInfo.Summary.FailedTests++
            if ($result.RiskLevel -eq "Critical") {
                $assessmentInfo.Summary.CriticalIssues++
            }
        }
        
        # Add findings
        if ($result.Findings) {
            $assessmentInfo.Findings += $result.Findings
        }
    } catch {
        Write-Error "Error running $test : $_"
        $assessmentInfo.Summary.FailedTests++
    }
}

# Auto-fix if requested
if ($AutoFix) {
    Write-Host "Attempting to fix identified issues..."
    $fixResults = Repair-SecurityIssues -Findings $assessmentInfo.Findings -WhatIf:$WhatIf
    $assessmentInfo.FixResults = $fixResults
}

# Export results
$assessmentInfo.EndTime = Get-Date
$assessmentInfo.Duration = ($assessmentInfo.EndTime - $assessmentInfo.StartTime).TotalMinutes

# Output summary
Write-Host "`nAssessment Summary:"
Write-Host "-----------------"
Write-Host "Total Tests: $($assessmentInfo.Summary.TotalTests)"
Write-Host "Passed: $($assessmentInfo.Summary.PassedTests)"
Write-Host "Failed: $($assessmentInfo.Summary.FailedTests)"
Write-Host "Critical Issues: $($assessmentInfo.Summary.CriticalIssues)"
Write-Host "Duration: $($assessmentInfo.Duration) minutes"

# Export to JSON if path specified
if ($OutputPath) {
    $jsonContent = $assessmentInfo | ConvertTo-Json -Depth 10
    if ($PrettyOutput) {
        $jsonContent = $jsonContent | ForEach-Object { [System.Text.RegularExpressions.Regex]::Replace($_, '^(\s*)"([^"]+)":', '$1"$2":', [System.Text.RegularExpressions.RegexOptions]::Multiline) }
    }
    $jsonContent | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Results exported to: $OutputPath"
}

# Return assessment info
return $assessmentInfo 