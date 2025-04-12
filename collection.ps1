# Collection script for Invoke-SecureOps
# This script gathers all PowerShell modules and generates a comprehensive scan script

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".\scan.ps1",
    
    [Parameter()]
    [switch]$PrettyOutput
)

# Function to write section headers
function Write-SectionHeader {
    param(
        [string]$Title,
        [string]$Subtitle = ""
    )
    
    $header = @"
# -----------------------------------------------------------------------------
# $Title
$(if ($Subtitle) { "# $Subtitle" })
# -----------------------------------------------------------------------------

"@
    return $header
}

# Function to write module imports
function Write-ModuleImports {
    param(
        [string[]]$Modules
    )
    
    $imports = @"
# Import required modules
`$ModulePath = Join-Path `$PSScriptRoot "Invoke-SecureOps.psm1"
Import-Module `$ModulePath -Force

"@
    return $imports
}

# Function to write main execution
function Write-MainExecution {
    param(
        [hashtable]$TestCategories
    )
    
    $main = @"
# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

Write-Output "Starting security assessment on `$env:COMPUTERNAME at `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# Initialize assessment info
`$assessmentInfo = @{
    StartTime = Get-Date
    Version = `$ModuleVersion
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

# Run security tests by category
"@

    foreach ($category in $TestCategories.Keys) {
        $main += @"

# $category Tests
Write-Output "`nRunning $category tests..."
"@
        foreach ($test in $TestCategories[$category]) {
            $main += @"
Write-Output "Running $test..."
try {
    `$result = & $test -OutputPath `$OutputPath -PrettyOutput:`$PrettyOutput
    `$assessmentInfo.TestResults += `$result
    
    # Update summary
    `$assessmentInfo.Summary.TotalTests++
    if (`$result.Status -eq "Pass") {
        `$assessmentInfo.Summary.PassedTests++
    } else {
        `$assessmentInfo.Summary.FailedTests++
        if (`$result.RiskLevel -eq "Critical") {
            `$assessmentInfo.Summary.CriticalIssues++
        }
    }
    
    # Add findings
    if (`$result.Findings) {
        `$assessmentInfo.Findings += `$result.Findings
    }
} catch {
    Write-Error "Error running $test : `$_"
    `$assessmentInfo.Summary.FailedTests++
}

"@
        }
    }

    $main += @"

# Export results
`$assessmentInfo.EndTime = Get-Date
`$assessmentInfo.Duration = (`$assessmentInfo.EndTime - `$assessmentInfo.StartTime).TotalMinutes

# Output summary
Write-Host "`nAssessment Summary:"
Write-Host "-----------------"
Write-Host "Total Tests: `$(`$assessmentInfo.Summary.TotalTests)"
Write-Host "Passed: `$(`$assessmentInfo.Summary.PassedTests)"
Write-Host "Failed: `$(`$assessmentInfo.Summary.FailedTests)"
Write-Host "Critical Issues: `$(`$assessmentInfo.Summary.CriticalIssues)"
Write-Host "Duration: `$(`$assessmentInfo.Duration) minutes"

# Export to JSON if path specified
if (`$OutputPath) {
    `$jsonContent = `$assessmentInfo | ConvertTo-Json -Depth 10
    if (`$PrettyOutput) {
        `$jsonContent = `$jsonContent | ForEach-Object { [System.Text.RegularExpressions.Regex]::Replace(`$_, '^(\s*)"([^"]+)":', '`$1"`$2":', [System.Text.RegularExpressions.RegexOptions]::Multiline) }
    }
    `$jsonContent | Out-File -FilePath `$OutputPath -Encoding UTF8
    Write-Host "Results exported to: `$OutputPath"
}

# Return assessment info
return `$assessmentInfo
"@
    return $main
}

# Define test categories and their functions
$testCategories = @{
    "PowerShell Security" = @(
        "Test-PowerShellSecurity",
        "Test-PowerShellLogging"
    )
    "Windows Defender" = @(
        "Test-DefenderStatus"
    )
    "Credential Protection" = @(
        "Test-CredentialProtection"
    )
    "Firewall" = @(
        "Test-FirewallStatus",
        "Test-NetworkSecurityProtocols"
    )
    "System Security" = @(
        "Test-SystemSecurity",
        "Test-OS_EOL",
        "Test-PatchManagement",
        "Test-TimeConfiguration"
    )
    "Storage Security" = @(
        "Test-StorageEncryption",
        "Test-DirectoryPermissions"
    )
}

# Generate the scan script
$scriptContent = @"
# Generated Security Assessment Script
# Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Version: 2.0.0

[CmdletBinding()]
param(
    [Parameter()]
    [string]`$OutputPath = ".\security_assessment.json",
    
    [Parameter()]
    [switch]`$PrettyOutput
)

$(Write-ModuleImports)

$(Write-MainExecution -TestCategories $testCategories)
"@

# Write the script to file
$scriptContent | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Scan script generated successfully at: $OutputPath" 