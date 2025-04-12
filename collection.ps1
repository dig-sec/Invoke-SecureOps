# -----------------------------------------------------------------------------
# Script Collection Generator
# -----------------------------------------------------------------------------

param (
    [string]$OutputFile = ".\scan.ps1",
    [switch]$Verbose
)

# Function to write section headers
function Write-SectionHeader {
    param (
        [string]$Title
    )
    
    Write-Output "`n# ============================================="
    Write-Output "# $Title"
    Write-Output "# =============================================`n"
}

# Function to write module imports
function Write-ModuleImports {
    param (
        [string]$OutputFile
    )
    
    Add-Content -Path $OutputFile -Value @"
# -----------------------------------------------------------------------------
# Windows Security Assessment Tool
# -----------------------------------------------------------------------------
#Requires -RunAsAdministrator

param (
    [string]`$OutputDir = ".\output",
    [switch]`$Verbose,
    [switch]`$Pretty,
    [switch]`$RunAllTests,
    [string[]]`$TestCategories,
    [switch]`$AutoFix,
    [switch]`$WhatIf
)

# Create output directory if it doesn't exist
if (-not (Test-Path `$OutputDir)) {
    New-Item -ItemType Directory -Path `$OutputDir | Out-Null
}

# Initialize assessment info
`$assessmentInfo = @{
    StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = `$env:COMPUTERNAME
    OutputDirectory = `$OutputDir
    Findings = @()
    TestResults = @()
}

# Initialize findings array
`$script:Findings = @()

# Helper function for adding findings
function Add-Finding {
    param (
        [Parameter(Mandatory=`$true)]
        [string]`$CheckName,
        
        [Parameter(Mandatory=`$true)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Error')]
        [string]`$Status,
        
        [Parameter(Mandatory=`$false)]
        [string]`$Details,
        
        [Parameter(Mandatory=`$false)]
        [string]`$Category = "Security",
        
        [Parameter(Mandatory=`$false)]
        [object]`$AdditionalInfo
    )
    
    `$finding = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CheckName = `$CheckName
        Status = `$Status
        Details = `$Details
        Category = `$Category
        AdditionalInfo = `$AdditionalInfo
    }
    
    `$script:Findings += `$finding
    
    # Output finding with color coding
    switch (`$Status) {
        'Pass' { Write-Host "[PASS] `$CheckName" -ForegroundColor Green }
        'Fail' { Write-Host "[FAIL] `$CheckName" -ForegroundColor Red }
        'Warning' { Write-Host "[WARN] `$CheckName" -ForegroundColor Yellow }
        'Info' { Write-Host "[INFO] `$CheckName" -ForegroundColor Cyan }
        'Error' { Write-Host "[ERROR] `$CheckName" -ForegroundColor Magenta }
    }
    
    if (`$Details) {
        Write-Host "  `$Details" -ForegroundColor Gray
    }
}

function Write-SectionHeader {
    param (
        [Parameter(Mandatory=`$true)]
        [string]`$Title
    )
    
    Write-Output "`n============================================="
    Write-Output " `$Title"
    Write-Output "=============================================`n"
}

function Export-Findings {
    param (
        [string]`$OutputPath,
        [switch]`$Pretty
    )
    
    `$findings = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = `$env:COMPUTERNAME
        Findings = `$script:Findings
        TestResults = `$assessmentInfo.TestResults
    }
    
    if (`$Pretty) {
        `$findings | ConvertTo-Json -Depth 10 | Out-File `$OutputPath
    }
    else {
        `$findings | ConvertTo-Json -Compress | Out-File `$OutputPath
    }
}

function Write-FindingsSummary {
    `$totalFindings = `$script:Findings.Count
    `$passFindings = (`$script:Findings | Where-Object { `$_.Status -eq "Pass" }).Count
    `$failFindings = (`$script:Findings | Where-Object { `$_.Status -eq "Fail" }).Count
    `$warningFindings = (`$script:Findings | Where-Object { `$_.Status -eq "Warning" }).Count
    `$errorFindings = (`$script:Findings | Where-Object { `$_.Status -eq "Error" }).Count
    
    Write-Output "`nFindings Summary:"
    Write-Output "- Total Findings: `$totalFindings"
    Write-Output "- Pass: `$passFindings"
    Write-Output "- Fail: `$failFindings"
    Write-Output "- Warning: `$warningFindings"
    Write-Output "- Error: `$errorFindings"
}

# Function to run a test and collect its findings
function Invoke-SecurityTest {
    param (
        [Parameter(Mandatory=`$true)]
        [string]`$TestName,
        
        [Parameter(Mandatory=`$false)]
        [string]`$OutputPath,
        
        [Parameter(Mandatory=`$false)]
        [switch]`$Pretty,
        
        [Parameter(Mandatory=`$false)]
        [switch]`$Verbose
    )
    
    if (-not `$OutputPath) {
        `$OutputPath = Join-Path `$OutputDir "`$TestName.json"
    }
    
    Write-Output "Running test: `$TestName"
    
    try {
        # Invoke the test function
        `$testResult = & `$TestName -OutputPath `$OutputPath -Pretty:`$Pretty -Verbose:`$Verbose
        
        # Add test result to assessment info
        `$assessmentInfo.TestResults += `$testResult
        
        # Add findings from the test to the global findings array
        foreach (`$finding in `$testResult.Findings) {
            Add-Finding -CheckName "`$(`$TestName): `$(`$finding.CheckName)" -Status `$finding.Status -Details `$finding.Details -Category `$finding.Category -AdditionalInfo `$finding.AdditionalInfo
        }
        
        # Return the test result
        return `$testResult
    }
    catch {
        Write-Error "Failed to run test `$TestName: `$(`$_.Exception.Message)"
        Add-Finding -CheckName `$TestName -Status "Error" -Details "Failed to run test: `$(`$_.Exception.Message)" -Category "TestExecution"
        return `$null
    }
}

"@
}

# Function to write main execution section
function Write-MainExecution {
    param (
        [string]$OutputFile
    )
    
    Add-Content -Path $OutputFile -Value @"
# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

if (`$Verbose) {
    Write-Output "Starting assessment on `$env:COMPUTERNAME at `$(`$assessmentInfo.StartTime)"
}

# Check dependencies first
`$dependencies = Test-Dependencies -RequiredModules @(
    "Microsoft.PowerShell.Diagnostics",
    "Microsoft.PowerShell.Security",
    "Microsoft.PowerShell.Management"
) -RequiredCommands @(
    "Get-Process",
    "Get-Service",
    "Get-ItemProperty"
)

if (-not `$dependencies.AllDependenciesMet) {
    Write-Warning "Some dependencies are missing. The assessment may be incomplete."
    if (`$Verbose) {
        Write-Output "Missing dependencies:"
        Write-Output "- Modules: `$(`$dependencies.MissingModules -join ', ')"
        Write-Output "- Commands: `$(`$dependencies.MissingCommands -join ', ')"
    }
}

# Run security integration tests if specified
if (`$TestCategories -or `$RunAllTests) {
    `$integrationResults = Test-SecurityIntegration -OutputPath "`$OutputDir\security_integration.json" -RunAllTests:`$RunAllTests -TestCategories `$TestCategories
    if (`$Verbose) {
        Write-Output "Security Integration Test Results:"
        Write-Output "- Overall Status: `$(`$integrationResults.OverallStatus)"
        Write-Output "- Total Tests: `$(`$integrationResults.TotalTests)"
        Write-Output "- Passed Tests: `$(`$integrationResults.PassedTests)"
        Write-Output "- Failed Tests: `$(`$integrationResults.FailedTests)"
        Write-Output "- Warning Tests: `$(`$integrationResults.WarningTests)"
    }
}

# Run individual tests based on categories
`$testFunctions = @{
    "PowerShellSecurity" = @("Test-PowerShellSecurity", "Test-PowerShellHistory")
    "Defender" = @("Test-DefenderStatus", "Test-AntivirusStatus")
    "CredentialProtection" = @("Test-CredentialProtection", "Test-CachedCredentials", "Test-CredentialGuard")
    "ThreatHunting" = @("Test-SuspiciousProcesses", "Test-ThreatHunting_EnvVariables", "Test-ThreatHunting_ScheduledTasks")
    "Firewall" = @("Test-FirewallStatus", "Test-NetworkConfiguration")
    "UAC" = @("Test-UACStatus")
    "NetworkSecurity" = @("Test-NetworkSecurityProtocols", "Test-AdvancedNetworkSecurity")
    "WindowsServices" = @("Test-WindowsServices", "Test-ServiceVulnerabilities")
    "System" = @("Test-OS_EOL", "Test-PatchManagement", "Test-TimeConfiguration")
    "Storage" = @("Test-StorageEncryption", "Test-DirectoryPermissions")
}

# Determine which tests to run
`$testsToRun = @()
if (`$RunAllTests) {
    `$testsToRun = `$testFunctions.Values | ForEach-Object { `$_ } | Select-Object -Unique
}
elseif (`$TestCategories) {
    foreach (`$category in `$TestCategories) {
        if (`$testFunctions.ContainsKey(`$category)) {
            `$testsToRun += `$testFunctions[`$category]
        }
        else {
            Write-Warning "Unknown test category: `$category"
        }
    }
}
else {
    # Default to running core security tests
    `$testsToRun = `$testFunctions["PowerShellSecurity"] + `$testFunctions["Defender"] + `$testFunctions["CredentialProtection"] + `$testFunctions["ThreatHunting"]
}

# Run the selected tests
foreach (`$testName in `$testsToRun) {
    `$outputPath = Join-Path `$OutputDir "`$testName.json"
    Invoke-SecurityTest -TestName `$testName -OutputPath `$outputPath -Pretty:`$Pretty -Verbose:`$Verbose
}

"@
}

# Function to write footer
function Write-Footer {
    param (
        [string]$OutputFile
    )
    
    Add-Content -Path $OutputFile -Value @"
# Write JSON report
`$JsonOutputPath = Join-Path `$OutputDir "`$env:COMPUTERNAME`_`$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
Export-Findings -OutputPath `$JsonOutputPath -Pretty:`$Pretty

# Attempt to fix security issues if requested
if (`$AutoFix) {
    `$remediationResults = Repair-SecurityIssues -Findings `$assessmentInfo -AutoFix -WhatIf:`$WhatIf
    if (`$Verbose) {
        Write-Output "Remediation Results:"
        Write-Output "- Total Findings: `$(`$remediationResults.TotalFindings)"
        Write-Output "- Fixed Issues: `$(`$remediationResults.FixedIssues.Count)"
        Write-Output "- Skipped Issues: `$(`$remediationResults.SkippedIssues.Count)"
        Write-Output "- Failed Fixes: `$(`$remediationResults.FailedFixes.Count)"
        if (`$remediationResults.RequiresReboot) {
            Write-Output "- System reboot required to apply all changes"
        }
    }
}

if (`$Verbose) {
    Write-Output "Assessment completed. Results exported to: `$JsonOutputPath"
    Write-FindingsSummary
}
"@
}

# Function to collect and process scripts
function Collect-Scripts {
    param (
        [string]$OutputFile,
        [switch]$Verbose
    )
    
    # Create the output file
    if (Test-Path $OutputFile) {
        Remove-Item $OutputFile -Force
    }
    
    # Write module imports and initialization
    Write-ModuleImports -OutputFile $OutputFile
    
    # Write main execution section
    Write-MainExecution -OutputFile $OutputFile
    
    # Find all PowerShell scripts in the src directory
    $srcPath = Join-Path $PSScriptRoot "src"
    $scriptFiles = Get-ChildItem -Path $srcPath -Recurse -Filter "*.ps1" | Where-Object { $_.Name -notlike "*.tests.ps1" }
    
    if ($Verbose) {
        Write-Output "Found $($scriptFiles.Count) script files to process"
    }
    
    # Group scripts by module type
    $moduleGroups = $scriptFiles | Group-Object { $_.Directory.Name }
    
    # Process each module group
    foreach ($group in $moduleGroups) {
        $moduleType = $group.Name
        
        if ($Verbose) {
            Write-Output "Processing $moduleType module scripts..."
        }
        
        # Add section header for this module type
        Add-Content -Path $OutputFile -Value "`n# -----------------------------------------------------------------------------"
        Add-Content -Path $OutputFile -Value "# $moduleType Module Functions"
        Add-Content -Path $OutputFile -Value "# -----------------------------------------------------------------------------`n"
        
        # Process each script in the group
        foreach ($script in $group.Group) {
            if ($Verbose) {
                Write-Output "  Processing $($script.Name)..."
            }
            
            # Read the script content
            $content = Get-Content -Path $script.FullName -Raw
            
            # Extract function definitions
            $functionMatches = [regex]::Matches($content, 'function\s+([A-Za-z0-9-]+)\s*{([^}]+)}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            
            foreach ($match in $functionMatches) {
                $functionName = $match.Groups[1].Value
                $functionBody = $match.Groups[2].Value
                
                # Add the function to the output file
                Add-Content -Path $OutputFile -Value "function $functionName {"
                Add-Content -Path $OutputFile -Value $functionBody
                Add-Content -Path $OutputFile -Value "}`n"
                
                if ($Verbose) {
                    Write-Output "    Added function: $functionName"
                }
            }
        }
    }
    
    # Write footer
    Write-Footer -OutputFile $OutputFile
    
    if ($Verbose) {
        Write-Output "Collection complete. Generated $OutputFile"
    }
}

# Execute the collection
Write-SectionHeader "Script Collection Generator"
Write-Output "Starting script collection process..."

Collect-Scripts -OutputFile $OutputFile -Verbose:$Verbose

Write-Output "`nCollection process complete. Generated $OutputFile" 