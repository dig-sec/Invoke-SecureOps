# Invoke-SecureOps

A comprehensive Windows security assessment and remediation toolkit for PowerShell.

<p align="center">
    <img src="docs/Invoke-SecureOps.png" alt="Invoke-SecureOps Logo" width="200" style="border-radius: 50%;">
</p>

## Overview

Invoke-SecureOps is a modular PowerShell framework designed to assess, detect, and remediate security issues on Windows systems. It provides a knowledge base of security checks that can be bundled into custom assessment scripts, with support for baseline comparison and detailed JSON reporting.

## Features

- **Modular Security Assessment**: Comprehensive security checks organized by category
- **Baseline Comparison**: Compare current system state against known good baselines
- **Detailed JSON Reporting**: Generate detailed reports for compliance and auditing
- **Evidence Collection**: Collect and store evidence for each security finding
- **Custom Assessment Generation**: Create tailored assessment scripts by selecting specific tests
- **Remediation Guidance**: Get detailed recommendations and mitigation strategies for each finding

## Project Structure

```
src/
├── modules/
│   ├── core/           # Core functionality and base templates
│   ├── security/       # Security assessment modules
│   ├── system/         # System configuration modules
│   ├── network/        # Network security modules
│   ├── powerShell/     # PowerShell security modules
│   ├── storage/        # Storage security modules
│   └── mitigations/    # Mitigation strategy modules
└── core/               # Core utilities and helpers
```

## Getting Started

### Prerequisites

- Windows 10/11 or Windows Server 2016/2019/2022
- PowerShell 5.1 or higher
- Administrative privileges

### Installation

1. Clone the repository:
   ```powershell
   git clone https://github.com/dig-sec/Invoke-SecureOps.git
   cd Invoke-SecureOps
   ```

2. Import the module:
   ```powershell
   Import-Module .\Invoke-SecureOps.psm1
   ```

### Quick Start Guide

1. **First-Time Setup**:
   ```powershell
   # Verify PowerShell version
   $PSVersionTable.PSVersion

   # Import the module
   Import-Module .\Invoke-SecureOps.psm1

   # Verify module is loaded
   Get-Module Invoke-SecureOps
   ```

2. **Basic Security Assessment**:
   ```powershell
   # Run a complete security assessment
   .\Invoke-SecureOps.ps1 -RunAll -OutputPath .\security_report.json -PrettyOutput

   # Run focused checks on critical areas
   .\Invoke-SecureOps.ps1 -Categories @("PowerShellSecurity", "Defender", "CredentialProtection") -OutputPath .\focused_report.json
   ```

3. **Understanding Results**:
   - After each run, a summary is displayed showing:
     - Total Tests Run
     - Passed Tests
     - Failed Tests
     - Critical Issues
     - Duration
   - Detailed results are saved in the specified JSON file
   - Review the JSON file for:
     - Test results
     - Findings
     - Risk levels
     - Evidence
     - Recommendations

4. **Best Practices**:
   - Run full assessments monthly
   - Run focused checks weekly
   - Keep historical reports for comparison
   - Address critical issues immediately
   - Document any manual fixes applied

5. **Common Use Cases**:
   ```powershell
   # Initial baseline assessment
   .\Invoke-SecureOps.ps1 -RunAll -OutputPath .\baseline.json

   # Regular security check
   .\Invoke-SecureOps.ps1 -Categories @("PowerShellSecurity", "Defender") -OutputPath .\daily_check.json

   # Compliance verification
   .\Invoke-SecureOps.ps1 -Categories @("SystemSecurity", "Storage") -OutputPath .\compliance_report.json

   # Auto-fix issues where possible
   .\Invoke-SecureOps.ps1 -RunAll -AutoFix -OutputPath .\fixed_report.json
   ```

6. **Troubleshooting**:
   - Ensure you have administrative privileges
   - Check error messages in the output
   - Verify the output path is writable
   - Use `-Verbose` for detailed output
   ```powershell
   # Get help
   Get-Help Invoke-SecureOps -Detailed

   # View available commands
   Get-Command -Module Invoke-SecureOps
   ```

## Usage

### Running a Security Assessment

```powershell
# Run a complete security assessment
Invoke-SecurityOperations -OutputPath .\security_report.json -PrettyOutput

# Run specific categories of tests
Invoke-SecurityOperations -Categories @("PowerShellSecurity", "Defender") -OutputPath .\focused_report.json

# Run specific tests
Invoke-SecurityOperations -SpecificTests @("Test-DefenderStatus", "Test-CredentialProtection") -OutputPath .\specific_report.json
```

### Creating a Baseline

```powershell
# Create a baseline of the current system state
Invoke-SecurityOperations -CreateBaseline -BaselinePath .\baseline.json
```

### Comparing Against Baseline

```powershell
# Compare current state against a baseline
Invoke-SecurityOperations -IncludeBaseline -BaselinePath .\baseline.json -OutputPath .\comparison_report.json
```

### Generating Custom Assessment Scripts

```powershell
# Generate a custom assessment script
New-SecurityAssessment -AssessmentName "CustomAssessment" -Categories @("PowerShellSecurity", "Defender") -OutputPath .\custom_assessment.ps1

# Generate a script with specific tests
New-SecurityAssessment -AssessmentName "FocusedAssessment" -SpecificTests @("Test-DefenderStatus", "Test-CredentialProtection") -OutputPath .\focused_assessment.ps1
```

### Getting Mitigation Strategies

```powershell
# Get mitigation strategies for security findings
Get-SecurityMitigations -FindingsPath .\security_report.json -OutputPath .\mitigation_strategies.json
```

## Test Modules

Each test module follows a standardized structure:

1. **Initialization**: Set up test parameters and initialize the test result
2. **Data Collection**: Gather relevant system data
3. **Analysis**: Analyze the data for security issues
4. **Finding Creation**: Create findings for each issue detected
5. **Evidence Collection**: Collect evidence for each finding
6. **Baseline Comparison**: Compare with baseline data if available
7. **Result Export**: Export the test results to JSON

### Example Test Module

```powershell
function Test-DefenderStatus {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath = ".\defender_status.json",
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$IncludeBaseline,
        
        [Parameter()]
        [string]$BaselinePath = ".\baseline.json",
        
        [Parameter()]
        [hashtable]$CustomParameters = @{},
        
        [Parameter()]
        [string]$ReportFormat = "JSON"
    )

    # Initialize test result
    $testResult = Initialize-TestResult -TestName "Test-DefenderStatus" `
        -Category "Windows Defender" `
        -Description "Analyzes Windows Defender status" `
        -Status "Info" `
        -RiskLevel "Info" `
        -Recommendation "Ensure Windows Defender is properly configured" `
        -Tags @("Defender", "Antivirus", "Security") `
        -ComplianceReference "CIS 8.1, NIST 800-53 SC-7" `
        -MitigationStrategy "Enable Windows Defender features" `
        -Dependencies @() `
        -CustomData @{}

    # Collect data
    $defenderStatus = Get-MpComputerStatus
    
    # Store current data for baseline comparison
    $currentData = @{
        AntivirusEnabled = $defenderStatus.AntivirusEnabled
        # ... more data ...
    }
    
    $testResult.CurrentData = $currentData

    # Load baseline data if requested
    $baselineData = @{}
    if ($IncludeBaseline -and (Test-Path $BaselinePath)) {
        $baselineData = Get-Content -Path $BaselinePath | ConvertFrom-Json -AsHashtable
        $testResult.BaselineData = $baselineData
    }

    # Check for issues
    if (-not $currentData.AntivirusEnabled) {
        $testResult = Add-TestFinding -TestResult $testResult `
            -FindingName "Antivirus Disabled" `
            -Status "Fail" `
            -Description "Antivirus protection is disabled" `
            -RiskLevel "Critical" `
            -Recommendation "Enable antivirus protection" `
            -ComplianceReference "CIS 8.1" `
            -MitigationStrategy "Enable Windows Defender antivirus protection" `
            -TechnicalDetails "Windows Defender antivirus is currently disabled" `
            -CustomData @{
                CurrentValue = $currentData.AntivirusEnabled
                ExpectedValue = $true
            }
        
        # Add evidence
        $testResult = Add-Evidence -TestResult $testResult `
            -FindingName "Antivirus Disabled" `
            -EvidenceType "Configuration" `
            -EvidenceData $currentData `
            -Description "Windows Defender configuration showing antivirus disabled" `
            -Metadata @{
                Source = "Get-MpComputerStatus"
                Timestamp = Get-Date
            }
    }

    # ... more checks ...

    # Compare with baseline if available
    if ($IncludeBaseline -and $baselineData.Count -gt 0) {
        $criticalFields = @("AntivirusEnabled", "RealTimeProtectionEnabled", "AntispywareEnabled")
        
        $fieldWeights = @{
            "AntivirusEnabled" = 1.0
            "RealTimeProtectionEnabled" = 1.0
            "AntispywareEnabled" = 1.0
            # ... more weights ...
        }
        
        $comparison = Compare-BaselineData -BaselineData $baselineData `
            -CurrentData $currentData `
            -CriticalFields $criticalFields `
            -FieldWeights $fieldWeights
        
        if ($comparison.Differences.Count -gt 0) {
            $testResult = Add-TestFinding -TestResult $testResult `
                -FindingName "Baseline Comparison" `
                -Status "Warning" `
                -Description "System state differs from baseline" `
                -RiskLevel $(if ($comparison.CriticalChanges -gt 0) { "Critical" } elseif ($comparison.HighChanges -gt 0) { "High" } else { "Medium" }) `
                -Recommendation "Review changes from baseline and ensure they are authorized" `
                -ComplianceReference "NIST 800-53 CA-7" `
                -MitigationStrategy "Review and revert unauthorized changes" `
                -TechnicalDetails "Overall change score: $($comparison.OverallChangeScore)" `
                -CustomData @{
                    CriticalChanges = $comparison.CriticalChanges
                    HighChanges = $comparison.HighChanges
                    MediumChanges = $comparison.MediumChanges
                    LowChanges = $comparison.LowChanges
                    OverallChangeScore = $comparison.OverallChangeScore
                }
            
            # Add evidence
            $testResult = Add-Evidence -TestResult $testResult `
                -FindingName "Baseline Comparison" `
                -EvidenceType "Comparison" `
                -EvidenceData $comparison.Differences `
                -Description "Differences between baseline and current state" `
                -Metadata @{
                    BaselineTimestamp = $baselineData.Timestamp
                    CurrentTimestamp = Get-Date
                }
        }
    }

    # If no findings were added, add a passing finding
    if ($testResult.Findings.Count -eq 0) {
        $testResult = Add-TestFinding -TestResult $testResult `
            -FindingName "Windows Defender Status" `
            -Status "Pass" `
            -Description "No Windows Defender status issues found" `
            -RiskLevel "Info" `
            -Recommendation "Continue regular monitoring" `
            -ComplianceReference "CIS 8.1" `
            -MitigationStrategy "None required" `
            -TechnicalDetails "All Windows Defender components are properly configured" `
            -CustomData @{
                Status = $currentData
            }
        
        # Add evidence
        $testResult = Add-Evidence -TestResult $testResult `
            -FindingName "Windows Defender Status" `
            -EvidenceType "Configuration" `
            -EvidenceData $currentData `
            -Description "Windows Defender configuration showing all components properly configured" `
            -Metadata @{
                Source = "Get-MpComputerStatus"
                Timestamp = Get-Date
            }
    }

    # Export results if path specified
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult `
            -OutputPath $OutputPath `
            -PrettyOutput:$PrettyOutput `
            -Format $ReportFormat
        Write-Output "Results exported to: $OutputPath"
    }
    
    return $testResult
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- CIS Benchmarks for Windows
- NIST Cybersecurity Framework
- Microsoft Security Baselines 