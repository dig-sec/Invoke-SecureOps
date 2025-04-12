# -----------------------------------------------------------------------------
# AMSI Bypass Detection Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for AMSI (Antimalware Scan Interface) bypasses.

.DESCRIPTION
    This function analyzes the system for potential AMSI bypasses and evasion techniques
    that could allow malicious scripts to execute without being detected.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of potential bypasses.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-AMSIBypass -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-AMSIBypass {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$DetailedAnalysis,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-AMSIBypass" -Category "Security" -Description "Checks for potential AMSI bypass techniques and vulnerabilities"
    
    try {
        # Check AMSI DLL integrity
        $amsiDllPath = "$env:SystemRoot\System32\amsi.dll"
        if (Test-Path $amsiDllPath) {
            $amsiDll = Get-Item $amsiDllPath
            $fileHash = Get-FileHash -Path $amsiDllPath -Algorithm SHA256
            
            Add-Finding -TestResult $result -Name "AMSI DLL Presence" -Status "Pass" -RiskLevel "Info" `
                -Description "AMSI DLL is present at expected location" `
                -Recommendation "No action required"
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result -FindingName "AMSI DLL Presence" `
                    -EvidenceType "FileInfo" -EvidenceData @{
                        Path = $amsiDllPath
                        Hash = $fileHash.Hash
                        Version = $amsiDll.VersionInfo.FileVersion
                        LastWriteTime = $amsiDll.LastWriteTime
                    }
            }
        }
        else {
            Add-Finding -TestResult $result -Name "AMSI DLL Missing" -Status "Critical" -RiskLevel "Critical" `
                -Description "AMSI DLL is missing from the expected location" `
                -Recommendation "Verify system integrity and reinstall AMSI components"
        }
        
        # Check AMSI provider registration
        $amsiProviders = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        if ($amsiProviders) {
            Add-Finding -TestResult $result -Name "AMSI Providers" -Status "Pass" -RiskLevel "Info" `
                -Description "AMSI providers are registered" `
                -Recommendation "No action required"
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result -FindingName "AMSI Providers" `
                    -EvidenceType "Registry" -EvidenceData $amsiProviders
            }
        }
        else {
            Add-Finding -TestResult $result -Name "AMSI Providers Missing" -Status "Critical" -RiskLevel "Critical" `
                -Description "No AMSI providers are registered" `
                -Recommendation "Verify antivirus software installation and AMSI integration"
        }
        
        # Check for common AMSI bypass indicators in PowerShell sessions
        $amsiBypassIndicators = @(
            '[Ref].Assembly.GetType',
            'System.Management.Automation.AmsiUtils',
            'amsiInitFailed',
            '[Runtime.InteropServices.Marshal]::WriteInt32',
            'AmsiScanBuffer'
        )
        
        $psHistory = Get-History -ErrorAction SilentlyContinue
        $suspiciousCommands = $psHistory | Where-Object {
            $command = $_.CommandLine
            $amsiBypassIndicators | Where-Object { $command -match $_ }
        }
        
        if ($suspiciousCommands) {
            Add-Finding -TestResult $result -Name "AMSI Bypass Attempts" -Status "Critical" -RiskLevel "Critical" `
                -Description "Detected potential AMSI bypass attempts in PowerShell history" `
                -Recommendation "Investigate suspicious PowerShell commands and implement additional monitoring"
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result -FindingName "AMSI Bypass Attempts" `
                    -EvidenceType "CommandHistory" -EvidenceData $suspiciousCommands
            }
        }
        else {
            Add-Finding -TestResult $result -Name "AMSI Bypass Detection" -Status "Pass" -RiskLevel "Info" `
                -Description "No AMSI bypass attempts detected in PowerShell history" `
                -Recommendation "Continue monitoring for suspicious activities"
        }
        
        # Check AMSI event logs
        $amsiEvents = Get-WinEvent -LogName "Microsoft-Windows-AMSI/Debug" -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) }
        
        if ($amsiEvents) {
            $suspiciousEvents = $amsiEvents | Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" }
            if ($suspiciousEvents) {
                Add-Finding -TestResult $result -Name "AMSI Events" -Status "Warning" -RiskLevel "Medium" `
                    -Description "Detected suspicious AMSI events in the last 7 days" `
                    -Recommendation "Review AMSI events for potential security issues"
                
                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result -FindingName "AMSI Events" `
                        -EvidenceType "EventLog" -EvidenceData $suspiciousEvents
                }
            }
            else {
                Add-Finding -TestResult $result -Name "AMSI Events" -Status "Pass" -RiskLevel "Info" `
                    -Description "No suspicious AMSI events detected in the last 7 days" `
                    -Recommendation "Continue monitoring AMSI events"
            }
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during AMSI bypass test: $_"
        Add-Finding -TestResult $result -Name "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "An error occurred while checking for AMSI bypass: $_" `
            -Recommendation "Check system permissions and AMSI configuration"
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-AMSIBypass 