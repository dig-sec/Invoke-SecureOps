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
            
            Add-Finding -TestResult $result -FindingName "AMSI DLL Presence" -Status "Pass" -RiskLevel "Info" `
                -Description "AMSI DLL found at expected location" `
                -TechnicalDetails @{
                    Path = $amsiDllPath
                    FileVersion = (Get-Item $amsiDllPath).VersionInfo.FileVersion
                    Recommendation = "Continue monitoring for changes"
                }
            
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
            Add-Finding -TestResult $result -FindingName "AMSI DLL Missing" -Status "Critical" -RiskLevel "Critical" `
                -Description "AMSI DLL not found at expected location" `
                -TechnicalDetails @{
                    Path = $amsiDllPath
                    Recommendation = "Investigate potential AMSI bypass attempt"
                }
        }
        
        # Check AMSI providers
        $amsiProviders = Get-WmiObject -Namespace "root\Microsoft\Windows\AMSI" -Class MSFT_Provider -ErrorAction SilentlyContinue
        if ($amsiProviders) {
            Add-Finding -TestResult $result -FindingName "AMSI Providers" -Status "Pass" -RiskLevel "Info" `
                -Description "AMSI providers found and registered" `
                -TechnicalDetails @{
                    ProviderCount = $amsiProviders.Count
                    Providers = $amsiProviders | Select-Object Name, Version
                    Recommendation = "Continue monitoring for changes"
                }
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result -FindingName "AMSI Providers" `
                    -EvidenceType "Registry" -EvidenceData $amsiProviders
            }
        }
        else {
            Add-Finding -TestResult $result -FindingName "AMSI Providers Missing" -Status "Critical" -RiskLevel "Critical" `
                -Description "No AMSI providers found" `
                -TechnicalDetails @{
                    Recommendation = "Investigate potential AMSI bypass attempt"
                }
        }
        
        # Check for known AMSI bypass attempts in PowerShell history
        $bypassAttempts = @()
        $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $historyPath) {
            $bypassAttempts = Get-Content $historyPath | Where-Object {
                $_ -match "amsi\.dll|AmsiUtils|amsiInitFailed|System\.Management\.Automation\.AmsiUtils"
            }
        }
        
        if ($bypassAttempts) {
            Add-Finding -TestResult $result -FindingName "AMSI Bypass Attempts" -Status "Critical" -RiskLevel "Critical" `
                -Description "Found potential AMSI bypass attempts in PowerShell history" `
                -TechnicalDetails @{
                    AttemptCount = $bypassAttempts.Count
                    Attempts = $bypassAttempts
                    Recommendation = "Investigate these commands and the user who executed them"
                }
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result -FindingName "AMSI Bypass Attempts" `
                    -EvidenceType "CommandHistory" -EvidenceData $bypassAttempts
            }
        }
        else {
            Add-Finding -TestResult $result -FindingName "AMSI Bypass Detection" -Status "Pass" -RiskLevel "Info" `
                -Description "No AMSI bypass attempts found in PowerShell history" `
                -TechnicalDetails @{
                    Recommendation = "Continue monitoring for bypass attempts"
                }
        }
        
        # Check Windows Event Log for AMSI-related events
        $amsiEvents = Get-WinEvent -LogName "Microsoft-Windows-AMSI/Debug" -ErrorAction SilentlyContinue
        if ($amsiEvents) {
            Add-Finding -TestResult $result -FindingName "AMSI Events" -Status "Warning" -RiskLevel "Medium" `
                -Description "Found AMSI-related events in Windows Event Log" `
                -TechnicalDetails @{
                    EventCount = $amsiEvents.Count
                    RecentEvents = $amsiEvents | Select-Object -First 5 | ForEach-Object { @{
                        TimeCreated = $_.TimeCreated
                        Message = $_.Message
                    }}
                    Recommendation = "Review these events for potential security issues"
                }
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result -FindingName "AMSI Events" `
                    -EvidenceType "EventLog" -EvidenceData $amsiEvents
            }
        }
        else {
            Add-Finding -TestResult $result -FindingName "AMSI Events" -Status "Pass" -RiskLevel "Info" `
                -Description "No AMSI-related events found in Windows Event Log" `
                -TechnicalDetails @{
                    Recommendation = "Continue monitoring for AMSI events"
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
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "Error during AMSI bypass test: $_" `
            -TechnicalDetails @{
                Recommendation = "Check system permissions and AMSI configuration"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-AMSIBypass 