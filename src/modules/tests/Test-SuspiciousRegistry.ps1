# -----------------------------------------------------------------------------
# Suspicious Registry Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious registry entries.

.DESCRIPTION
    This function analyzes the Windows registry for suspicious entries,
    unauthorized modifications, and potential security risks.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of registry entries.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-SuspiciousRegistry -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-SuspiciousRegistry {
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
        [hashtable]$CustomComparators
    )

    # Initialize test result
    $result = Initialize-JsonOutput -Category "Security" -RiskLevel "Info" -ActionLevel "Review"
    $result.Description = "Analysis of suspicious registry entries and modifications"

    try {
        # Define suspicious registry paths to check
        $suspiciousPaths = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Description = "Auto-start programs"
                RiskLevel = "Medium"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                Description = "One-time auto-start programs"
                RiskLevel = "Medium"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                Description = "Logon settings"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services"
                Description = "System services"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Description = "System policies"
                RiskLevel = "High"
            }
        )
        
        # Check each suspicious path
        foreach ($pathInfo in $suspiciousPaths) {
            if (Test-Path -Path $pathInfo.Path) {
                $registryEntries = Get-ItemProperty -Path $pathInfo.Path -ErrorAction SilentlyContinue
                
                if ($registryEntries) {
                    $entryDetails = @()
                    
                    foreach ($entry in $registryEntries.PSObject.Properties) {
                        if ($entry.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                            $entryDetails += @{
                                Name = $entry.Name
                                Value = $entry.Value
                                Type = $entry.Type
                            }
                        }
                    }
                    
                    if ($entryDetails.Count -gt 0) {
                        Add-Finding -TestResult $result -FindingName "Suspicious Registry Entries" `
                            -Status "Warning" -RiskLevel $pathInfo.RiskLevel `
                            -Description "Found $($entryDetails.Count) entries in $($pathInfo.Path) ($($pathInfo.Description))" `
                            -AdditionalInfo @{
                                Component = "Registry"
                                Path = $pathInfo.Path
                                Description = $pathInfo.Description
                                EntryCount = $entryDetails.Count
                                Entries = $entryDetails
                                Recommendation = "Review these registry entries and verify they are authorized"
                            }
                        
                        if ($CollectEvidence) {
                            Add-Evidence -TestResult $result `
                                -FindingName "Registry Entries" `
                                -EvidenceType "Registry" `
                                -EvidenceData @{
                                    Path = $pathInfo.Path
                                    Description = $pathInfo.Description
                                    Entries = $entryDetails
                                } `
                                -Description "Registry entries in $($pathInfo.Path)"
                        }
                    }
                }
            }
        }
        
        # Check for suspicious registry modifications
        $suspiciousModifications = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Key = "EnableLUA"
                ExpectedValue = 1
                Description = "User Account Control (UAC) enabled"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Key = "ConsentPromptBehaviorAdmin"
                ExpectedValue = 2
                Description = "UAC admin approval mode"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                Key = "RestrictAnonymous"
                ExpectedValue = 1
                Description = "Restrict anonymous access"
                RiskLevel = "Medium"
            }
        )
        
        foreach ($modification in $suspiciousModifications) {
            if (Test-Path -Path $modification.Path) {
                $registryValue = Get-ItemProperty -Path $modification.Path -Name $modification.Key -ErrorAction SilentlyContinue
                
                if ($registryValue) {
                    $actualValue = $registryValue.$($modification.Key)
                    
                    if ($actualValue -ne $modification.ExpectedValue) {
                        Add-Finding -TestResult $result -FindingName "Suspicious Registry Modification" `
                            -Status "Warning" -RiskLevel $modification.RiskLevel `
                            -Description "Registry value $($modification.Key) in $($modification.Path) is set to $actualValue, expected $($modification.ExpectedValue) for $($modification.Description)" `
                            -AdditionalInfo @{
                                Component = "Registry"
                                Path = $modification.Path
                                Key = $modification.Key
                                ExpectedValue = $modification.ExpectedValue
                                ActualValue = $actualValue
                                Description = $modification.Description
                                Recommendation = "Review and correct this registry setting"
                            }
                        
                        if ($CollectEvidence) {
                            Add-Evidence -TestResult $result `
                                -FindingName "Registry Modification" `
                                -EvidenceType "Registry" `
                                -EvidenceData @{
                                    Path = $modification.Path
                                    Key = $modification.Key
                                    ExpectedValue = $modification.ExpectedValue
                                    ActualValue = $actualValue
                                    Description = $modification.Description
                                } `
                                -Description "Registry modification in $($modification.Path)"
                        }
                    }
                }
            }
        }
        
        # Export results if path is provided
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Registry Analysis"
        
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during registry analysis: $($errorInfo.ErrorMessage)" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and registry access"
            }
        
        # Export results if path is provided
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
} 