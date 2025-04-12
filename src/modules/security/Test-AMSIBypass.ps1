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
        [hashtable]$CustomComparators
    )

    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-AMSIBypass" -Category "Security" -Description "Analysis of potential AMSI bypasses and evasion techniques"

    try {
        # Check if AMSI is available
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            Add-Finding -TestResult $result -FindingName "Windows Defender Not Available" -Status "Error" `
                -Description "Windows Defender PowerShell module is not available" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "AMSI"
                    Recommendation = "Ensure Windows Defender is installed and the PowerShell module is available"
                }
            return $result
        }

        # Check AMSI status
        $amsiStatus = Get-MpComputerStatus -ErrorAction Stop
        $amsiEnabled = $amsiStatus.AMServiceEnabled

        if (-not $amsiEnabled) {
            Add-Finding -TestResult $result -FindingName "AMSI Disabled" -Status "Critical" `
                -Description "AMSI is disabled on this system" -RiskLevel "Critical" `
                -AdditionalInfo @{
                    Component = "AMSI"
                    Status = "Disabled"
                    Recommendation = "Enable AMSI to prevent script-based attacks"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "AMSI Status" -Status "Pass" `
                -Description "AMSI is enabled on this system" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "AMSI"
                    Status = "Enabled"
                }
        }

        # Check for common AMSI bypass techniques in PowerShell history
        $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $psHistoryPath) {
            $psHistory = Get-Content -Path $psHistoryPath -ErrorAction SilentlyContinue
            
            # Define common AMSI bypass patterns
            $amsiBypassPatterns = @(
                @{
                    Pattern = "amsi\.utils"
                    Description = "AMSI Utils Bypass"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "amsi\.initfail"
                    Description = "AMSI InitFail Bypass"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "amsi\.scanbuffer"
                    Description = "AMSI ScanBuffer Bypass"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "amsi\.context"
                    Description = "AMSI Context Bypass"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "amsi\.dll"
                    Description = "AMSI DLL Bypass"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "bypass"
                    Description = "Generic Bypass Term"
                    RiskLevel = "Medium"
                },
                @{
                    Pattern = "amsi\.bypass"
                    Description = "AMSI Bypass Term"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "amsi\.disable"
                    Description = "AMSI Disable Term"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "amsi\.off"
                    Description = "AMSI Off Term"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "amsi\.fail"
                    Description = "AMSI Fail Term"
                    RiskLevel = "High"
                }
            )

            $foundBypasses = @()
            foreach ($pattern in $amsiBypassPatterns) {
                $matches = $psHistory | Select-String -Pattern $pattern.Pattern -AllMatches
                if ($matches) {
                    $foundBypasses += @{
                        Pattern = $pattern.Pattern
                        Description = $pattern.Description
                        RiskLevel = $pattern.RiskLevel
                        Occurrences = $matches.Count
                        Lines = $matches | ForEach-Object { $_.Line }
                    }
                }
            }

            if ($foundBypasses.Count -gt 0) {
                Add-Finding -TestResult $result -FindingName "AMSI Bypass Attempts" -Status "Warning" `
                    -Description "Found $($foundBypasses.Count) potential AMSI bypass attempts in PowerShell history" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "AMSI"
                        BypassCount = $foundBypasses.Count
                        Bypasses = $foundBypasses
                        Recommendation = "Investigate and remove any unauthorized AMSI bypass attempts"
                    }
            }
        }

        # Check for AMSI registry modifications
        $amsiRegistryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ServicePrincipalNames"
        )

        $registryModifications = @()
        foreach ($path in $amsiRegistryPaths) {
            if (Test-Path $path) {
                $registryValues = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($registryValues) {
                    $registryModifications += @{
                        Path = $path
                        Values = $registryValues
                    }
                }
            }
        }

        if ($registryModifications.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "AMSI Registry Modifications" -Status "Info" `
                -Description "Found $($registryModifications.Count) AMSI-related registry paths" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "AMSI"
                    RegistryCount = $registryModifications.Count
                    RegistryPaths = $registryModifications
                    Recommendation = "Review these registry paths for unauthorized modifications"
                }
        }

        # Check for AMSI DLL modifications
        $amsiDllPath = "$env:SystemRoot\System32\amsi.dll"
        if (Test-Path $amsiDllPath) {
            $amsiDllInfo = Get-Item -Path $amsiDllPath -ErrorAction SilentlyContinue
            if ($amsiDllInfo) {
                $amsiDllDetails = @{
                    Path = $amsiDllPath
                    Size = $amsiDllInfo.Length
                    CreationTime = $amsiDllInfo.CreationTime
                    LastWriteTime = $amsiDllInfo.LastWriteTime
                    LastAccessTime = $amsiDllInfo.LastAccessTime
                    Attributes = $amsiDllInfo.Attributes
                }

                # Check if the DLL has been modified recently (within the last 30 days)
                $recentModification = $amsiDllInfo.LastWriteTime -gt (Get-Date).AddDays(-30)
                if ($recentModification) {
                    Add-Finding -TestResult $result -FindingName "AMSI DLL Recent Modification" -Status "Warning" `
                        -Description "AMSI DLL was modified within the last 30 days" -RiskLevel "High" `
                        -AdditionalInfo @{
                            Component = "AMSI"
                            DLLInfo = $amsiDllDetails
                            LastModified = $amsiDllInfo.LastWriteTime
                            Recommendation = "Investigate recent modifications to the AMSI DLL"
                        }
                }
                else {
                    Add-Finding -TestResult $result -FindingName "AMSI DLL Status" -Status "Info" `
                        -Description "AMSI DLL is present and has not been recently modified" -RiskLevel "Low" `
                        -AdditionalInfo @{
                            Component = "AMSI"
                            DLLInfo = $amsiDllDetails
                        }
                }
            }
        }
        else {
            Add-Finding -TestResult $result -FindingName "AMSI DLL Missing" -Status "Critical" `
                -Description "AMSI DLL is missing from the system" -RiskLevel "Critical" `
                -AdditionalInfo @{
                    Component = "AMSI"
                    ExpectedPath = $amsiDllPath
                    Recommendation = "Restore the AMSI DLL from a trusted source"
                }
        }

        # Check for PowerShell execution policy bypasses
        $executionPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
        $executionPolicyBypass = $executionPolicy -eq "Bypass" -or $executionPolicy -eq "Unrestricted"
        
        if ($executionPolicyBypass) {
            Add-Finding -TestResult $result -FindingName "PowerShell Execution Policy Bypass" -Status "Warning" `
                -Description "PowerShell execution policy is set to $executionPolicy" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "PowerShell"
                    ExecutionPolicy = $executionPolicy
                    Recommendation = "Set PowerShell execution policy to Restricted or RemoteSigned"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "PowerShell Execution Policy" -Status "Pass" `
                -Description "PowerShell execution policy is set to $executionPolicy" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "PowerShell"
                    ExecutionPolicy = $executionPolicy
                }
            }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during AMSI bypass analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-AMSIBypass 