# -----------------------------------------------------------------------------
# Suspicious Registry Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious registry entries and configurations.

.DESCRIPTION
    This function analyzes the Windows registry for suspicious entries, unauthorized
    modifications, and potential security risks.

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
    $result = Initialize-TestResult -TestName "Test-SuspiciousRegistry" -Category "Security" -Description "Analysis of suspicious registry entries and configurations"

    try {
        # Define suspicious registry patterns to check
        $suspiciousPatterns = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Description = "Startup Programs"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                Description = "One-time Startup Programs"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services"
                Description = "System Services"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                Description = "Winlogon Configuration"
                RiskLevel = "High"
            }
        )

        # Check each suspicious pattern
        foreach ($pattern in $suspiciousPatterns) {
            if (Test-Path $pattern.Path) {
                $entries = Get-ItemProperty -Path $pattern.Path -ErrorAction SilentlyContinue
                
                if ($entries) {
                    # Convert entries to a more manageable format
                    $entryList = $entries.PSObject.Properties | 
                        Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') } |
                        ForEach-Object {
                            @{
                                Name = $_.Name
                                Value = $_.Value
                                Type = $_.Type
                            }
                        }

                    if ($entryList.Count -gt 0) {
                        Add-Finding -TestResult $result -FindingName "Suspicious Registry: $($pattern.Description)" -Status "Warning" `
                            -Description "Found $($entryList.Count) entries in $($pattern.Path)" -RiskLevel $pattern.RiskLevel `
                            -AdditionalInfo @{
                                Component = "Registry"
                                Path = $pattern.Path
                                EntryCount = $entryList.Count
                                Entries = $entryList
                                Recommendation = "Review these entries for unauthorized modifications"
                            }
                    }
                }
            }
        }

        # Check for suspicious registry values
        $suspiciousValues = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "EnableLUA"
                ExpectedValue = 1
                Description = "User Account Control (UAC)"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                Name = "RestrictAnonymous"
                ExpectedValue = 1
                Description = "Anonymous Access Restriction"
                RiskLevel = "High"
            }
        )

        foreach ($value in $suspiciousValues) {
            if (Test-Path $value.Path) {
                $currentValue = Get-ItemProperty -Path $value.Path -Name $value.Name -ErrorAction SilentlyContinue
                
                if ($currentValue.$($value.Name) -ne $value.ExpectedValue) {
                    Add-Finding -TestResult $result -FindingName "Registry Value: $($value.Description)" -Status "Fail" `
                        -Description "$($value.Description) is not properly configured" -RiskLevel $value.RiskLevel `
                        -AdditionalInfo @{
                            Component = "Registry"
                            Path = $value.Path
                            Setting = $value.Name
                            CurrentValue = $currentValue.$($value.Name)
                            ExpectedValue = $value.ExpectedValue
                            Recommendation = "Set $($value.Name) to $($value.ExpectedValue)"
                        }
                }
                else {
                    Add-Finding -TestResult $result -FindingName "Registry Value: $($value.Description)" -Status "Pass" `
                        -Description "$($value.Description) is properly configured" -RiskLevel "Info" `
                        -AdditionalInfo @{
                            Component = "Registry"
                            Path = $value.Path
                            Setting = $value.Name
                            Value = $currentValue.$($value.Name)
                        }
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
            -Description "Error during registry analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousRegistry 