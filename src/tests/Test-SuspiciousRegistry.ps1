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
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-SuspiciousRegistry" -Category "Security" -Description "Analyzes registry for suspicious configurations and modifications"
    
    try {
        # Define suspicious registry paths and values to check
        $suspiciousLocations = @{
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" = @{
                Description = "Startup Programs (Machine)"
                RiskLevel = "Medium"
            }
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" = @{
                Description = "Startup Programs (User)"
                RiskLevel = "Medium"
            }
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" = @{
                Description = "Run Once Programs (Machine)"
                RiskLevel = "High"
            }
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" = @{
                Description = "Run Once Programs (User)"
                RiskLevel = "High"
            }
            "HKLM:\SYSTEM\CurrentControlSet\Services" = @{
                Description = "System Services"
                RiskLevel = "High"
            }
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" = @{
                Description = "Image File Execution Options"
                RiskLevel = "Critical"
            }
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
                Description = "Winlogon Configuration"
                RiskLevel = "Critical"
            }
        }
        
        foreach ($location in $suspiciousLocations.Keys) {
            if (Test-Path $location) {
                $values = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                $childItems = Get-ChildItem -Path $location -ErrorAction SilentlyContinue
                
                if ($values -or $childItems) {
                    $suspiciousEntries = @()
                    
                    # Check property values
                    if ($values) {
                        $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                            $suspiciousEntries += @{
                                Type = "Value"
                                Name = $_.Name
                                Value = $_.Value
                            }
                        }
                    }
                    
                    # Check child items
                    if ($childItems) {
                        $childItems | ForEach-Object {
                            $suspiciousEntries += @{
                                Type = "Key"
                                Name = $_.PSChildName
                                Path = $_.PSPath
                            }
                        }
                    }
                    
                    if ($suspiciousEntries.Count -gt 0) {
                        Add-Finding -TestResult $result -FindingName "$($suspiciousLocations[$location].Description)" `
                            -Status "Warning" -RiskLevel $suspiciousLocations[$location].RiskLevel `
                            -Description "Found $($suspiciousEntries.Count) entries in $location" `
                            -Recommendation "Review and verify all entries in this location"
                        
                        if ($CollectEvidence) {
                            Add-Evidence -TestResult $result -FindingName "$($suspiciousLocations[$location].Description)" `
                                -EvidenceType "Registry" -EvidenceData $suspiciousEntries `
                                -Description "Registry entries found in $location"
                        }
                    }
                    else {
                        Add-Finding -TestResult $result -FindingName "$($suspiciousLocations[$location].Description)" `
                            -Status "Pass" -RiskLevel "Info" `
                            -Description "No suspicious entries found in $location" `
                            -Recommendation "Continue monitoring for changes"
                    }
                }
            }
            else {
                Add-Finding -TestResult $result -FindingName "$($suspiciousLocations[$location].Description)" `
                    -Status "Info" -RiskLevel "Low" `
                    -Description "Registry path $location does not exist" `
                    -Recommendation "Monitor for creation of this registry path"
            }
        }
        
        # Check for specific suspicious values
        $suspiciousValues = @{
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" = @{
                Values = @(
                    @{
                        Name = "UseLogonCredential"
                        ExpectedValue = 0
                        Description = "WDigest Authentication"
                        RiskLevel = "Critical"
                    }
                )
            }
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                Values = @(
                    @{
                        Name = "EnableLUA"
                        ExpectedValue = 1
                        Description = "User Account Control"
                        RiskLevel = "Critical"
                    },
                    @{
                        Name = "ConsentPromptBehaviorAdmin"
                        ExpectedValue = 2
                        Description = "UAC Consent Prompt"
                        RiskLevel = "High"
                    }
                )
            }
        }
        
        foreach ($path in $suspiciousValues.Keys) {
            if (Test-Path $path) {
                foreach ($valueCheck in $suspiciousValues[$path].Values) {
                    $value = Get-ItemProperty -Path $path -Name $valueCheck.Name -ErrorAction SilentlyContinue
                    if ($value) {
                        $actualValue = $value.$($valueCheck.Name)
                        if ($actualValue -ne $valueCheck.ExpectedValue) {
                            Add-Finding -TestResult $result -FindingName $valueCheck.Description `
                                -Status "Warning" -RiskLevel $valueCheck.RiskLevel `
                                -Description "Suspicious value found: $($valueCheck.Name) = $actualValue (Expected: $($valueCheck.ExpectedValue))" `
                                -AdditionalInfo @{
                                    Recommendation = "Review and correct the registry value"
                                }
                            
                            if ($CollectEvidence) {
                                Add-Evidence -TestResult $result -FindingName $valueCheck.Description `
                                    -EvidenceType "Registry" -EvidenceData @{
                                        Path = $path
                                        Name = $valueCheck.Name
                                        ActualValue = $actualValue
                                        ExpectedValue = $valueCheck.ExpectedValue
                                    }
                            }
                        }
                        else {
                            Add-Finding -TestResult $result -FindingName $valueCheck.Description `
                                -Status "Pass" -RiskLevel "Info" `
                                -Description "$($valueCheck.Name) is set to the expected value" `
                                -AdditionalInfo @{
                                    Recommendation = "Continue monitoring for changes"
                                }
                        }
                    }
                }
            }
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during suspicious registry test: $_"
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "An error occurred while checking registry: $_" `
            -Recommendation "Check system permissions and registry access"
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousRegistry 