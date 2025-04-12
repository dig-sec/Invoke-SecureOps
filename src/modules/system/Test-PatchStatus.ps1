# -----------------------------------------------------------------------------
# Patch Management Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests Windows Update configuration and patch status.

.DESCRIPTION
    This function analyzes Windows Update settings, installed updates, and patch status
    to identify potential security issues and missing updates.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of installed updates.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-PatchStatus -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-PatchStatus {
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
    $result = Initialize-TestResult -TestName "Test-PatchStatus" -Category "System" -Description "Analysis of Windows Update configuration and patch status"

    try {
        # Get Windows Update service status
        $updateService = Get-Service -Name "wuauserv" -ErrorAction Stop
        
        # Get last update time
        $lastUpdate = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
        $daysSinceUpdate = if ($lastUpdate) { [math]::Round((Get-Date) - $lastUpdate.InstalledOn).TotalDays } else { 999 }
        
        # Get Windows Update settings
        $updateSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue
        
        # Check Windows Update service
        if ($updateService.Status -ne "Running") {
            Add-Finding -TestResult $result -FindingName "Windows Update Service" -Status "Fail" `
                -Description "Windows Update service is not running" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "WindowsUpdate"
                    ServiceStatus = $updateService.Status
                    Recommendation = "Start the Windows Update service and set it to Automatic"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Windows Update Service" -Status "Pass" `
                -Description "Windows Update service is running" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "WindowsUpdate"
                    ServiceStatus = $updateService.Status
                    StartType = $updateService.StartType
                }
        }

        # Check last update time
        if ($daysSinceUpdate -gt 30) {
            Add-Finding -TestResult $result -FindingName "Last Update Time" -Status "Warning" `
                -Description "System has not been updated in $daysSinceUpdate days" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "WindowsUpdate"
                    DaysSinceUpdate = $daysSinceUpdate
                    LastUpdate = $lastUpdate.InstalledOn
                    HotFixID = $lastUpdate.HotFixID
                    Recommendation = "Check for and install available Windows updates"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Last Update Time" -Status "Pass" `
                -Description "System updates are current" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "WindowsUpdate"
                    DaysSinceUpdate = $daysSinceUpdate
                    LastUpdate = $lastUpdate.InstalledOn
                    HotFixID = $lastUpdate.HotFixID
                }
        }

        # Check Windows Update settings
        if ($updateSettings) {
            if ($updateSettings.AUOptions -eq 1) {
                Add-Finding -TestResult $result -FindingName "Windows Update Settings" -Status "Warning" `
                    -Description "Windows Update is configured to notify before download" -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "WindowsUpdate"
                        Setting = "AUOptions"
                        CurrentValue = "Notify before download"
                        RecommendedValue = "Auto download and notify before install"
                        Recommendation = "Configure Windows Update to automatically download updates"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Update Settings" -Status "Pass" `
                    -Description "Windows Update is properly configured" -RiskLevel "Info" `
                    -AdditionalInfo @{
                        Component = "WindowsUpdate"
                        AUOptions = $updateSettings.AUOptions
                        CachedAUOptions = $updateSettings.CachedAUOptions
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
            -Description "Error during patch status analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-PatchStatus 