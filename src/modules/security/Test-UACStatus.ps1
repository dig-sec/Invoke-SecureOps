# -----------------------------------------------------------------------------
# User Account Control (UAC) Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests User Account Control (UAC) configuration and status.

.DESCRIPTION
    This function analyzes UAC settings, elevation behavior, and related security
    configurations to ensure proper security controls are in place.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of UAC settings.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-UACStatus -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-UACStatus {
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
    $result = Initialize-TestResult -TestName "Test-UACStatus" -Category "Security" -Description "Analysis of User Account Control (UAC) configuration and status"

    try {
        # Get UAC settings from registry
        $uacSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop

        # Check if UAC is enabled
        if ($uacSettings.EnableLUA -ne 1) {
            Add-Finding -TestResult $result -FindingName "UAC Status" -Status "Fail" `
                -Description "User Account Control (UAC) is disabled" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "EnableLUA"
                    CurrentValue = $uacSettings.EnableLUA
                    ExpectedValue = 1
                    Recommendation = "Enable User Account Control (UAC) for better security"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "UAC Status" -Status "Pass" `
                -Description "User Account Control (UAC) is enabled" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "EnableLUA"
                    Value = $uacSettings.EnableLUA
                }
        }

        # Check UAC elevation behavior
        if ($uacSettings.EnableVirtualization -ne 1) {
            Add-Finding -TestResult $result -FindingName "UAC Virtualization" -Status "Warning" `
                -Description "UAC virtualization is disabled" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "EnableVirtualization"
                    CurrentValue = $uacSettings.EnableVirtualization
                    ExpectedValue = 1
                    Recommendation = "Enable UAC virtualization for better application compatibility"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "UAC Virtualization" -Status "Pass" `
                -Description "UAC virtualization is enabled" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "EnableVirtualization"
                    Value = $uacSettings.EnableVirtualization
                }
        }

        # Check UAC elevation prompt behavior
        $promptBehavior = switch ($uacSettings.PromptOnSecureDesktop) {
            0 { "No prompt" }
            1 { "Prompt on secure desktop" }
            default { "Unknown" }
        }

        if ($uacSettings.PromptOnSecureDesktop -ne 1) {
            Add-Finding -TestResult $result -FindingName "UAC Prompt Behavior" -Status "Warning" `
                -Description "UAC elevation prompt is not configured securely" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "PromptOnSecureDesktop"
                    CurrentValue = $promptBehavior
                    ExpectedValue = "Prompt on secure desktop"
                    Recommendation = "Configure UAC to prompt on secure desktop"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "UAC Prompt Behavior" -Status "Pass" `
                -Description "UAC elevation prompt is properly configured" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "PromptOnSecureDesktop"
                    Value = $promptBehavior
                }
        }

        # Check for admin approval mode
        if ($uacSettings.EnableInstallerDetection -ne 1) {
            Add-Finding -TestResult $result -FindingName "UAC Admin Approval" -Status "Warning" `
                -Description "UAC admin approval mode is disabled" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "EnableInstallerDetection"
                    CurrentValue = $uacSettings.EnableInstallerDetection
                    ExpectedValue = 1
                    Recommendation = "Enable UAC admin approval mode for better security"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "UAC Admin Approval" -Status "Pass" `
                -Description "UAC admin approval mode is enabled" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "UAC"
                    Setting = "EnableInstallerDetection"
                    Value = $uacSettings.EnableInstallerDetection
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
            -Description "Error during UAC status analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-UACStatus 