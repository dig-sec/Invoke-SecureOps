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
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-JsonOutput -Category "Security" -RiskLevel "Info" -ActionLevel "Review"
    $result.Description = "Analyzes User Account Control (UAC) configuration and settings"
    
    try {
        # Get UAC settings from registry
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacSettings = Get-ItemProperty -Path $uacPath -ErrorAction Stop
        
        # Check if UAC is enabled
        $uacEnabled = $uacSettings.EnableLUA -eq 1
        Add-Finding -TestResult $result -FindingName "UAC Status" `
            -Status $(if ($uacEnabled) { "Pass" } else { "Critical" }) `
            -RiskLevel $(if ($uacEnabled) { "Info" } else { "Critical" }) `
            -Description "User Account Control is $(if ($uacEnabled) { 'enabled' } else { 'disabled' })" `
            -AdditionalInfo @{
                Component = "UAC"
                Setting = "EnableLUA"
                Value = $uacSettings.EnableLUA
                Recommendation = if (-not $uacEnabled) { "Enable User Account Control for better system security" }
            }
        
        if ($CollectEvidence) {
            Add-Evidence -TestResult $result -FindingName "UAC Status" -EvidenceType "Registry" `
                -EvidenceData $uacSettings -Description "UAC registry settings"
        }
        
        # Check UAC virtualization
        $virtualizationEnabled = $uacSettings.EnableVirtualization -eq 1
        Add-Finding -TestResult $result -FindingName "UAC Virtualization" `
            -Status $(if ($virtualizationEnabled) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($virtualizationEnabled) { "Info" } else { "Medium" }) `
            -Description "UAC virtualization is $(if ($virtualizationEnabled) { 'enabled' } else { 'disabled' })" `
            -AdditionalInfo @{
                Component = "UAC"
                Setting = "EnableVirtualization"
                Value = $uacSettings.EnableVirtualization
                Recommendation = if (-not $virtualizationEnabled) { "Enable UAC virtualization for better application compatibility" }
            }
        
        # Check elevation prompt behavior
        $promptBehavior = switch ($uacSettings.PromptOnSecureDesktop) {
            1 { "Always notify" }
            0 { "Notify me only when programs try to make changes" }
            default { "Unknown" }
        }
        
        Add-Finding -TestResult $result -FindingName "UAC Prompt Behavior" `
            -Status "Info" -RiskLevel "Info" `
            -Description "UAC prompt behavior is set to: $promptBehavior" `
            -AdditionalInfo @{
                Component = "UAC"
                Setting = "ConsentPromptBehaviorAdmin"
                Value = $uacSettings.ConsentPromptBehaviorAdmin
                Recommendation = "Consider using 'Always notify' for maximum security"
            }
        
        # Check admin approval mode
        $adminApprovalMode = $uacSettings.EnableInstallerDetection -eq 1
        Add-Finding -TestResult $result -FindingName "Admin Approval Mode" `
            -Status $(if ($adminApprovalMode) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($adminApprovalMode) { "Info" } else { "Medium" }) `
            -Description "Admin approval mode is $(if ($adminApprovalMode) { 'enabled' } else { 'disabled' })" `
            -AdditionalInfo @{
                Component = "UAC"
                Setting = "EnableInstallerDetection"
                Value = $uacSettings.EnableInstallerDetection
                Recommendation = if (-not $adminApprovalMode) { "Enable admin approval mode for better security" }
            }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during UAC status test: $_"
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during UAC status test: $_" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and registry access"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-UACStatus 