# -----------------------------------------------------------------------------
# UAC Status Test Module
# -----------------------------------------------------------------------------

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
        [switch]$CollectEvidence
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-UACStatus" `
                                  -Category "Security" `
                                  -Description "Analyzes User Account Control (UAC) settings" `
                                  -Status "Info" `
                                  -RiskLevel "Info"
    
    try {
        # Get UAC settings from registry
        $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacSettings = Get-ItemProperty -Path $uacKey -ErrorAction Stop
        
        # Check UAC status
        $uacEnabled = $uacSettings.EnableLUA -eq 1
        Add-Finding -TestResult $result `
            -Name "UAC Status" `
            -Status $(if ($uacEnabled) { "Pass" } else { "Critical" }) `
            -RiskLevel $(if ($uacEnabled) { "Info" } else { "Critical" }) `
            -Description "User Account Control is $(if ($uacEnabled) { 'enabled' } else { 'disabled' })" `
            -TechnicalDetails @{
                Component = "UAC"
                Setting = "EnableLUA"
                Value = $uacSettings.EnableLUA
                Recommendation = if (-not $uacEnabled) { "Enable User Account Control for better system security" }
            }
        
        # Check UAC virtualization
        $virtualizationEnabled = $uacSettings.EnableVirtualization -eq 1
        Add-Finding -TestResult $result `
            -Name "UAC Virtualization" `
            -Status $(if ($virtualizationEnabled) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($virtualizationEnabled) { "Info" } else { "Medium" }) `
            -Description "UAC virtualization is $(if ($virtualizationEnabled) { 'enabled' } else { 'disabled' })" `
            -TechnicalDetails @{
                Component = "UAC"
                Setting = "EnableVirtualization"
                Value = $uacSettings.EnableVirtualization
                Recommendation = if (-not $virtualizationEnabled) { "Enable UAC virtualization for better application compatibility" }
            }
        
        # Check UAC prompt behavior
        $promptBehavior = switch ($uacSettings.ConsentPromptBehaviorAdmin) {
            0 { "Elevate without prompting" }
            1 { "Prompt for credentials" }
            2 { "Prompt for consent" }
            5 { "Prompt for consent for non-Windows binaries" }
            default { "Unknown" }
        }
        Add-Finding -TestResult $result `
            -Name "UAC Prompt Behavior" `
            -Status "Info" `
            -RiskLevel "Info" `
            -Description "UAC prompt behavior is set to: $promptBehavior" `
            -TechnicalDetails @{
                Component = "UAC"
                Setting = "ConsentPromptBehaviorAdmin"
                Value = $uacSettings.ConsentPromptBehaviorAdmin
                Recommendation = "Consider using 'Always notify' for maximum security"
            }
        
        # Check admin approval mode
        $adminApprovalMode = $uacSettings.EnableInstallerDetection -eq 1
        Add-Finding -TestResult $result `
            -Name "Admin Approval Mode" `
            -Status $(if ($adminApprovalMode) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($adminApprovalMode) { "Info" } else { "Medium" }) `
            -Description "Admin approval mode is $(if ($adminApprovalMode) { 'enabled' } else { 'disabled' })" `
            -TechnicalDetails @{
                Component = "UAC"
                Setting = "EnableInstallerDetection"
                Value = $uacSettings.EnableInstallerDetection
                Recommendation = if (-not $adminApprovalMode) { "Enable admin approval mode for better security" }
            }
        
        # Add evidence if requested
        if ($CollectEvidence) {
            Add-Evidence -TestResult $result `
                -FindingName "UAC Configuration" `
                -EvidenceType "Registry" `
                -EvidenceData $uacSettings `
                -Description "UAC settings from registry"
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during UAC status test: $_"
        Add-Finding -TestResult $result `
            -Name "Test Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error during UAC status test: $_" `
            -TechnicalDetails @{
                Recommendation = "Check system permissions and registry access"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-UACStatus 