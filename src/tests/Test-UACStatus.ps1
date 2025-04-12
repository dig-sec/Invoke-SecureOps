# ... existing code ...
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
# ... existing code ...
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
# ... existing code ...
        Add-Finding -TestResult $result -FindingName "UAC Prompt Behavior" `
            -Status "Info" -RiskLevel "Info" `
            -Description "UAC prompt behavior is set to: $promptBehavior" `
            -AdditionalInfo @{
                Component = "UAC"
                Setting = "ConsentPromptBehaviorAdmin"
                Value = $uacSettings.ConsentPromptBehaviorAdmin
                Recommendation = "Consider using 'Always notify' for maximum security"
            }
# ... existing code ...
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
# ... existing code ...
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during UAC status test: $_" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and registry access"
            }
# ... existing code ... 