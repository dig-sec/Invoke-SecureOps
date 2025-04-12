# -----------------------------------------------------------------------------
# UAC Status Check
# -----------------------------------------------------------------------------

function Test-UACStatus {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
    )

    Write-SectionHeader "UAC Status Check"
    Write-Output "Analyzing User Account Control settings..."

    # Initialize test result
    $testResult = Initialize-JsonOutput -Category "Security" -RiskLevel "High"

    try {
        # Check if UAC is enabled
        $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop).EnableLUA -eq 1
        
        if ($uacEnabled) {
            Add-Finding -TestResult $testResult -FindingName "UAC Enabled" -Status "Pass" -Description "User Account Control is enabled" -RiskLevel "Info"
        } else {
            Add-Finding -TestResult $testResult -FindingName "UAC Enabled" -Status "Fail" -Description "User Account Control is disabled" -RiskLevel "High"
        }
        
        # Check UAC notification level
        $notificationLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction Stop).ConsentPromptBehaviorAdmin
        
        switch ($notificationLevel) {
            0 { 
                Add-Finding -TestResult $testResult -FindingName "UAC Notification Level" -Status "Warning" -Description "UAC is set to 'Never notify'" -RiskLevel "High"
            }
            1 { 
                Add-Finding -TestResult $testResult -FindingName "UAC Notification Level" -Status "Pass" -Description "UAC is set to 'Notify me only when programs try to make changes to my computer'" -RiskLevel "Info"
            }
            2 { 
                Add-Finding -TestResult $testResult -FindingName "UAC Notification Level" -Status "Pass" -Description "UAC is set to 'Notify me only when programs try to make changes to my computer (do not dim my desktop)'" -RiskLevel "Info"
            }
            3 { 
                Add-Finding -TestResult $testResult -FindingName "UAC Notification Level" -Status "Info" -Description "UAC is set to 'Always notify'" -RiskLevel "Info"
            }
            4 { 
                Add-Finding -TestResult $testResult -FindingName "UAC Notification Level" -Status "Info" -Description "UAC is set to 'Always notify and wait for my response'" -RiskLevel "Info"
            }
            5 { 
                Add-Finding -TestResult $testResult -FindingName "UAC Notification Level" -Status "Info" -Description "UAC is set to 'Always notify and wait for my response (do not dim my desktop)'" -RiskLevel "Info"
            }
            default { 
                Add-Finding -TestResult $testResult -FindingName "UAC Notification Level" -Status "Warning" -Description "Unknown UAC notification level: $notificationLevel" -RiskLevel "Medium"
            }
        }
        
        # Check if file and registry write failures are virtualized
        $virtualizationEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -ErrorAction Stop).EnableVirtualization -eq 1
        
        if ($virtualizationEnabled) {
            Add-Finding -TestResult $testResult -FindingName "UAC Virtualization" -Status "Pass" -Description "File and registry write failures are virtualized" -RiskLevel "Info"
        } else {
            Add-Finding -TestResult $testResult -FindingName "UAC Virtualization" -Status "Warning" -Description "File and registry write failures are not virtualized" -RiskLevel "Medium"
        }
        
        # Check if admin approval mode is enabled
        $adminApprovalMode = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -ErrorAction Stop).FilterAdministratorToken -eq 1
        
        if ($adminApprovalMode) {
            Add-Finding -TestResult $testResult -FindingName "Admin Approval Mode" -Status "Pass" -Description "Admin approval mode is enabled" -RiskLevel "Info"
        } else {
            Add-Finding -TestResult $testResult -FindingName "Admin Approval Mode" -Status "Warning" -Description "Admin approval mode is disabled" -RiskLevel "High"
        }
        
        # Check if UAC prompts on secure desktop
        $secureDesktop = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -ErrorAction Stop).PromptOnSecureDesktop -eq 1
        
        if ($secureDesktop) {
            Add-Finding -TestResult $testResult -FindingName "Secure Desktop" -Status "Pass" -Description "UAC prompts on secure desktop" -RiskLevel "Info"
        } else {
            Add-Finding -TestResult $testResult -FindingName "Secure Desktop" -Status "Warning" -Description "UAC prompts do not use secure desktop" -RiskLevel "Medium"
        }
    }
    catch {
        Write-Error "Error checking UAC status: $_"
        Add-Finding -TestResult $testResult -FindingName "UAC Status" -Status "Error" -Description "Failed to check UAC status: $_" -RiskLevel "High"
    }
    
    # Export results if output path provided
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
    }
    
    return $testResult
}

Export-ModuleMember -Function Test-UACStatus 