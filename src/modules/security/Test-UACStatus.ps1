# -----------------------------------------------------------------------------
# UAC Status Check
# -----------------------------------------------------------------------------

function Test-UACStatus {
    Write-SectionHeader "UAC Status Check"
    Write-Output "Checking User Account Control settings..."

    try {
        # Get UAC settings from registry
        $uacSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop

        # Check if UAC is enabled
        if ($uacSettings.EnableLUA -eq 1) {
            Add-Finding -CheckName "UAC Enabled" -Status "Pass" -Details "User Account Control is enabled"
        } else {
            Add-Finding -CheckName "UAC Enabled" -Status "Fail" -Details "User Account Control is disabled"
        }

        # Check UAC notification level
        $notificationLevel = $uacSettings.PromptBehavior
        switch ($notificationLevel) {
            0 { 
                Add-Finding -CheckName "UAC Notification Level" -Status "Warning" -Details "UAC is set to 'Never notify'"
            }
            1 { 
                Add-Finding -CheckName "UAC Notification Level" -Status "Pass" -Details "UAC is set to 'Notify me only when programs try to make changes to my computer'"
            }
            2 { 
                Add-Finding -CheckName "UAC Notification Level" -Status "Pass" -Details "UAC is set to 'Notify me only when programs try to make changes to my computer (do not dim my desktop)'"
            }
            3 { 
                Add-Finding -CheckName "UAC Notification Level" -Status "Info" -Details "UAC is set to 'Always notify'"
            }
            4 { 
                Add-Finding -CheckName "UAC Notification Level" -Status "Info" -Details "UAC is set to 'Always notify and wait for my response'"
            }
            5 { 
                Add-Finding -CheckName "UAC Notification Level" -Status "Info" -Details "UAC is set to 'Always notify and wait for my response (do not dim my desktop)'"
            }
            default {
                Add-Finding -CheckName "UAC Notification Level" -Status "Warning" -Details "Unknown UAC notification level: $notificationLevel"
            }
        }

        # Check if virtual file and registry write failures are virtualized
        if ($uacSettings.EnableVirtualization -eq 1) {
            Add-Finding -CheckName "UAC Virtualization" -Status "Pass" -Details "File and registry write failures are virtualized"
        } else {
            Add-Finding -CheckName "UAC Virtualization" -Status "Warning" -Details "File and registry write failures are not virtualized"
        }

        # Check if admin approval mode is enabled
        if ($uacSettings.EnableInstallerDetection -eq 1) {
            Add-Finding -CheckName "Admin Approval Mode" -Status "Pass" -Details "Admin approval mode is enabled"
        } else {
            Add-Finding -CheckName "Admin Approval Mode" -Status "Warning" -Details "Admin approval mode is disabled"
        }

        # Check if secure desktop is enabled
        if ($uacSettings.PromptOnSecureDesktop -eq 1) {
            Add-Finding -CheckName "Secure Desktop" -Status "Pass" -Details "UAC prompts on secure desktop"
        } else {
            Add-Finding -CheckName "Secure Desktop" -Status "Warning" -Details "UAC prompts do not use secure desktop"
        }
    }
    catch {
        Write-Error "Error checking UAC status: $_"
        Add-Finding -CheckName "UAC Status" -Status "Error" -Details "Failed to check UAC status: $_"
    }
}

Export-ModuleMember -Function Test-UACStatus 