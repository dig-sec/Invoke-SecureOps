# -----------------------------------------------------------------------------
# Windows Firewall Status Check
# -----------------------------------------------------------------------------

function Test-FirewallStatus {
    Write-SectionHeader "Windows Firewall Status Check"
    Write-Output "Checking Windows Firewall status..."

    try {
        # Get firewall profiles
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop

        foreach ($profile in $firewallProfiles) {
            $profileName = $profile.Name
            $enabled = $profile.Enabled
            $defaultInboundAction = $profile.DefaultInboundAction
            $defaultOutboundAction = $profile.DefaultOutboundAction
            $logAllowed = $profile.LogAllowed
            $logBlocked = $profile.LogBlocked
            $logFileName = $profile.LogFileName
            $logMaxSizeKilobytes = $profile.LogMaxSizeKilobytes

            # Check if firewall is enabled
            if ($enabled) {
                Add-Finding -CheckName "Firewall $profileName" -Status "Pass" -Details "Firewall is enabled for $profileName profile"
            } else {
                Add-Finding -CheckName "Firewall $profileName" -Status "Fail" -Details "Firewall is disabled for $profileName profile"
            }

            # Check default inbound action
            if ($defaultInboundAction -eq "Block") {
                Add-Finding -CheckName "Firewall $profileName Inbound" -Status "Pass" -Details "Default inbound action is set to Block"
            } else {
                Add-Finding -CheckName "Firewall $profileName Inbound" -Status "Warning" -Details "Default inbound action is set to $defaultInboundAction"
            }

            # Check default outbound action
            if ($defaultOutboundAction -eq "Allow") {
                Add-Finding -CheckName "Firewall $profileName Outbound" -Status "Pass" -Details "Default outbound action is set to Allow"
            } else {
                Add-Finding -CheckName "Firewall $profileName Outbound" -Status "Warning" -Details "Default outbound action is set to $defaultOutboundAction"
            }

            # Check logging settings
            if ($logAllowed -and $logBlocked) {
                Add-Finding -CheckName "Firewall $profileName Logging" -Status "Pass" -Details "Logging is enabled for both allowed and blocked connections"
            } elseif ($logAllowed) {
                Add-Finding -CheckName "Firewall $profileName Logging" -Status "Warning" -Details "Logging is enabled only for allowed connections"
            } elseif ($logBlocked) {
                Add-Finding -CheckName "Firewall $profileName Logging" -Status "Warning" -Details "Logging is enabled only for blocked connections"
            } else {
                Add-Finding -CheckName "Firewall $profileName Logging" -Status "Fail" -Details "Logging is disabled"
            }

            # Check log file settings
            if ($logFileName -and $logMaxSizeKilobytes -gt 0) {
                Add-Finding -CheckName "Firewall $profileName Log File" -Status "Info" -Details "Log file: $logFileName (Max size: $logMaxSizeKilobytes KB)"
            }
        }

        # Check for any active firewall rules
        $activeRules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
        if ($activeRules) {
            Add-Finding -CheckName "Active Firewall Rules" -Status "Info" -Details "Found $($activeRules.Count) active firewall rules"
        }
    }
    catch {
        Write-Error "Error checking firewall status: $_"
        Add-Finding -CheckName "Windows Firewall" -Status "Error" -Details "Failed to check firewall status: $_"
    }
}

Export-ModuleMember -Function Test-FirewallStatus 