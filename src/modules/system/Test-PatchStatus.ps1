# -----------------------------------------------------------------------------
# Windows Patch Status Check
# -----------------------------------------------------------------------------

function Test-PatchStatus {
    Write-SectionHeader "Windows Patch Status Check"
    Write-Output "Checking Windows patch status..."

    try {
        # Get installed updates
        $updates = Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending
        $latestUpdate = $updates | Select-Object -First 1

        if ($latestUpdate) {
            $lastPatchDate = [DateTime]::Parse($latestUpdate.InstalledOn)
            $daysSinceLastPatch = (Get-Date) - $lastPatchDate

            if ($daysSinceLastPatch.Days -le 30) {
                Add-Finding -CheckName "Windows Patches" -Status "Pass" -Details "Last patch installed on $($lastPatchDate.ToShortDateString())"
            } elseif ($daysSinceLastPatch.Days -le 90) {
                Add-Finding -CheckName "Windows Patches" -Status "Warning" -Details "Last patch installed on $($lastPatchDate.ToShortDateString()) - $($daysSinceLastPatch.Days) days ago"
            } else {
                Add-Finding -CheckName "Windows Patches" -Status "Fail" -Details "Last patch installed on $($lastPatchDate.ToShortDateString()) - $($daysSinceLastPatch.Days) days ago"
            }

            # Check for critical updates
            $criticalUpdates = $updates | Where-Object { $_.Description -match "Critical" }
            if ($criticalUpdates) {
                Add-Finding -CheckName "Critical Updates" -Status "Info" -Details "Found $($criticalUpdates.Count) critical updates installed"
            }
        } else {
            Add-Finding -CheckName "Windows Patches" -Status "Warning" -Details "No patch history found"
        }

        # Check Windows Update service status
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($wuService) {
            if ($wuService.Status -eq "Running") {
                Add-Finding -CheckName "Windows Update Service" -Status "Pass" -Details "Windows Update service is running"
            } else {
                Add-Finding -CheckName "Windows Update Service" -Status "Fail" -Details "Windows Update service is not running"
            }
        } else {
            Add-Finding -CheckName "Windows Update Service" -Status "Error" -Details "Could not find Windows Update service"
        }
    }
    catch {
        Write-Error "Error checking patch status: $_"
        Add-Finding -CheckName "Windows Patches" -Status "Error" -Details "Failed to check patch status: $_"
    }
}

Export-ModuleMember -Function Test-PatchStatus 