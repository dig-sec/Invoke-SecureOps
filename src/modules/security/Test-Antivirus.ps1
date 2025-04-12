# -----------------------------------------------------------------------------
# Antivirus Status Check
# -----------------------------------------------------------------------------

function Test-Antivirus {
    Write-SectionHeader "Antivirus Status Check"
    Write-Output "Checking antivirus status..."

    try {
        # Check Windows Defender status
        $defenderStatus = Get-MpComputerStatus
        if ($defenderStatus.AntivirusEnabled) {
            Add-Finding -CheckName "Windows Defender" -Status "Pass" -Details "Windows Defender is enabled and running"
        } else {
            Add-Finding -CheckName "Windows Defender" -Status "Fail" -Details "Windows Defender is not enabled"
        }

        # Check for third-party antivirus
        $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction SilentlyContinue
        if ($avProducts) {
            foreach ($av in $avProducts) {
                $findingStatus = if ($av.productState -match "^(\d{2})(\d{2})(\d{2})") {
                    $state = [int]$matches[3]
                    if ($state -eq 0) { "Pass" } else { "Warning" }
                } else { "Warning" }
                
                Add-Finding -CheckName "Antivirus: $($av.displayName)" -Status $findingStatus -Details "Product State: $($av.productState)"
            }
        } else {
            Add-Finding -CheckName "Antivirus" -Status "Fail" -Details "No third-party antivirus detected"
        }

        # Fallback check using registry
        $avPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
        if (Test-Path $avPath) {
            $avEnabled = Get-ItemProperty -Path $avPath -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            if ($avEnabled.DisableAntiSpyware -eq 0) {
                Add-Finding -CheckName "Antivirus (Fallback Detection)" -Status "Pass" -Details "Windows Defender appears to be enabled via registry"
            }
        }

        # Summary
        Add-Finding -CheckName "Antivirus Status Summary" -Status "Info" -Details "Antivirus check completed"
    }
    catch {
        Write-Error "Error checking antivirus status: $_"
        Add-Finding -CheckName "Antivirus" -Status "Error" -Details "Failed to check antivirus status: $_"
    }
}

Export-ModuleMember -Function Test-Antivirus 