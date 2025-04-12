# -----------------------------------------------------------------------------
# Windows Defender Status Analysis Module
# -----------------------------------------------------------------------------

function Test-DefenderStatus {
    param (
        [string]$OutputPath = ".\defender_status.json"
    )

    Write-SectionHeader "Windows Defender Status Analysis"
    Write-Output "Analyzing Windows Defender status..."

    # Initialize JSON output object
    $statusInfo = @{
        AntivirusEnabled = $null
        RealTimeProtectionEnabled = $null
        AntispywareEnabled = $null
        AntivirusSignatureAge = $null
        AntispywareSignatureAge = $null
        NISEnabled = $null
        NISSignatureAge = $null
        QuickScanSignatureAge = $null
        FullScanSignatureAge = $null
        SecurityRisk = "Windows Defender status issues detected"
        Recommendation = "Review and fix Windows Defender status issues"
    }

    # Get Windows Defender status
    $defenderStatus = Get-MpComputerStatus

    # Check antivirus status
    $statusInfo.AntivirusEnabled = $defenderStatus.AntivirusEnabled
    $statusInfo.RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
    $statusInfo.AntispywareEnabled = $defenderStatus.AntispywareEnabled

    # Check signature ages
    $statusInfo.AntivirusSignatureAge = $defenderStatus.AntivirusSignatureAge
    $statusInfo.AntispywareSignatureAge = $defenderStatus.AntispywareSignatureAge
    $statusInfo.NISEnabled = $defenderStatus.NISEnabled
    $statusInfo.NISSignatureAge = $defenderStatus.NISSignatureAge
    $statusInfo.QuickScanSignatureAge = $defenderStatus.QuickScanSignatureAge
    $statusInfo.FullScanSignatureAge = $defenderStatus.FullScanSignatureAge

    # Analyze status
    $issues = @()

    # Check antivirus status
    if (-not $statusInfo.AntivirusEnabled) {
        $issues += "Antivirus protection is disabled"
    }
    if (-not $statusInfo.RealTimeProtectionEnabled) {
        $issues += "Real-time protection is disabled"
    }
    if (-not $statusInfo.AntispywareEnabled) {
        $issues += "Antispyware protection is disabled"
    }

    # Check signature ages
    if ($statusInfo.AntivirusSignatureAge -gt 7) {
        $issues += "Antivirus signatures are outdated (Age: $($statusInfo.AntivirusSignatureAge) days)"
    }
    if ($statusInfo.AntispywareSignatureAge -gt 7) {
        $issues += "Antispyware signatures are outdated (Age: $($statusInfo.AntispywareSignatureAge) days)"
    }
    if ($statusInfo.NISEnabled -and $statusInfo.NISSignatureAge -gt 7) {
        $issues += "NIS signatures are outdated (Age: $($statusInfo.NISSignatureAge) days)"
    }
    if ($statusInfo.QuickScanSignatureAge -gt 7) {
        $issues += "Quick scan signatures are outdated (Age: $($statusInfo.QuickScanSignatureAge) days)"
    }
    if ($statusInfo.FullScanSignatureAge -gt 30) {
        $issues += "Full scan signatures are outdated (Age: $($statusInfo.FullScanSignatureAge) days)"
    }

    # Output results
    if ($issues.Count -gt 0) {
        Write-Output "Found Windows Defender status issues:"
        $issues | ForEach-Object {
            Write-Output "- $_"
        }

        Add-Finding -CheckName "Windows Defender Status" -Status "Fail" `
            -Details "Found $($issues.Count) status issues." -Category "Defender" `
            -AdditionalInfo @{
                Issues = $issues
                Status = $statusInfo
            }
    }
    else {
        Write-Output "No Windows Defender status issues found."
        Add-Finding -CheckName "Windows Defender Status" -Status "Pass" `
            -Details "No status issues detected." -Category "Defender" `
            -AdditionalInfo @{
                Status = $statusInfo
            }
    }

    # Export results to JSON if path specified
    if ($OutputPath) {
        $statusInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }
    
    return $statusInfo
}

# Export the function
Export-ModuleMember -Function Test-DefenderStatus 