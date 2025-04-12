# -----------------------------------------------------------------------------
# Threat Hunting Analysis Module
# -----------------------------------------------------------------------------

function Test-ThreatHunting {
    param (
        [string]$OutputPath = ".\threat_hunting.json"
    )

    Write-SectionHeader "Threat Hunting Analysis"
    Write-Output "Starting comprehensive threat hunting analysis..."

    # Initialize JSON output object using common function
    $threatInfo = Initialize-JsonOutput -Category "ThreatHunting" -RiskLevel "High" -ActionLevel "Investigate"
    $threatInfo.SuspiciousActivities = @()
    $threatInfo.TotalChecks = 0
    $threatInfo.PassedChecks = 0
    $threatInfo.FailedChecks = 0
    $threatInfo.WarningChecks = 0

    try {
        # Test for suspicious processes
        Write-Output "Analyzing processes for suspicious behavior..."
        $processResults = Test-SuspiciousProcesses
        $threatInfo.SuspiciousActivities += $processResults.SuspiciousActivities
        $threatInfo.TotalChecks += $processResults.TotalChecks
        $threatInfo.PassedChecks += $processResults.PassedChecks
        $threatInfo.FailedChecks += $processResults.FailedChecks
        $threatInfo.WarningChecks += $processResults.WarningChecks

        # Test for suspicious network connections
        Write-Output "Analyzing network connections..."
        $networkResults = Test-SuspiciousConnections
        $threatInfo.SuspiciousActivities += $networkResults.SuspiciousActivities
        $threatInfo.TotalChecks += $networkResults.TotalChecks
        $threatInfo.PassedChecks += $networkResults.PassedChecks
        $threatInfo.FailedChecks += $networkResults.FailedChecks
        $threatInfo.WarningChecks += $networkResults.WarningChecks

        # Test for suspicious files
        Write-Output "Analyzing files for suspicious patterns..."
        $fileResults = Test-SuspiciousFiles
        $threatInfo.SuspiciousActivities += $fileResults.SuspiciousActivities
        $threatInfo.TotalChecks += $fileResults.TotalChecks
        $threatInfo.PassedChecks += $fileResults.PassedChecks
        $threatInfo.FailedChecks += $fileResults.FailedChecks
        $threatInfo.WarningChecks += $fileResults.WarningChecks

        # Test for suspicious registry entries
        Write-Output "Analyzing registry for suspicious entries..."
        $registryResults = Test-SuspiciousRegistry
        $threatInfo.SuspiciousActivities += $registryResults.SuspiciousActivities
        $threatInfo.TotalChecks += $registryResults.TotalChecks
        $threatInfo.PassedChecks += $registryResults.PassedChecks
        $threatInfo.FailedChecks += $registryResults.FailedChecks
        $threatInfo.WarningChecks += $registryResults.WarningChecks

        # Add overall finding
        if ($threatInfo.SuspiciousActivities.Count -gt 0) {
            Add-Finding -CheckName "Threat Hunting Analysis" -Status "Warning" `
                -Details "Found $($threatInfo.SuspiciousActivities.Count) suspicious activities" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    SuspiciousActivities = $threatInfo.SuspiciousActivities
                    TotalChecks = $threatInfo.TotalChecks
                    PassedChecks = $threatInfo.PassedChecks
                    FailedChecks = $threatInfo.FailedChecks
                    WarningChecks = $threatInfo.WarningChecks
                }
        }
        else {
            Add-Finding -CheckName "Threat Hunting Analysis" -Status "Pass" `
                -Details "No suspicious activities found" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    TotalChecks = $threatInfo.TotalChecks
                    PassedChecks = $threatInfo.PassedChecks
                    FailedChecks = $threatInfo.FailedChecks
                    WarningChecks = $threatInfo.WarningChecks
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Threat Hunting Analysis"
        Add-Finding -CheckName "Threat Hunting Analysis" -Status "Fail" `
            -Details "Failed to complete threat hunting analysis: $($_.Exception.Message)" -Category "ThreatHunting" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $threatInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }
}

# Export the function
Export-ModuleMember -Function Test-ThreatHunting 