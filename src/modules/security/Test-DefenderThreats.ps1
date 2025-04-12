# -----------------------------------------------------------------------------
# Windows Defender Threats Analysis Module
# -----------------------------------------------------------------------------

function Test-DefenderThreats {
    param (
        [string]$OutputPath = ".\defender_threats.json"
    )

    Write-SectionHeader "Windows Defender Threats Analysis"
    Write-Output "Analyzing Windows Defender threats..."

    # Initialize JSON output object
    $threatInfo = @{
        CurrentThreats = @()
        ThreatHistory = @()
        SecurityRisk = "Active threats detected"
        Recommendation = "Review and address detected threats"
    }

    # Get current threats
    $currentThreats = Get-MpThreatDetection -ErrorAction SilentlyContinue
    if ($currentThreats) {
        foreach ($threat in $currentThreats) {
            $threatInfo.CurrentThreats += @{
                ThreatID = $threat.ThreatID
                ThreatName = $threat.ThreatName
                Severity = $threat.SeverityID
                Category = $threat.ThreatCategoryID
                DetectionTime = $threat.InitialDetectionTime
                Status = $threat.ThreatStatus
                ActionRecommended = $threat.ActionRecommended
                Resources = $threat.Resources
            }
        }
    }

    # Get threat history
    $threatHistory = Get-MpThreat -ErrorAction SilentlyContinue
    if ($threatHistory) {
        foreach ($threat in $threatHistory) {
            $threatInfo.ThreatHistory += @{
                ThreatID = $threat.ThreatID
                ThreatName = $threat.ThreatName
                Severity = $threat.SeverityID
                Category = $threat.ThreatCategoryID
                DetectionTime = $threat.InitialDetectionTime
                ResolutionTime = $threat.ResolutionTime
                ActionTaken = $threat.ActionTaken
                Resources = $threat.Resources
            }
        }
    }

    # Analyze threats
    if ($threatInfo.CurrentThreats.Count -gt 0) {
        Write-Output "Found $($threatInfo.CurrentThreats.Count) active threats:"
        foreach ($threat in $threatInfo.CurrentThreats) {
            Write-Output "- $($threat.ThreatName) (Severity: $($threat.Severity), Status: $($threat.Status))"
        }

        Add-Finding -CheckName "Windows Defender Threats" -Status "Fail" `
            -Details "Found $($threatInfo.CurrentThreats.Count) active threats." -Category "Defender" `
            -AdditionalInfo @{
                CurrentThreats = $threatInfo.CurrentThreats
                ThreatHistory = $threatInfo.ThreatHistory
            }
    }
    else {
        Write-Output "No active threats found."
        Add-Finding -CheckName "Windows Defender Threats" -Status "Pass" `
            -Details "No active threats detected." -Category "Defender" `
            -AdditionalInfo @{
                CurrentThreats = $threatInfo.CurrentThreats
                ThreatHistory = $threatInfo.ThreatHistory
            }
    }

    # Export results to JSON if path specified
    if ($OutputPath) {
        $threatInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }
    
    return $threatInfo
}

# Export the function
Export-ModuleMember -Function Test-DefenderThreats 