# -----------------------------------------------------------------------------
# Windows Defender Settings Analysis Module
# -----------------------------------------------------------------------------

function Test-DefenderSettings {
    param (
        [string]$OutputPath = ".\defender_settings.json"
    )

    Write-SectionHeader "Windows Defender Settings Analysis"
    Write-Output "Analyzing Windows Defender settings..."

    # Initialize JSON output object
    $settingsInfo = @{
        RealTimeProtection = $null
        CloudProtection = $null
        ScanSettings = $null
        SecurityRisk = "Insecure Windows Defender settings may reduce protection"
        Recommendation = "Review and adjust security settings"
    }

    # Get current settings
    $preferences = Get-MpPreference

    # Check real-time protection
    $settingsInfo.RealTimeProtection = @{
        DisableRealtimeMonitoring = $preferences.DisableRealtimeMonitoring
        DisableIOAVProtection = $preferences.DisableIOAVProtection
        DisableBehaviorMonitoring = $preferences.DisableBehaviorMonitoring
        DisableBlockAtFirstSeen = $preferences.DisableBlockAtFirstSeen
        DisablePrivacyMode = $preferences.DisablePrivacyMode
    }

    # Check cloud protection
    $settingsInfo.CloudProtection = @{
        MAPSReporting = $preferences.MAPSReporting
        SubmitSamplesConsent = $preferences.SubmitSamplesConsent
    }

    # Check scan settings
    $settingsInfo.ScanSettings = @{
        ScanScheduleDay = $preferences.ScanScheduleDay
        ScanScheduleTime = $preferences.ScanScheduleTime
        ScanParameters = $preferences.ScanParameters
        DisableArchiveScanning = $preferences.DisableArchiveScanning
        DisableRemovableDriveScanning = $preferences.DisableRemovableDriveScanning
    }

    # Analyze settings for security risks
    $securityIssues = @()

    # Check real-time protection settings
    if ($settingsInfo.RealTimeProtection.DisableRealtimeMonitoring) {
        $securityIssues += @{
            Category = "RealTimeProtection"
            Setting = "DisableRealtimeMonitoring"
            Issue = "Real-time protection is disabled"
            RiskLevel = "Critical"
        }
    }

    if ($settingsInfo.RealTimeProtection.DisableIOAVProtection) {
        $securityIssues += @{
            Category = "RealTimeProtection"
            Setting = "DisableIOAVProtection"
            Issue = "IOAV protection is disabled"
            RiskLevel = "High"
        }
    }

    # Check cloud protection settings
    if ($settingsInfo.CloudProtection.MAPSReporting -eq 0) {
        $securityIssues += @{
            Category = "CloudProtection"
            Setting = "MAPSReporting"
            Issue = "Cloud protection is disabled"
            RiskLevel = "High"
        }
    }

    # Check scan settings
    if ($settingsInfo.ScanSettings.DisableArchiveScanning) {
        $securityIssues += @{
            Category = "ScanSettings"
            Setting = "DisableArchiveScanning"
            Issue = "Archive scanning is disabled"
            RiskLevel = "Medium"
        }
    }

    # Output results
    if ($securityIssues.Count -gt 0) {
        Write-Output "Found security issues in Windows Defender settings:"
        $securityIssues | ForEach-Object {
            Write-Output "Category: $($_.Category)"
            Write-Output "Setting: $($_.Setting)"
            Write-Output "Issue: $($_.Issue)"
            Write-Output "Risk Level: $($_.RiskLevel)"
            Write-Output "---"
        }

        Add-Finding -CheckName "Windows Defender Settings" -Status "Fail" `
            -Details "Found $($securityIssues.Count) security issues in Windows Defender settings." -Category "Defender" `
            -AdditionalInfo @{
                Settings = $settingsInfo
                SecurityIssues = $securityIssues
            }
    }
    else {
        Write-Output "No security issues found in Windows Defender settings."
        Add-Finding -CheckName "Windows Defender Settings" -Status "Pass" `
            -Details "Windows Defender settings are secure." -Category "Defender" `
            -AdditionalInfo $settingsInfo
    }

    # Export results to JSON if path specified
    if ($OutputPath) {
        $settingsInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }
    
    return $settingsInfo
}

# Export the function
Export-ModuleMember -Function Test-DefenderSettings 