# -----------------------------------------------------------------------------
# AMSI Bypass Analysis Module
# -----------------------------------------------------------------------------

function Test-AMSIBypass {
    param (
        [string]$OutputPath = ".\amsi_analysis.json"
    )

    Write-SectionHeader "AMSI Bypass Analysis"
    Write-Output "Analyzing AMSI bypass attempts..."

    # Initialize JSON output object using common function
    $amsiInfo = Initialize-JsonOutput -Category "AMSIBypass" -RiskLevel "High" -ActionLevel "Review"
    $amsiInfo.TotalEventsChecked = 0
    $amsiInfo.BypassAttemptsDetected = 0
    $amsiInfo.BypassAttempts = @()

    # Define AMSI bypass patterns
    $bypassPatterns = @(
        @{
            Pattern = "amsiInitFailed"
            Description = "AMSI initialization failure"
            RiskLevel = "High"
        },
        @{
            Pattern = "System.Management.Automation.AmsiUtils"
            Description = "AMSI utility manipulation"
            RiskLevel = "High"
        },
        @{
            Pattern = "amsi\.dll"
            Description = "AMSI DLL manipulation"
            RiskLevel = "High"
        },
        @{
            Pattern = "amsiScanBuffer|amsiScanString"
            Description = "AMSI scan function manipulation"
            RiskLevel = "High"
        },
        @{
            Pattern = "amsi\.dll.*patch"
            Description = "AMSI DLL patching"
            RiskLevel = "Critical"
        }
    )

    # Get PowerShell events
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = 4104
    } -ErrorAction SilentlyContinue

    $amsiInfo.TotalEventsChecked = $events.Count

    # Check for bypass attempts
    $bypassAttempts = @()
    foreach ($event in $events) {
        foreach ($pattern in $bypassPatterns) {
            if ($event.Message -match $pattern.Pattern) {
                $bypassAttempts += @{
                    TimeCreated = $event.TimeCreated
                    Message = $event.Message
                    Pattern = $pattern.Description
                    RiskLevel = $pattern.RiskLevel
                }
                break
            }
        }
    }

    $amsiInfo.BypassAttempts = $bypassAttempts
    $amsiInfo.BypassAttemptsDetected = $bypassAttempts.Count

    # Export results to JSON
    Export-ToJson -Data $amsiInfo -FilePath $OutputPath -Pretty

    # Add findings
    Add-Finding -CheckName "AMSI Analysis" -Status "Info" -Details "Analyzed $($amsiInfo.TotalEventsChecked) events" -Category "AMSIBypass"
    
    if ($amsiInfo.BypassAttemptsDetected -gt 0) {
        $criticalAttempts = $bypassAttempts | Where-Object { $_.RiskLevel -eq "Critical" }
        if ($criticalAttempts.Count -gt 0) {
            Add-Finding -CheckName "Critical AMSI Bypass" -Status "Fail" -Details "Found $($criticalAttempts.Count) critical AMSI bypass attempts" -Category "AMSIBypass"
        }
        
        Add-Finding -CheckName "AMSI Bypass Attempts" -Status "Warning" -Details "Found $($amsiInfo.BypassAttemptsDetected) AMSI bypass attempts" -Category "AMSIBypass"
    }
    else {
        Add-Finding -CheckName "AMSI Bypass Attempts" -Status "Pass" -Details "No AMSI bypass attempts found" -Category "AMSIBypass"
    }

    return $amsiInfo
}

# Export the function
Export-ModuleMember -Function Test-AMSIBypass 