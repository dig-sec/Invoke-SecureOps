# -----------------------------------------------------------------------------
# Windows Defender Exclusions Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for Windows Defender exclusions and security settings.

.DESCRIPTION
    This function analyzes Windows Defender configuration to identify excluded paths,
    processes, and extensions that may pose security risks.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of exclusions.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-DefenderExclusions -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-DefenderExclusions {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$DetailedAnalysis,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators
    )

    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-DefenderExclusions" -Category "Security" -Description "Analysis of Windows Defender exclusions and security settings"

    try {
        # Check if Windows Defender is available
        if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
            Add-Finding -TestResult $result -FindingName "Windows Defender Not Available" -Status "Error" `
                -Description "Windows Defender PowerShell module is not available" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "WindowsDefender"
                    Recommendation = "Ensure Windows Defender is installed and the PowerShell module is available"
                }
            return $result
        }

        # Get Windows Defender preferences
        $defenderPrefs = Get-MpPreference -ErrorAction Stop

        # Check for excluded paths
        if ($defenderPrefs.ExclusionPath) {
            $excludedPaths = $defenderPrefs.ExclusionPath | ForEach-Object {
                @{
                    Path = $_
                    Type = "Path"
                    RiskLevel = "High"
                }
            }

            Add-Finding -TestResult $result -FindingName "Excluded Paths" -Status "Warning" `
                -Description "Found $($excludedPaths.Count) excluded paths in Windows Defender" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "WindowsDefender"
                    ExclusionType = "Path"
                    ExclusionCount = $excludedPaths.Count
                    Exclusions = $excludedPaths
                    Recommendation = "Review and remove unnecessary path exclusions"
                }
        }

        # Check for excluded processes
        if ($defenderPrefs.ExclusionProcess) {
            $excludedProcesses = $defenderPrefs.ExclusionProcess | ForEach-Object {
                @{
                    Process = $_
                    Type = "Process"
                    RiskLevel = "High"
                }
            }

            Add-Finding -TestResult $result -FindingName "Excluded Processes" -Status "Warning" `
                -Description "Found $($excludedProcesses.Count) excluded processes in Windows Defender" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "WindowsDefender"
                    ExclusionType = "Process"
                    ExclusionCount = $excludedProcesses.Count
                    Exclusions = $excludedProcesses
                    Recommendation = "Review and remove unnecessary process exclusions"
                }
        }

        # Check for excluded extensions
        if ($defenderPrefs.ExclusionExtension) {
            $excludedExtensions = $defenderPrefs.ExclusionExtension | ForEach-Object {
                @{
                    Extension = $_
                    Type = "Extension"
                    RiskLevel = "Medium"
                }
            }

            Add-Finding -TestResult $result -FindingName "Excluded Extensions" -Status "Warning" `
                -Description "Found $($excludedExtensions.Count) excluded file extensions in Windows Defender" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "WindowsDefender"
                    ExclusionType = "Extension"
                    ExclusionCount = $excludedExtensions.Count
                    Exclusions = $excludedExtensions
                    Recommendation = "Review and remove unnecessary extension exclusions"
                }
        }

        # Check for disabled features
        $disabledFeatures = @()
        
        if (-not $defenderPrefs.DisableRealtimeMonitoring) {
            $disabledFeatures += @{
                Feature = "RealtimeMonitoring"
                Status = "Enabled"
                RiskLevel = "Low"
            }
        }
        else {
            $disabledFeatures += @{
                Feature = "RealtimeMonitoring"
                Status = "Disabled"
                RiskLevel = "Critical"
            }
        }

        if (-not $defenderPrefs.DisableIOAVProtection) {
            $disabledFeatures += @{
                Feature = "IOAVProtection"
                Status = "Enabled"
                RiskLevel = "Low"
            }
        }
        else {
            $disabledFeatures += @{
                Feature = "IOAVProtection"
                Status = "Disabled"
                RiskLevel = "Critical"
            }
        }

        if (-not $defenderPrefs.DisableScriptScanning) {
            $disabledFeatures += @{
                Feature = "ScriptScanning"
                Status = "Enabled"
                RiskLevel = "Low"
            }
        }
        else {
            $disabledFeatures += @{
                Feature = "ScriptScanning"
                Status = "Disabled"
                RiskLevel = "Critical"
            }
        }

        # Add finding for disabled features
        $disabledCount = ($disabledFeatures | Where-Object { $_.Status -eq "Disabled" }).Count
        if ($disabledCount -gt 0) {
            Add-Finding -TestResult $result -FindingName "Disabled Features" -Status "Warning" `
                -Description "Found $disabledCount disabled Windows Defender features" -RiskLevel "Critical" `
                -AdditionalInfo @{
                    Component = "WindowsDefender"
                    FeatureCount = $disabledCount
                    Features = $disabledFeatures
                    Recommendation = "Enable all Windows Defender features for maximum protection"
                }
        }

        # Check scan settings
        $scanSettings = @{
            ScanScheduleDay = $defenderPrefs.ScanScheduleDay
            ScanScheduleTime = $defenderPrefs.ScanScheduleTime
            ScanParameters = $defenderPrefs.ScanParameters
            ScanScheduleQuickScanTime = $defenderPrefs.ScanScheduleQuickScanTime
            ScanScheduleQuickScanDay = $defenderPrefs.ScanScheduleQuickScanDay
        }

        Add-Finding -TestResult $result -FindingName "Scan Settings" -Status "Info" `
            -Description "Current Windows Defender scan settings" -RiskLevel "Low" `
            -AdditionalInfo @{
                Component = "WindowsDefender"
                Settings = $scanSettings
                Recommendation = "Ensure scan schedule is appropriate for your environment"
            }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during Windows Defender analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-DefenderExclusions 