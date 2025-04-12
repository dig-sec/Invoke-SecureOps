# -----------------------------------------------------------------------------
# Command History Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for command history settings and configurations.

.DESCRIPTION
    This function analyzes the system's command history settings, including PowerShell history,
    command prompt history, and related security configurations.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of command history settings.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-CommandHistory -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-CommandHistory {
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
    $result = Initialize-TestResult -TestName "Test-CommandHistory" -Category "System" `
        -Description "Analyzes command history settings and configurations"

    try {
        # Check PowerShell history settings
        $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $psHistoryPath) {
            $psHistory = Get-Content -Path $psHistoryPath -ErrorAction SilentlyContinue
            $historySize = $psHistory.Count

            # Check history file size
            if ($historySize -gt 1000) {
                Add-Finding -TestResult $result -FindingName "Large PowerShell History" -Status "Warning" `
                    -Description "PowerShell history contains $historySize entries" -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "PowerShell"
                        Setting = "History Size"
                        CurrentValue = $historySize
                        Recommendation = "Consider clearing PowerShell history periodically"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "PowerShell History Size" -Status "Pass" `
                    -Description "PowerShell history size is manageable" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "PowerShell"
                        Setting = "History Size"
                        CurrentValue = $historySize
                    }
            }

            # Check for sensitive commands in history
            $sensitivePatterns = @(
                @{
                    Pattern = "password|credential|secret|key"
                    Description = "Sensitive Information"
                    RiskLevel = "High"
                },
                @{
                    Pattern = "net user|net localgroup"
                    Description = "User Management"
                    RiskLevel = "Medium"
                },
                @{
                    Pattern = "reg add|reg delete|reg modify"
                    Description = "Registry Modification"
                    RiskLevel = "Medium"
                }
            )

            $sensitiveCommands = @()
            foreach ($pattern in $sensitivePatterns) {
                $matches = $psHistory | Select-String -Pattern $pattern.Pattern -AllMatches
                if ($matches) {
                    $sensitiveCommands += @{
                        Pattern = $pattern.Pattern
                        Description = $pattern.Description
                        RiskLevel = $pattern.RiskLevel
                        Occurrences = $matches.Count
                    }
                }
            }

            if ($sensitiveCommands.Count -gt 0) {
                Add-Finding -TestResult $result -FindingName "Sensitive Commands in History" -Status "Warning" `
                    -Description "Found sensitive commands in PowerShell history" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "PowerShell"
                        Setting = "Command History"
                        SensitiveCommands = $sensitiveCommands
                        Recommendation = "Clear PowerShell history and avoid storing sensitive commands"
                    }
            }
        }

        # Check Command Prompt history settings
        $cmdHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Command History"
        if (Test-Path $cmdHistoryPath) {
            $cmdHistory = Get-ChildItem -Path $cmdHistoryPath -ErrorAction SilentlyContinue
            $historySize = $cmdHistory.Count

            if ($historySize -gt 100) {
                Add-Finding -TestResult $result -FindingName "Large Command Prompt History" -Status "Warning" `
                    -Description "Command Prompt history contains $historySize entries" -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "Command Prompt"
                        Setting = "History Size"
                        CurrentValue = $historySize
                        Recommendation = "Consider clearing Command Prompt history periodically"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Command Prompt History Size" -Status "Pass" `
                    -Description "Command Prompt history size is manageable" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Command Prompt"
                        Setting = "History Size"
                        CurrentValue = $historySize
                    }
            }
        }

        # Check PowerShell history size limit
        $historySizeLimit = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "MRUList" -ErrorAction SilentlyContinue
        if ($historySizeLimit) {
            Add-Finding -TestResult $result -FindingName "PowerShell History Limit" -Status "Info" `
                -Description "PowerShell history size limit is configured" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "PowerShell"
                    Setting = "History Limit"
                    Status = "Configured"
                }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during command history analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-CommandHistory 