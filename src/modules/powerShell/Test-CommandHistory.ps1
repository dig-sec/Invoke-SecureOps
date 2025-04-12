# -----------------------------------------------------------------------------
# Command History Analysis Module
# -----------------------------------------------------------------------------

function Test-CommandHistory {
    param (
        [int]$MaxHistoryEntries = 1000,
        [string]$OutputPath = ".\command_history_analysis.json"
    )

    Write-SectionHeader "PowerShell Command History Analysis"
    Write-Output "Analyzing PowerShell command history..."

    # Initialize JSON output object using common function
    $historyInfo = Initialize-JsonOutput -Category "CommandHistory" -RiskLevel "Medium" -ActionLevel "Review"
    $historyInfo.TotalCommandsAnalyzed = 0
    $historyInfo.SuspiciousCommandsFound = 0
    $historyInfo.SuspiciousCommands = @()

    # Get command history
    $history = Get-History -Count $MaxHistoryEntries -ErrorAction SilentlyContinue
    $historyInfo.TotalCommandsAnalyzed = $history.Count

    # Define suspicious patterns
    $suspiciousPatterns = @(
        @{
            Pattern = "Invoke-Expression|iex"
            Description = "PowerShell code execution"
            RiskLevel = "High"
        },
        @{
            Pattern = "DownloadString|WebClient|Invoke-WebRequest"
            Description = "File download or web request"
            RiskLevel = "High"
        },
        @{
            Pattern = "New-Object|Add-Type"
            Description = "Object creation or type loading"
            RiskLevel = "Medium"
        },
        @{
            Pattern = "Set-ExecutionPolicy|Bypass"
            Description = "Execution policy modification"
            RiskLevel = "High"
        },
        @{
            Pattern = "net\s+user|net\s+localgroup"
            Description = "User or group management"
            RiskLevel = "Medium"
        },
        @{
            Pattern = "net\s+share|net\s+use"
            Description = "Share or drive mapping"
            RiskLevel = "Medium"
        },
        @{
            Pattern = "netsh|firewall"
            Description = "Network configuration"
            RiskLevel = "High"
        },
        @{
            Pattern = "reg\s+add|reg\s+delete|reg\s+import"
            Description = "Registry modification"
            RiskLevel = "High"
        },
        @{
            Pattern = "schtasks|at\s+"
            Description = "Task scheduling"
            RiskLevel = "High"
        },
        @{
            Pattern = "sc\s+config|sc\s+create|sc\s+start|sc\s+stop"
            Description = "Service configuration"
            RiskLevel = "High"
        }
    )

    # Check for suspicious commands
    $suspiciousCommands = @()
    foreach ($command in $history) {
        foreach ($pattern in $suspiciousPatterns) {
            if ($command.CommandLine -match $pattern.Pattern) {
                $suspiciousCommands += @{
                    Id = $command.Id
                    CommandLine = $command.CommandLine
                    StartExecutionTime = $command.StartExecutionTime
                    EndExecutionTime = $command.EndExecutionTime
                    Pattern = $pattern.Description
                    RiskLevel = $pattern.RiskLevel
                }
                break
            }
        }
    }

    $historyInfo.SuspiciousCommands = $suspiciousCommands
    $historyInfo.SuspiciousCommandsFound = $suspiciousCommands.Count

    # Export results to JSON
    Export-ToJson -Data $historyInfo -FilePath $OutputPath -Pretty

    # Add findings
    Add-Finding -CheckName "Command History Analysis" -Status "Info" -Details "Analyzed $($historyInfo.TotalCommandsAnalyzed) commands" -Category "CommandHistory"
    
    if ($historyInfo.SuspiciousCommandsFound -gt 0) {
        $highRiskCommands = $suspiciousCommands | Where-Object { $_.RiskLevel -eq "High" }
        if ($highRiskCommands.Count -gt 0) {
            Add-Finding -CheckName "High-Risk Commands" -Status "Warning" -Details "Found $($highRiskCommands.Count) high-risk commands" -Category "CommandHistory"
        }
        
        Add-Finding -CheckName "Suspicious Commands" -Status "Warning" -Details "Found $($historyInfo.SuspiciousCommandsFound) suspicious commands" -Category "CommandHistory"
    }
    else {
        Add-Finding -CheckName "Suspicious Commands" -Status "Pass" -Details "No suspicious commands found" -Category "CommandHistory"
    }

    return $historyInfo
}

# Export the function
Export-ModuleMember -Function Test-CommandHistory 