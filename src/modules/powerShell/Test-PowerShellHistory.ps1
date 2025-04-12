# -----------------------------------------------------------------------------
# PowerShell Command History Analysis Module
# -----------------------------------------------------------------------------

function Test-PowerShellCommandHistory {
    param (
        [string]$OutputPath = ".\powershell_command_history.json"
    )

    Write-SectionHeader "PowerShell Command History Check"
    Write-Output "Analyzing PowerShell command history and suspicious commands..."

    # Initialize JSON output object using common function
    $historyInfo = Initialize-JsonOutput -Category "PowerShellCommandHistory" -RiskLevel "Medium" -ActionLevel "Review"

    try {
        # Get PowerShell history file
        $historyFile = (Get-PSReadlineOption).HistorySavePath
        
        # Get PowerShell history content
        $history = Get-Content -Path $historyFile -ErrorAction SilentlyContinue
        
        $historyInfo.HistoryFile = $historyFile
        $historyInfo.CommandCount = $history.Count
        $historyInfo.LastCommands = $history | Select-Object -Last 10

        # Add findings based on PowerShell history
        if ($history.Count -eq 0) {
            Add-Finding -CheckName "PowerShell Command History" -Status "Info" `
                -Details "No command history found" -Category "PowerShellCommandHistory" `
                -AdditionalInfo @{
                    Component = "CommandHistory"
                    Status = "Empty"
                    HistoryFile = $historyFile
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Command History" -Status "Info" `
                -Details "Found $($history.Count) commands in history" -Category "PowerShellCommandHistory" `
                -AdditionalInfo @{
                    Component = "CommandHistory"
                    Status = "Found"
                    CommandCount = $history.Count
                    HistoryFile = $historyFile
                }
        }

        # Check for suspicious commands
        $suspiciousPatterns = @(
            @{
                Pattern = "Invoke-Expression"
                Description = "PowerShell command execution"
                RiskLevel = "High"
            },
            @{
                Pattern = "DownloadString"
                Description = "Remote code execution"
                RiskLevel = "High"
            },
            @{
                Pattern = "reg add"
                Description = "Registry modification"
                RiskLevel = "Medium"
            }
        )

        $suspiciousCommands = @()
        foreach ($pattern in $suspiciousPatterns) {
            $matches = $history | Select-String -Pattern $pattern.Pattern
            if ($matches) {
                foreach ($match in $matches) {
                    $suspiciousCommands += @{
                        Command = $match.Line
                        Pattern = $pattern.Pattern
                        Description = $pattern.Description
                        RiskLevel = $pattern.RiskLevel
                    }
                }
            }
        }

        if ($suspiciousCommands.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Commands" -Status "Warning" `
                -Details "Found $($suspiciousCommands.Count) suspicious commands in history" -Category "PowerShellCommandHistory" `
                -AdditionalInfo @{
                    Component = "SuspiciousCommands"
                    Count = $suspiciousCommands.Count
                    Commands = $suspiciousCommands
                }
        }

        $historyInfo.SuspiciousCommands = $suspiciousCommands
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "PowerShell Command History Analysis"
        Add-Finding -CheckName "PowerShell Command History" -Status "Error" `
            -Details "Failed to check PowerShell command history: $($_.Exception.Message)" -Category "PowerShellCommandHistory" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $historyInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $historyInfo
}

# Export the function
Export-ModuleMember -Function Test-PowerShellCommandHistory 