# -----------------------------------------------------------------------------
# System Processes Analysis Module
# -----------------------------------------------------------------------------

function Test-SystemProcesses {
    param (
        [string]$OutputPath = ".\system_processes.json"
    )

    Write-SectionHeader "System Processes Analysis"
    Write-Output "Analyzing system processes..."

    # Initialize JSON output object using common function
    $processInfo = Initialize-JsonOutput -Category "ProcessAnalysis" -RiskLevel "High" -ActionLevel "Investigate"
    $processInfo.TotalProcesses = 0
    $processInfo.ProcessesByState = @{}
    $processInfo.ProcessesByUser = @{}

    try {
        # Get all processes
        $processes = Get-Process -ErrorAction Stop
        $processInfo.TotalProcesses = $processes.Count

        # Group processes by state
        $processInfo.ProcessesByState = $processes | Group-Object Responding | ForEach-Object {
            @{
                $_.Name = $_.Count
            }
        }

        # Group processes by user
        $processInfo.ProcessesByUser = $processes | Group-Object UserName | ForEach-Object {
            @{
                $_.Name = $_.Count
            }
        }

        # Check for suspicious processes
        $suspiciousPatterns = @(
            @{
                Pattern = "cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe"
                RiskLevel = "High"
                Category = "CommandShell"
            },
            @{
                Pattern = "netcat|nc\.exe|telnet\.exe"
                RiskLevel = "High"
                Category = "NetworkTool"
            },
            @{
                Pattern = "mimikatz|procdump|psexec"
                RiskLevel = "Critical"
                Category = "SecurityTool"
            }
        )

        $processInfo.SuspiciousProcesses = @()
        foreach ($pattern in $suspiciousPatterns) {
            $matches = $processes | Where-Object { $_.ProcessName -match $pattern.Pattern }
            if ($matches) {
                $processInfo.SuspiciousProcesses += @{
                    Pattern = $pattern.Pattern
                    Count = $matches.Count
                    RiskLevel = $pattern.RiskLevel
                    Category = $pattern.Category
                    Processes = $matches | ForEach-Object {
                        @{
                            ProcessName = $_.ProcessName
                            Id = $_.Id
                            UserName = $_.UserName
                            Path = $_.Path
                            StartTime = if ($_.StartTime) { $_.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                            CPU = $_.CPU
                            WorkingSet = $_.WorkingSet
                        }
                    }
                }
            }
        }

        # Add finding based on suspicious processes
        if ($processInfo.SuspiciousProcesses.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Processes" -Status "Warning" `
                -Details "Found $($processInfo.SuspiciousProcesses.Count) suspicious process patterns" -Category "ProcessAnalysis" `
                -AdditionalInfo @{
                    SuspiciousProcesses = $processInfo.SuspiciousProcesses
                    TotalProcessesAnalyzed = $processInfo.TotalProcesses
                }
        }
        else {
            Add-Finding -CheckName "Process Analysis" -Status "Pass" `
                -Details "No suspicious processes found" -Category "ProcessAnalysis" `
                -AdditionalInfo @{
                    TotalProcessesAnalyzed = $processInfo.TotalProcesses
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Process Analysis"
        Add-Finding -CheckName "Process Analysis" -Status "Fail" `
            -Details "Failed to analyze processes: $($_.Exception.Message)" -Category "ProcessAnalysis" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $processInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }
}

# Export the function
Export-ModuleMember -Function Test-SystemProcesses 