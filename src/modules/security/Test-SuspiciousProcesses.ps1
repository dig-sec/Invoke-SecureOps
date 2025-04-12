# -----------------------------------------------------------------------------
# Suspicious Process Detection Module
# -----------------------------------------------------------------------------

function Test-SuspiciousProcesses {
    param (
        [string]$OutputPath = ".\suspicious_processes.json",
        [switch]$DetailedAnalysis,
        [int]$MaxProcesses = 1000
    )

    Write-SectionHeader "Suspicious Process Analysis"
    Write-Output "Analyzing processes for suspicious behavior..."

    # Check dependencies
    $dependencies = Test-Dependencies -RequiredModules @("Microsoft.PowerShell.Diagnostics") -RequiredCommands @("Get-Process", "Get-WmiObject")

    if (-not $dependencies.AllDependenciesMet) {
        Write-Warning "Missing dependencies. Some checks may not work correctly."
        Add-Finding -CheckName "Process Analysis" -Status "Warning" `
            -Details "Missing required dependencies for process analysis" -Category "ThreatHunting" `
            -AdditionalInfo @{
                MissingDependencies = $dependencies
                Recommendation = "Install missing dependencies and run the test again"
            }
    }

    # Initialize JSON output object using common function
    $processInfo = Initialize-JsonOutput -Category "SuspiciousProcesses" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Performance optimization: Use a more efficient way to get processes
        Write-Output "Collecting process information..."
        $processes = Get-Process -ErrorAction Stop | Select-Object -First $MaxProcesses
        $processInfo.TotalProcesses = $processes.Count
        $processInfo.AnalyzedProcesses = $processes.Count
        $processInfo.MaxProcesses = $MaxProcesses

        # Define suspicious process patterns
        $suspiciousPatterns = @(
            @{
                Name = "cmd.exe"
                Description = "Command prompt process"
                RiskLevel = "Medium"
            },
            @{
                Name = "powershell.exe"
                Description = "PowerShell process"
                RiskLevel = "Medium"
            },
            @{
                Name = "mimikatz"
                Description = "Credential dumping tool"
                RiskLevel = "Critical"
            },
            @{
                Name = "procdump"
                Description = "Process dumping tool"
                RiskLevel = "High"
            },
            @{
                Name = "wireshark"
                Description = "Network capture tool"
                RiskLevel = "Medium"
            },
            @{
                Name = "netcat"
                Description = "Network utility tool"
                RiskLevel = "High"
            },
            @{
                Name = "nmap"
                Description = "Network scanning tool"
                RiskLevel = "Medium"
            },
            @{
                Name = "psexec"
                Description = "Remote execution tool"
                RiskLevel = "High"
            }
        )

        # Performance optimization: Use hashtable for faster lookups
        $processInfo.SuspiciousProcesses = @()
        $processInfo.HighResourceProcesses = @()
        
        # Create a hashtable for faster pattern matching
        $patternLookup = @{}
        foreach ($pattern in $suspiciousPatterns) {
            $patternLookup[$pattern.Name] = $pattern
        }

        # Process analysis with progress tracking
        $processedCount = 0
        $totalToProcess = $processes.Count
        $progressInterval = [Math]::Max(1, [Math]::Floor($totalToProcess / 10))
        
        foreach ($process in $processes) {
            $processedCount++
            if ($processedCount % $progressInterval -eq 0) {
                $percentComplete = [Math]::Floor(($processedCount / $totalToProcess) * 100)
                Write-Progress -Activity "Analyzing Processes" -Status "$percentComplete% Complete" -PercentComplete $percentComplete
            }

            # Check for suspicious process names
            foreach ($patternName in $patternLookup.Keys) {
                if ($process.ProcessName -like "*$patternName*") {
                    $pattern = $patternLookup[$patternName]
                    $processDetails = @{
                        Type = "SuspiciousProcess"
                        Name = $process.ProcessName
                        Id = $process.Id
                        Description = $pattern.Description
                        RiskLevel = $pattern.RiskLevel
                        Path = "Unknown"
                        CommandLine = "Unknown"
                        ParentProcessId = "Unknown"
                        StartTime = "Unknown"
                    }

                    # Only collect detailed information if DetailedAnalysis is specified
                    if ($DetailedAnalysis) {
                        try {
                            $processDetails.Path = $process.Path
                        }
                        catch {
                            # Path not available
                        }

                        try {
                            $wmiProcess = Get-WmiObject Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction SilentlyContinue
                            if ($wmiProcess) {
                                $processDetails.CommandLine = $wmiProcess.CommandLine
                                $processDetails.ParentProcessId = $wmiProcess.ParentProcessId
                            }
                        }
                        catch {
                            # WMI information not available
                        }

                        try {
                            $processDetails.StartTime = $process.StartTime
                        }
                        catch {
                            # Start time not available
                        }
                    }

                    $processInfo.SuspiciousProcesses += $processDetails
                }
            }

            # Check for high resource usage
            try {
                $cpuUsage = $process.CPU
                if ($cpuUsage -gt 80) {
                    $processInfo.HighResourceProcesses += @{
                        Type = "HighResourceUsage"
                        Name = $process.ProcessName
                        Id = $process.Id
                        Description = "Process using high CPU"
                        RiskLevel = "Medium"
                        CPU = $cpuUsage
                        WorkingSet = $process.WorkingSet64
                    }
                }
            }
            catch {
                # CPU information not available
            }
        }

        Write-Progress -Activity "Analyzing Processes" -Completed

        # Add findings based on suspicious processes
        if ($processInfo.SuspiciousProcesses.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Processes" -Status "Warning" `
                -Details "Found $($processInfo.SuspiciousProcesses.Count) suspicious processes" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    SuspiciousProcesses = $processInfo.SuspiciousProcesses
                    TotalProcesses = $processInfo.TotalProcesses
                    AnalyzedProcesses = $processInfo.AnalyzedProcesses
                    Recommendation = "Review these processes to determine if they are legitimate"
                }
        }
        else {
            Add-Finding -CheckName "Suspicious Processes" -Status "Pass" `
                -Details "No suspicious processes found" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    TotalProcesses = $processInfo.TotalProcesses
                    AnalyzedProcesses = $processInfo.AnalyzedProcesses
                }
        }

        # Add findings for high resource usage
        if ($processInfo.HighResourceProcesses.Count -gt 0) {
            Add-Finding -CheckName "High Resource Usage" -Status "Info" `
                -Details "Found $($processInfo.HighResourceProcesses.Count) processes with high resource usage" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    HighResourceProcesses = $processInfo.HighResourceProcesses
                    Recommendation = "Monitor these processes for potential performance issues"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Suspicious Process Analysis"
        Add-Finding -CheckName "Process Analysis" -Status "Error" `
            -Details "Failed to analyze processes: $($_.Exception.Message)" -Category "ThreatHunting" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $processInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $processInfo
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousProcesses 