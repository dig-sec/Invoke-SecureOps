# -----------------------------------------------------------------------------
# Suspicious Process Detection Module
# -----------------------------------------------------------------------------

function Test-SuspiciousProcesses {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{},

        [Parameter()]
        [switch]$DetailedAnalysis,

        [Parameter()]
        [int]$MaxProcesses = 1000
    )

    Write-SectionHeader "Suspicious Process Analysis"
    Write-Output "Analyzing processes for suspicious behavior..."

    # Initialize test result
    $testResult = Initialize-TestResult -TestName "Test-SuspiciousProcesses" -Category "Security" -Description "Analyzes processes for suspicious behavior"

    try {
        # Performance optimization: Use a more efficient way to get processes
        Write-Output "Collecting process information..."
        $processes = Get-Process -ErrorAction Stop | Select-Object -First $MaxProcesses

        # Store process count information
        $processCount = @{
            TotalProcesses = $processes.Count
            AnalyzedProcesses = $processes.Count
            MaxProcesses = $MaxProcesses
        }

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

        # Create collections for findings
        $suspiciousProcesses = @()
        $highResourceProcesses = @()
        
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

                    $suspiciousProcesses += $processDetails
                }
            }

            # Check for high resource usage
            try {
                $cpuUsage = $process.CPU
                if ($cpuUsage -gt 80) {
                    $highResourceProcesses += @{
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
        if ($suspiciousProcesses.Count -gt 0) {
            Add-Finding -TestResult $testResult -FindingName "Suspicious Process Detection" -Status "Warning" `
                -Description "Found $($suspiciousProcesses.Count) suspicious processes" -RiskLevel "High" `
                -AdditionalInfo @{
                    SuspiciousProcesses = $suspiciousProcesses
                    ProcessCount = $processCount
                    Recommendation = "Review these processes to determine if they are legitimate"
                }
        }
        else {
            Add-Finding -TestResult $testResult -FindingName "Suspicious Process Detection" -Status "Pass" `
                -Description "No suspicious processes found" -RiskLevel "Info" `
                -AdditionalInfo @{
                    ProcessCount = $processCount
                }
        }

        # Add findings for high resource usage
        if ($highResourceProcesses.Count -gt 0) {
            Add-Finding -TestResult $testResult -FindingName "High Resource Usage Detection" -Status "Info" `
                -Description "Found $($highResourceProcesses.Count) processes with high resource usage" -RiskLevel "Low" `
                -AdditionalInfo @{
                    HighResourceProcesses = $highResourceProcesses
                    Recommendation = "Monitor these processes for potential performance issues"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Suspicious Process Analysis"
        Add-Finding -TestResult $testResult -FindingName "Process Analysis Error" -Status "Error" `
            -Description "Failed to analyze processes: $($_.Exception.Message)" -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    # Export results if output path provided
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousProcesses 