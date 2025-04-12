# -----------------------------------------------------------------------------
# Process Network Connections Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious process network connections.

.DESCRIPTION
    This function analyzes process network connections to identify
    suspicious activities, unauthorized connections, and potential security risks.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of process connections.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-ProcessConnections -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-ProcessConnections {
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
    $result = Initialize-JsonOutput -Category "Security" -RiskLevel "Info" -ActionLevel "Review"
    $result.Description = "Analysis of process network connections and activities"

    try {
        # Get all established TCP connections
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop
        
        # Get process information for connections
        $processes = Get-Process -Id $connections.OwningProcess -ErrorAction SilentlyContinue
        
        # Group connections by process
        $processConnections = $connections | Group-Object -Property OwningProcess
        
        # Check for processes with high connection counts
        foreach ($processGroup in $processConnections) {
            if ($processGroup.Count -gt 10) {
                $process = $processes | Where-Object { $_.Id -eq $processGroup.Name } | Select-Object -First 1
                
                if ($process) {
                    $connectionDetails = $processGroup.Group | ForEach-Object {
                        @{
                            LocalAddress = $_.LocalAddress
                            LocalPort = $_.LocalPort
                            RemoteAddress = $_.RemoteAddress
                            RemotePort = $_.RemotePort
                            State = $_.State
                        }
                    }
                    
                    Add-Finding -TestResult $result -FindingName "High Connection Count" `
                        -Status "Warning" -RiskLevel "Medium" `
                        -Description "Process $($process.Name) (PID: $($process.Id)) has $($processGroup.Count) active connections" `
                        -AdditionalInfo @{
                            Component = "ProcessConnections"
                            ProcessName = $process.Name
                            ProcessId = $process.Id
                            ConnectionCount = $processGroup.Count
                            Connections = $connectionDetails
                            Recommendation = "Review process network activity for potential issues"
                        }
                    
                    if ($CollectEvidence) {
                        Add-Evidence -TestResult $result `
                            -FindingName "Process Connections" `
                            -EvidenceType "ProcessConnections" `
                            -EvidenceData @{
                                ProcessName = $process.Name
                                ProcessId = $process.Id
                                Connections = $connectionDetails
                            } `
                            -Description "Network connections for process $($process.Name)"
                    }
                }
            }
        }
        
        # Check for processes with suspicious ports
        $suspiciousPorts = @(
            @{
                Port = 445
                Description = "SMB"
                RiskLevel = "Medium"
            },
            @{
                Port = 135
                Description = "RPC"
                RiskLevel = "Medium"
            },
            @{
                Port = 139
                Description = "NetBIOS"
                RiskLevel = "Medium"
            },
            @{
                Port = 3389
                Description = "RDP"
                RiskLevel = "High"
            },
            @{
                Port = 22
                Description = "SSH"
                RiskLevel = "Medium"
            }
        )
        
        foreach ($port in $suspiciousPorts) {
            $suspiciousConnections = $connections | Where-Object { $_.LocalPort -eq $port.Port -or $_.RemotePort -eq $port.Port }
            
            if ($suspiciousConnections) {
                $processIds = $suspiciousConnections | Select-Object -ExpandProperty OwningProcess -Unique
                $processes = Get-Process -Id $processIds -ErrorAction SilentlyContinue
                
                $connectionDetails = $suspiciousConnections | ForEach-Object {
                    $process = $processes | Where-Object { $_.Id -eq $_.OwningProcess } | Select-Object -First 1
                    @{
                        LocalAddress = $_.LocalAddress
                        LocalPort = $_.LocalPort
                        RemoteAddress = $_.RemoteAddress
                        RemotePort = $_.RemotePort
                        State = $_.State
                        ProcessId = $_.OwningProcess
                        ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                        ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                    }
                }
                
                Add-Finding -TestResult $result -FindingName "Suspicious Port Connection" `
                    -Status "Warning" -RiskLevel $port.RiskLevel `
                    -Description "Found $($suspiciousConnections.Count) connections on port $($port.Port) ($($port.Description))" `
                    -AdditionalInfo @{
                        Component = "ProcessConnections"
                        Port = $port.Port
                        Description = $port.Description
                        ConnectionCount = $suspiciousConnections.Count
                        Connections = $connectionDetails
                        Recommendation = "Review these connections and verify they are authorized"
                    }
                
                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Process Connections" `
                        -EvidenceType "ProcessConnections" `
                        -EvidenceData @{
                            Port = $port.Port
                            Description = $port.Description
                            Connections = $connectionDetails
                        } `
                        -Description "Connections on port $($port.Port) ($($port.Description))"
                }
            }
        }
        
        # Export results if path is provided
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Process Connections Analysis"
        
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during process connections analysis: $($errorInfo.ErrorMessage)" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and network access"
            }
        
        # Export results if path is provided
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
} 