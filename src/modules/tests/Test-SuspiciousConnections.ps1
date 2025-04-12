# -----------------------------------------------------------------------------
# Suspicious Network Connections Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious network connections and activities.

.DESCRIPTION
    This function analyzes network connections, processes, and protocols to identify
    suspicious activities, unauthorized connections, and potential security risks.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of network connections.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-SuspiciousConnections -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-SuspiciousConnections {
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
    $result.Description = "Analysis of suspicious network connections and activities"

    try {
        # Get all established TCP connections
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop
        
        # Get process information for connections
        $processes = Get-Process -Id $connections.OwningProcess -ErrorAction SilentlyContinue
        
        # Define suspicious ports to monitor
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

        # Check for connections on suspicious ports
        foreach ($port in $suspiciousPorts) {
            $suspiciousConnections = $connections | Where-Object { $_.LocalPort -eq $port.Port -or $_.RemotePort -eq $port.Port }
            
            if ($suspiciousConnections) {
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
                    -Status "Warning" -RiskLevel "Medium" `
                    -Description "Found $($suspiciousConnections.Count) connections on port $($port.Port) ($($port.Description))" `
                    -AdditionalInfo @{
                        Component = "NetworkConnections"
                        Port = $port.Port
                        Description = $port.Description
                        ConnectionCount = $suspiciousConnections.Count
                        Connections = $connectionDetails
                        Recommendation = "Review these connections and verify they are authorized"
                    }

                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Process Connections" `
                        -EvidenceType "NetworkConnections" `
                        -EvidenceData @{
                            ProcessName = $process.ProcessName
                            ProcessId = $process.Id
                            Connections = $connectionDetails
                        } `
                        -Description "Network connections for process $($process.ProcessName)"
                }
            }
        }

        # Check for connections to suspicious IP ranges
        $suspiciousRanges = @(
            @{
                Range = "10.0.0.0/8"
                Description = "Private Network"
                RiskLevel = "Medium"
            },
            @{
                Range = "172.16.0.0/12"
                Description = "Private Network"
                RiskLevel = "Medium"
            },
            @{
                Range = "192.168.0.0/16"
                Description = "Private Network"
                RiskLevel = "Medium"
            }
        )

        foreach ($range in $suspiciousRanges) {
            $suspiciousConnections = $connections | Where-Object { 
                $ip = [System.Net.IPAddress]::Parse($_.RemoteAddress)
                $ip.GetAddressBytes()[0] -eq 10 -or 
                ($ip.GetAddressBytes()[0] -eq 172 -and $ip.GetAddressBytes()[1] -ge 16 -and $ip.GetAddressBytes()[1] -le 31) -or
                ($ip.GetAddressBytes()[0] -eq 192 -and $ip.GetAddressBytes()[1] -eq 168)
            }
            
            if ($suspiciousConnections) {
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

                Add-Finding -TestResult $result -FindingName "Suspicious IP Range Connection" `
                    -Status "Warning" -RiskLevel $range.RiskLevel `
                    -Description "Found $($suspiciousConnections.Count) connections to $($range.Description)" `
                    -AdditionalInfo @{
                        Component = "NetworkConnections"
                        Range = $range.Range
                        Description = $range.Description
                        ConnectionCount = $suspiciousConnections.Count
                        Connections = $connectionDetails
                        Recommendation = "Review these connections and verify they are authorized"
                    }

                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Process Connections" `
                        -EvidenceType "NetworkConnections" `
                        -EvidenceData @{
                            ProcessName = $process.ProcessName
                            ProcessId = $process.Id
                            Connections = $connectionDetails
                        } `
                        -Description "Network connections for process $($process.ProcessName)"
                }
            }
        }

        # Check for high number of connections from a single process
        $processConnections = $connections | Group-Object -Property OwningProcess
        
        foreach ($processGroup in $processConnections) {
            if ($processGroup.Count -gt 10) {
                $process = $processes | Where-Object { $_.Id -eq $processGroup.Name } | Select-Object -First 1
                
                if ($process) {
                    Add-Finding -TestResult $result -FindingName "High Connection Count" `
                        -Status "Warning" -RiskLevel "Medium" `
                        -Description "Process $($process.Name) (PID: $($process.Id)) has $($processGroup.Count) active connections" `
                        -AdditionalInfo @{
                            Component = "NetworkConnections"
                            ProcessName = $process.Name
                            ProcessId = $process.Id
                            ConnectionCount = $processGroup.Count
                            Connections = $connectionDetails
                            Recommendation = "Review process network activity for potential issues"
                        }

                    if ($CollectEvidence) {
                        Add-Evidence -TestResult $result `
                            -FindingName "Process Connections" `
                            -EvidenceType "NetworkConnections" `
                            -EvidenceData @{
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                Connections = $connectionDetails
                            } `
                            -Description "Network connections for process $($process.ProcessName)"
                    }
                }
            }
        }

        # Check for connections to private IP ranges (potential C2)
        $privateConnections = $connections | Where-Object { 
            $ip = [System.Net.IPAddress]::Parse($_.RemoteAddress)
            $ip.GetAddressBytes()[0] -eq 10 -or 
            ($ip.GetAddressBytes()[0] -eq 172 -and $ip.GetAddressBytes()[1] -ge 16 -and $ip.GetAddressBytes()[1] -le 31) -or
            ($ip.GetAddressBytes()[0] -eq 192 -and $ip.GetAddressBytes()[1] -eq 168)
        }
        
        if ($privateConnections.Count -gt 0) {
            $connectionDetails = $privateConnections | ForEach-Object {
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

            Add-Finding -TestResult $result -FindingName "Private Network Connections" `
                -Status "Info" -RiskLevel "Low" `
                -Description "Process $($process.Name) (PID: $($process.Id)) has $($privateConnections.Count) connections to private IP addresses" `
                -AdditionalInfo @{
                    Component = "NetworkConnections"
                    ProcessName = $process.Name
                    ProcessId = $process.Id
                    ConnectionCount = $privateConnections.Count
                    Connections = $connectionDetails
                    Recommendation = "Verify these internal network connections are authorized"
                }

            if ($CollectEvidence) {
                Add-Evidence -TestResult $result `
                    -FindingName "Process Connections" `
                    -EvidenceType "NetworkConnections" `
                    -EvidenceData @{
                        ProcessName = $process.ProcessName
                        ProcessId = $process.Id
                        Connections = $connectionDetails
                    } `
                    -Description "Network connections for process $($process.ProcessName)"
            }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during network connection analysis: $_" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and network access"
            }
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousConnections 