# -----------------------------------------------------------------------------
# Process Network Connections Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious process network connections.

.DESCRIPTION
    This function analyzes active network connections and their associated processes,
    identifying potentially suspicious network activity, unauthorized connections,
    and processes with unusual network behavior.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis.

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
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-ProcessConnections" -Category "Security" -Description "Analyzes process network connections for suspicious activity"
    
    try {
        # Define suspicious ports and their descriptions
        $suspiciousPorts = @(
            @{
                Port = 4444
                Description = "Metasploit Default Port"
                RiskLevel = "Critical"
            },
            @{
                Port = 31337
                Description = "Back Orifice Default Port"
                RiskLevel = "Critical"
            },
            @{
                Port = 1080
                Description = "SOCKS Proxy"
                RiskLevel = "High"
            },
            @{
                Port = 8080
                Description = "Alternative HTTP/Proxy"
                RiskLevel = "Medium"
            },
            @{
                Port = 3389
                Description = "RDP"
                RiskLevel = "Medium"
            }
        )

        # Get all active TCP connections
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        # Group connections by process ID
        $connectionsByProcess = $connections | Group-Object -Property OwningProcess
        
        foreach ($processGroup in $connectionsByProcess) {
            $process = Get-Process -Id $processGroup.Name -ErrorAction SilentlyContinue
            
            if ($process) {
                $connectionDetails = $processGroup.Group | ForEach-Object {
                    $remoteAddress = $_.RemoteAddress
                    $remotePort = $_.RemotePort
                    
                    # Check if connection is on a suspicious port
                    $suspiciousPort = $suspiciousPorts | Where-Object { $_.Port -eq $remotePort }
                    
                    if ($suspiciousPort) {
                        Add-Finding -TestResult $result -FindingName "Suspicious Port Connection" `
                            -Status "Warning" -RiskLevel $suspiciousPort.RiskLevel `
                            -Description "Process $($process.Name) (PID: $($process.Id)) has connection on suspicious port $($suspiciousPort.Port) ($($suspiciousPort.Description))" `
                            -AdditionalInfo @{
                                Component = "NetworkConnections"
                                ProcessName = $process.Name
                                ProcessId = $process.Id
                                RemoteAddress = $remoteAddress
                                RemotePort = $remotePort
                                PortDescription = $suspiciousPort.Description
                                Recommendation = "Investigate this connection and verify it is authorized"
                            }
                    }
                    
                    @{
                        LocalAddress = $_.LocalAddress
                        LocalPort = $_.LocalPort
                        RemoteAddress = $remoteAddress
                        RemotePort = $remotePort
                        State = $_.State
                        CreationTime = $_.CreationTime
                    }
                }
                
                # Check for high number of connections from single process
                if ($processGroup.Count -gt 10) {
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
                }
                
                # Check for connections to private IP ranges (potential C2)
                $privateConnections = $processGroup.Group | Where-Object {
                    $remoteIP = [System.Net.IPAddress]::Parse($_.RemoteAddress)
                    $bytes = $remoteIP.GetAddressBytes()
                    
                    # Check for private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
                    ($bytes[0] -eq 10) -or
                    ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                    ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
                }
                
                if ($privateConnections.Count -gt 0) {
                    Add-Finding -TestResult $result -FindingName "Private Network Connection" `
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
                }
                
                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -Name "Process Connections" `
                        -EvidenceType "NetworkConnections" `
                        -EvidenceData @{
                            ProcessName = $process.Name
                            ProcessId = $process.Id
                            Connections = $connectionDetails
                        } `
                        -Description "Network connections for process $($process.Name)"
                }
            }
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during process connections test: $_"
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "An error occurred while checking process connections: $_" `
            -Recommendation "Check system permissions and network access"
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-ProcessConnections 