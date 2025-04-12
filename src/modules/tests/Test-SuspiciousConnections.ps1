# -----------------------------------------------------------------------------
# Suspicious Network Connections Analysis Module
# -----------------------------------------------------------------------------

# Import helper functions
. "$PSScriptRoot\..\core\Helpers.ps1"

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
    $result.TestName = "Test-SuspiciousConnections"

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
                    $currentProcess = $_
                    $process = $processes | Where-Object { $_.Id -eq $currentProcess.OwningProcess } | Select-Object -First 1
                    @{
                        LocalAddress = $currentProcess.LocalAddress
                        LocalPort = $currentProcess.LocalPort
                        RemoteAddress = $currentProcess.RemoteAddress
                        RemotePort = $currentProcess.RemotePort
                        State = $currentProcess.State
                        ProcessId = $currentProcess.OwningProcess
                        ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                        ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                    }
                }

                $findingParams = @{
                    TestResult = $result
                    FindingName = "Suspicious Port Connection"
                    Status = "Warning"
                    RiskLevel = $port.RiskLevel
                    Description = "Found $($suspiciousConnections.Count) connections on port $($port.Port) ($($port.Description))"
                    AdditionalInfo = @{
                        Component = "NetworkConnections"
                        Port = $port.Port
                        Description = $port.Description
                        ConnectionCount = $suspiciousConnections.Count
                        Connections = $connectionDetails
                        Recommendation = "Review these connections and verify they are authorized"
                    }
                }
                Add-Finding @findingParams

                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Suspicious Port Connection" `
                        -EvidenceType "NetworkConnections" `
                        -EvidenceData @{
                            Port = $port.Port
                            Description = $port.Description
                            Connections = $connectionDetails
                        } `
                        -Description "Network connections on suspicious port $($port.Port) ($($port.Description))"
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
                    $currentProcess = $_
                    $process = $processes | Where-Object { $_.Id -eq $currentProcess.OwningProcess } | Select-Object -First 1
                    @{
                        LocalAddress = $currentProcess.LocalAddress
                        LocalPort = $currentProcess.LocalPort
                        RemoteAddress = $currentProcess.RemoteAddress
                        RemotePort = $currentProcess.RemotePort
                        State = $currentProcess.State
                        ProcessId = $currentProcess.OwningProcess
                        ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                        ProcessPath = if ($process) { $process.Path } else { "Unknown" }
                    }
                }

                $findingParams = @{
                    TestResult = $result
                    FindingName = "Suspicious IP Range Connection"
                    Status = "Warning"
                    RiskLevel = $range.RiskLevel
                    Description = "Found $($suspiciousConnections.Count) connections to $($range.Description)"
                    AdditionalInfo = @{
                        Component = "NetworkConnections"
                        Range = $range.Range
                        Description = $range.Description
                        ConnectionCount = $suspiciousConnections.Count
                        Connections = $connectionDetails
                        Recommendation = "Review these connections and verify they are authorized"
                    }
                }
                Add-Finding @findingParams

                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Suspicious IP Range Connection" `
                        -EvidenceType "NetworkConnections" `
                        -EvidenceData @{
                            Range = $range.Range
                            Description = $range.Description
                            Connections = $connectionDetails
                        } `
                        -Description "Network connections to suspicious IP range $($range.Range) ($($range.Description))"
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
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Test-SuspiciousConnections"
        
        # Ensure we have a valid test result
        if (-not $result) {
            $result = Initialize-JsonOutput -Category "Security" -RiskLevel "Info" -ActionLevel "Review"
            $result.Description = "Analysis of suspicious network connections and activities"
            $result.TestName = "Test-SuspiciousConnections"
        }
        
        $findingParams = @{
            TestResult = $result
            FindingName = "Test Error"
            Status = "Error"
            RiskLevel = "High"
            Description = "An error occurred during network connection analysis: $($errorInfo.ErrorMessage)"
            AdditionalInfo = @{
                Component = "NetworkConnections"
                Error = $errorInfo
            }
        }
        Add-Finding @findingParams
        
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousConnections 