# -----------------------------------------------------------------------------
# Process Connections Analysis Module
# -----------------------------------------------------------------------------

function Test-ProcessConnections {
    param (
        [string]$OutputPath = ".\process_connections.json"
    )

    Write-SectionHeader "Process Connections Analysis"
    Write-Output "Analyzing process network connections..."

    # Initialize JSON output object using common function
    $connectionInfo = Initialize-JsonOutput -Category "ProcessConnections" -RiskLevel "High" -ActionLevel "Investigate"
    $connectionInfo.TotalConnections = 0
    $connectionInfo.ConnectionsByState = @{}
    $connectionInfo.ConnectionsByProtocol = @{}
    $connectionInfo.SuspiciousConnections = @()

    try {
        # Get all network connections
        $connections = Get-NetTCPConnection -ErrorAction Stop
        $connectionInfo.TotalConnections = $connections.Count

        # Group connections by state
        $connectionInfo.ConnectionsByState = $connections | Group-Object State | ForEach-Object {
            @{
                $_.Name = $_.Count
            }
        }

        # Group connections by protocol
        $connectionInfo.ConnectionsByProtocol = $connections | Group-Object Protocol | ForEach-Object {
            @{
                $_.Name = $_.Count
            }
        }

        # Check for suspicious connections
        $suspiciousPorts = @(
            @{
                Port = 4444
                Description = "Common backdoor port"
                RiskLevel = "Critical"
            },
            @{
                Port = 666
                Description = "Common malware port"
                RiskLevel = "Critical"
            },
            @{
                Port = 1337
                Description = "Common backdoor port"
                RiskLevel = "High"
            }
        )

        foreach ($port in $suspiciousPorts) {
            $matches = $connections | Where-Object { $_.LocalPort -eq $port.Port -or $_.RemotePort -eq $port.Port }
            if ($matches) {
                foreach ($conn in $matches) {
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    $connectionInfo.SuspiciousConnections += @{
                        Port = $port.Port
                        Description = $port.Description
                        RiskLevel = $port.RiskLevel
                        LocalAddress = $conn.LocalAddress
                        LocalPort = $conn.LocalPort
                        RemoteAddress = $conn.RemoteAddress
                        RemotePort = $conn.RemotePort
                        State = $conn.State
                        ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                        ProcessId = $conn.OwningProcess
                        Protocol = $conn.Protocol
                    }
                }
            }
        }

        # Add finding based on suspicious connections
        if ($connectionInfo.SuspiciousConnections.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Connections" -Status "Warning" `
                -Details "Found $($connectionInfo.SuspiciousConnections.Count) suspicious network connections" -Category "ProcessConnections" `
                -AdditionalInfo @{
                    SuspiciousConnections = $connectionInfo.SuspiciousConnections
                    TotalConnectionsAnalyzed = $connectionInfo.TotalConnections
                }
        }
        else {
            Add-Finding -CheckName "Connection Analysis" -Status "Pass" `
                -Details "No suspicious connections found" -Category "ProcessConnections" `
                -AdditionalInfo @{
                    TotalConnectionsAnalyzed = $connectionInfo.TotalConnections
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Process Connections Analysis"
        Add-Finding -CheckName "Process Connections Analysis" -Status "Fail" `
            -Details "Failed to analyze process connections: $($_.Exception.Message)" -Category "ProcessConnections" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $connectionInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }
}

# Export the function
Export-ModuleMember -Function Test-ProcessConnections 