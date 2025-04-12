# -----------------------------------------------------------------------------
# Suspicious Network Connection Detection Module
# -----------------------------------------------------------------------------

function Test-SuspiciousConnections {
    param (
        [string]$OutputPath = ".\suspicious_connections.json"
    )

    Write-SectionHeader "Suspicious Connection Analysis"
    Write-Output "Analyzing network connections for suspicious behavior..."

    # Initialize results object
    $results = @{
        SuspiciousActivities = @()
        TotalChecks = 0
        PassedChecks = 0
        FailedChecks = 0
        WarningChecks = 0
    }

    try {
        # Get all network connections
        $connections = Get-NetTCPConnection -ErrorAction Stop
        $results.TotalChecks = $connections.Count

        # Define suspicious connection patterns
        $suspiciousPatterns = @(
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
            },
            @{
                Port = 31337
                Description = "Common backdoor port"
                RiskLevel = "High"
            }
        )

        foreach ($pattern in $suspiciousPatterns) {
            $matches = $connections | Where-Object { $_.LocalPort -eq $pattern.Port -or $_.RemotePort -eq $pattern.Port }
            if ($matches) {
                foreach ($conn in $matches) {
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    $results.SuspiciousActivities += @{
                        Type = "SuspiciousConnection"
                        Port = $pattern.Port
                        Description = $pattern.Description
                        RiskLevel = $pattern.RiskLevel
                        LocalAddress = $conn.LocalAddress
                        LocalPort = $conn.LocalPort
                        RemoteAddress = $conn.RemoteAddress
                        RemotePort = $conn.RemotePort
                        State = $conn.State
                        ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                        ProcessId = $conn.OwningProcess
                        Protocol = $conn.Protocol
                    }
                    $results.WarningChecks++
                }
            }
            else {
                $results.PassedChecks++
            }
        }

        # Check for connections to known malicious IPs
        $maliciousIPs = @(
            @{
                IP = "185.147.128.0"
                Description = "Known malicious IP range"
                RiskLevel = "Critical"
            },
            @{
                IP = "45.67.230.0"
                Description = "Known malicious IP range"
                RiskLevel = "Critical"
            }
        )

        foreach ($ip in $maliciousIPs) {
            $matches = $connections | Where-Object { $_.RemoteAddress -like "$($ip.IP)*" }
            if ($matches) {
                foreach ($conn in $matches) {
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    $results.SuspiciousActivities += @{
                        Type = "MaliciousIPConnection"
                        IP = $ip.IP
                        Description = $ip.Description
                        RiskLevel = $ip.RiskLevel
                        LocalAddress = $conn.LocalAddress
                        LocalPort = $conn.LocalPort
                        RemoteAddress = $conn.RemoteAddress
                        RemotePort = $conn.RemotePort
                        State = $conn.State
                        ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
                        ProcessId = $conn.OwningProcess
                        Protocol = $conn.Protocol
                    }
                    $results.WarningChecks++
                }
            }
            else {
                $results.PassedChecks++
            }
        }

        # Add finding based on suspicious connections
        if ($results.SuspiciousActivities.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Connections" -Status "Warning" `
                -Details "Found $($results.SuspiciousActivities.Count) suspicious connections" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    SuspiciousActivities = $results.SuspiciousActivities
                    TotalChecks = $results.TotalChecks
                    PassedChecks = $results.PassedChecks
                    FailedChecks = $results.FailedChecks
                    WarningChecks = $results.WarningChecks
                }
        }
        else {
            Add-Finding -CheckName "Connection Analysis" -Status "Pass" `
                -Details "No suspicious connections found" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    TotalChecks = $results.TotalChecks
                    PassedChecks = $results.PassedChecks
                    FailedChecks = $results.FailedChecks
                    WarningChecks = $results.WarningChecks
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Suspicious Connection Analysis"
        Add-Finding -CheckName "Connection Analysis" -Status "Fail" `
            -Details "Failed to analyze connections: $($_.Exception.Message)" -Category "ThreatHunting" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $results -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $results
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousConnections 