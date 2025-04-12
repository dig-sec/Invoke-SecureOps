# -----------------------------------------------------------------------------
# Network Connections Analysis Module
# -----------------------------------------------------------------------------

function Test-NetworkConnections {
    param (
        [string]$OutputPath = ".\network_connections.json"
    )

    Write-SectionHeader "Network Connections Analysis"
    Write-Output "Analyzing network connections..."

    # Initialize JSON output object
    $networkInfo = Initialize-JsonOutput -Category "NetworkConnections" -RiskLevel "Medium" -ActionLevel "Review"
    $networkInfo.TotalConnections = 0
    $networkInfo.SuspiciousConnections = @()
    $networkInfo.RemoteConnections = @()

    # Get all network connections
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
    $networkInfo.TotalConnections = $connections.Count

    # Define suspicious patterns
    $suspiciousPatterns = @(
        @{
            Pattern = "\.(ru|cn|kp)$"
            Description = "Connection to high-risk country"
            RiskLevel = "High"
        },
        @{
            Pattern = "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
            Description = "Internal network connection"
            RiskLevel = "Info"
        },
        @{
            Pattern = "^(?!10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
            Description = "External network connection"
            RiskLevel = "Medium"
        }
    )

    # Analyze connections
    foreach ($conn in $connections) {
        $remoteAddress = $conn.RemoteAddress
        $remotePort = $conn.RemotePort
        $localPort = $conn.LocalPort
        $state = $conn.State
        $processId = $conn.OwningProcess

        # Get process information
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        $processName = if ($process) { $process.ProcessName } else { "Unknown" }
        $processPath = if ($process) { $process.Path } else { "Unknown" }

        # Check for suspicious patterns
        foreach ($pattern in $suspiciousPatterns) {
            if ($remoteAddress -match $pattern.Pattern) {
                $networkInfo.SuspiciousConnections += @{
                    RemoteAddress = $remoteAddress
                    RemotePort = $remotePort
                    LocalPort = $localPort
                    State = $state
                    ProcessName = $processName
                    ProcessPath = $processPath
                    ProcessId = $processId
                    Pattern = $pattern.Description
                    RiskLevel = $pattern.RiskLevel
                }
                break
            }
        }

        # Check for remote connections
        if ($state -eq "Established" -and $remoteAddress -notmatch "^(127\.0\.0\.1|::1)$") {
            $networkInfo.RemoteConnections += @{
                RemoteAddress = $remoteAddress
                RemotePort = $remotePort
                LocalPort = $localPort
                ProcessName = $processName
                ProcessPath = $processPath
                ProcessId = $processId
            }
        }
    }

    # Export results to JSON
    Export-ToJson -Data $networkInfo -FilePath $OutputPath -Pretty

    # Add findings
    Add-Finding -CheckName "Network Connections" -Status "Info" -Details "Analyzed $($networkInfo.TotalConnections) connections" -Category "Network"
    
    if ($networkInfo.SuspiciousConnections.Count -gt 0) {
        $highRiskConnections = $networkInfo.SuspiciousConnections | Where-Object { $_.RiskLevel -eq "High" }
        if ($highRiskConnections.Count -gt 0) {
            Add-Finding -CheckName "High-Risk Network Connections" -Status "Warning" -Details "Found $($highRiskConnections.Count) high-risk connections" -Category "Network"
        }
        
        Add-Finding -CheckName "Suspicious Network Connections" -Status "Warning" -Details "Found $($networkInfo.SuspiciousConnections.Count) suspicious connections" -Category "Network"
    }
    else {
        Add-Finding -CheckName "Suspicious Network Connections" -Status "Pass" -Details "No suspicious connections found" -Category "Network"
    }

    return $networkInfo
}

# Export the function
Export-ModuleMember -Function Test-NetworkConnections 