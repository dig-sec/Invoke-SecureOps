# -----------------------------------------------------------------------------
# Network Adapters and Firewall Analysis Module
# -----------------------------------------------------------------------------

function Test-NetworkAdaptersAndFirewall {
    param (
        [string]$OutputPath = ".\network_adapters_firewall.json"
    )

    Write-SectionHeader "Network Adapters and Firewall Check"
    Write-Output "Analyzing network adapters and firewall configuration..."

    # Initialize JSON output object using common function
    $networkInfo = Initialize-JsonOutput -Category "NetworkAdaptersAndFirewall" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Get network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        # Get firewall profiles
        $firewall = Get-NetFirewallProfile
        
        # Get network connections
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        
        $networkInfo.Adapters = $adapters | ForEach-Object {
            @{
                Name = $_.Name
                InterfaceDescription = $_.InterfaceDescription
                MacAddress = $_.MacAddress
                LinkSpeed = $_.LinkSpeed
            }
        }
        $networkInfo.Firewall = @{
            Domain = $firewall | Where-Object { $_.Name -eq "Domain" } | Select-Object Enabled,DefaultInboundAction,DefaultOutboundAction
            Private = $firewall | Where-Object { $_.Name -eq "Private" } | Select-Object Enabled,DefaultInboundAction,DefaultOutboundAction
            Public = $firewall | Where-Object { $_.Name -eq "Public" } | Select-Object Enabled,DefaultInboundAction,DefaultOutboundAction
        }
        $networkInfo.Connections = $connections | ForEach-Object {
            @{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
                OwningProcess = $_.OwningProcess
            }
        }

        # Add findings based on network configuration
        foreach ($profile in $firewall) {
            if (-not $profile.Enabled) {
                Add-Finding -CheckName "Windows Firewall: $($profile.Name)" -Status "Fail" `
                    -Details "Firewall is disabled for $($profile.Name) profile" -Category "NetworkAdaptersAndFirewall" `
                    -AdditionalInfo @{
                        Component = "Firewall"
                        Profile = $profile.Name
                        Status = "Disabled"
                    }
            }
            elseif ($profile.DefaultInboundAction -eq "Allow") {
                Add-Finding -CheckName "Windows Firewall: $($profile.Name)" -Status "Warning" `
                    -Details "Default inbound action is set to Allow for $($profile.Name) profile" -Category "NetworkAdaptersAndFirewall" `
                    -AdditionalInfo @{
                        Component = "Firewall"
                        Profile = $profile.Name
                        DefaultInboundAction = "Allow"
                        RecommendedValue = "Block"
                    }
            }
            else {
                Add-Finding -CheckName "Windows Firewall: $($profile.Name)" -Status "Pass" `
                    -Details "Firewall is properly configured for $($profile.Name) profile" -Category "NetworkAdaptersAndFirewall" `
                    -AdditionalInfo @{
                        Component = "Firewall"
                        Profile = $profile.Name
                        Status = "Enabled"
                        DefaultInboundAction = $profile.DefaultInboundAction
                    }
            }
        }

        # Check for suspicious connections
        $suspiciousPorts = @(445, 135, 139)  # Common ports for file sharing and RPC
        $suspiciousConnections = @()
        foreach ($conn in $connections) {
            if ($conn.RemotePort -in $suspiciousPorts) {
                $suspiciousConnections += @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    ProcessId = $conn.OwningProcess
                }
            }
        }

        if ($suspiciousConnections.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Connections" -Status "Warning" `
                -Details "Found $($suspiciousConnections.Count) suspicious connections" -Category "NetworkConfiguration" `
                -AdditionalInfo @{
                    Component = "NetworkConnections"
                    Count = $suspiciousConnections.Count
                    Connections = $suspiciousConnections
                }
        }

        $networkInfo.SuspiciousConnections = $suspiciousConnections
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Network Configuration Analysis"
        Add-Finding -CheckName "Network Configuration" -Status "Error" `
            -Details "Failed to check network configuration: $($_.Exception.Message)" -Category "NetworkConfiguration" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $networkInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $networkInfo
}

# Export the function
Export-ModuleMember -Function Test-NetworkConfiguration 