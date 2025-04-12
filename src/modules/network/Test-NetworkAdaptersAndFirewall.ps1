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
                Status = $_.Status
                MediaType = $_.MediaType
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
                Protocol = $_.Protocol
            }
        }

        # Add findings based on network adapters
        if ($adapters.Count -eq 0) {
            Add-Finding -CheckName "Network Adapters" -Status "Warning" `
                -Details "No active network adapters found" -Category "NetworkAdaptersAndFirewall" `
                -AdditionalInfo @{
                    Component = "NetworkAdapters"
                    Status = "No Active Adapters"
                    Recommendation = "Check network adapter configuration and connectivity"
                }
        }
        else {
            Add-Finding -CheckName "Network Adapters" -Status "Pass" `
                -Details "Found $($adapters.Count) active network adapters" -Category "NetworkAdaptersAndFirewall" `
                -AdditionalInfo @{
                    Component = "NetworkAdapters"
                    Count = $adapters.Count
                }
        }

        # Add findings based on firewall configuration
        foreach ($profile in $firewall) {
            if (-not $profile.Enabled) {
                Add-Finding -CheckName "Windows Firewall: $($profile.Name)" -Status "Fail" `
                    -Details "Firewall is disabled for $($profile.Name) profile" -Category "NetworkAdaptersAndFirewall" `
                    -AdditionalInfo @{
                        Component = "Firewall"
                        Profile = $profile.Name
                        Status = "Disabled"
                        Recommendation = "Enable Windows Firewall for all profiles"
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
                        Recommendation = "Change default inbound action to Block for better security"
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
                    Protocol = $conn.Protocol
                }
            }
        }

        if ($suspiciousConnections.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Connections" -Status "Warning" `
                -Details "Found $($suspiciousConnections.Count) suspicious connections" -Category "NetworkAdaptersAndFirewall" `
                -AdditionalInfo @{
                    Component = "NetworkConnections"
                    Count = $suspiciousConnections.Count
                    Connections = $suspiciousConnections
                    Recommendation = "Review these connections and consider blocking if not needed"
                }
        }
        else {
            Add-Finding -CheckName "Suspicious Connections" -Status "Pass" `
                -Details "No suspicious connections found" -Category "NetworkAdaptersAndFirewall" `
                -AdditionalInfo @{
                    Component = "NetworkConnections"
                    Status = "No Suspicious Connections"
                }
        }

        $networkInfo.SuspiciousConnections = $suspiciousConnections
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Network Adapters and Firewall Analysis"
        Add-Finding -CheckName "Network Adapters and Firewall" -Status "Error" `
            -Details "Failed to check network adapters and firewall: $($_.Exception.Message)" -Category "NetworkAdaptersAndFirewall" `
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
Export-ModuleMember -Function Test-NetworkAdaptersAndFirewall 