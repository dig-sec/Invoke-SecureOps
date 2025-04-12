# -----------------------------------------------------------------------------
# Network Security Protocols Analysis Module
# -----------------------------------------------------------------------------

function Test-NetworkSecurityProtocols {
    param (
        [string]$OutputPath = ".\network_security_protocols.json"
    )

    Write-SectionHeader "Network Security Protocols Check"
    Write-Output "Analyzing network security protocols and settings..."

    # Initialize JSON output object using common function
    $networkProtocolInfo = Initialize-JsonOutput -Category "NetworkSecurityProtocols" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Get IPsec settings
        $ipsec = Get-NetIPsecMainModeRule
        
        # Get network isolation settings
        $isolation = Get-NetConnectionProfile
        
        # Get DNS settings
        $dns = Get-DnsClientServerAddress
        
        $networkProtocolInfo.IPsec = @{
            Rules = $ipsec | ForEach-Object {
                @{
                    Name = $_.Name
                    Enabled = $_.Enabled
                    Action = $_.Action
                    Description = $_.Description
                }
            }
        }
        $networkProtocolInfo.NetworkIsolation = @{
            Profiles = $isolation | ForEach-Object {
                @{
                    Name = $_.Name
                    NetworkCategory = $_.NetworkCategory
                    IPv4Connectivity = $_.IPv4Connectivity
                    IPv6Connectivity = $_.IPv6Connectivity
                }
            }
        }
        $networkProtocolInfo.DNS = @{
            Servers = $dns | ForEach-Object {
                @{
                    InterfaceAlias = $_.InterfaceAlias
                    ServerAddresses = $_.ServerAddresses
                }
            }
        }

        # Add findings based on IPsec configuration
        if ($ipsec.Count -eq 0) {
            Add-Finding -CheckName "IPsec Configuration" -Status "Warning" `
                -Details "No IPsec rules found" -Category "NetworkSecurityProtocols" `
                -AdditionalInfo @{
                    Component = "IPsec"
                    Status = "No Rules"
                    Recommendation = "Consider implementing IPsec rules for network security"
                }
        }
        else {
            Add-Finding -CheckName "IPsec Configuration" -Status "Pass" `
                -Details "Found $($ipsec.Count) IPsec rules" -Category "NetworkSecurityProtocols" `
                -AdditionalInfo @{
                    Component = "IPsec"
                    Status = "Configured"
                    RuleCount = $ipsec.Count
                }
        }

        # Check network isolation settings
        $publicNetworks = @()
        foreach ($profile in $isolation) {
            if ($profile.NetworkCategory -eq "Public") {
                $publicNetworks += @{
                    Name = $profile.Name
                    NetworkCategory = $profile.NetworkCategory
                    IPv4Connectivity = $profile.IPv4Connectivity
                    IPv6Connectivity = $profile.IPv6Connectivity
                }
            }
        }

        if ($publicNetworks.Count -gt 0) {
            Add-Finding -CheckName "Network Isolation" -Status "Warning" `
                -Details "Found $($publicNetworks.Count) networks set to Public" -Category "NetworkSecurityProtocols" `
                -AdditionalInfo @{
                    Component = "NetworkIsolation"
                    Status = "Public Networks Found"
                    Networks = $publicNetworks
                    Recommendation = "Review and potentially change network categories to Private or Domain"
                }
        }
        else {
            Add-Finding -CheckName "Network Isolation" -Status "Pass" `
                -Details "No networks found set to Public" -Category "NetworkSecurityProtocols" `
                -AdditionalInfo @{
                    Component = "NetworkIsolation"
                    Status = "Properly Isolated"
                }
        }

        # Check DNS configuration
        $dnsIssues = @()
        foreach ($dnsConfig in $dns) {
            if ($dnsConfig.ServerAddresses.Count -eq 0) {
                $dnsIssues += @{
                    Interface = $dnsConfig.InterfaceAlias
                    Status = "No DNS Servers"
                }
            }
        }

        if ($dnsIssues.Count -gt 0) {
            Add-Finding -CheckName "DNS Configuration" -Status "Warning" `
                -Details "Found $($dnsIssues.Count) interfaces without DNS servers" -Category "NetworkSecurityProtocols" `
                -AdditionalInfo @{
                    Component = "DNS"
                    Status = "Missing DNS Servers"
                    Issues = $dnsIssues
                    Recommendation = "Configure DNS servers for all network interfaces"
                }
        }
        else {
            Add-Finding -CheckName "DNS Configuration" -Status "Pass" `
                -Details "All interfaces have DNS servers configured" -Category "NetworkSecurityProtocols" `
                -AdditionalInfo @{
                    Component = "DNS"
                    Status = "Properly Configured"
                }
        }

        $networkProtocolInfo.PublicNetworks = $publicNetworks
        $networkProtocolInfo.DNSIssues = $dnsIssues
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Network Security Protocols Analysis"
        Add-Finding -CheckName "Network Security Protocols" -Status "Error" `
            -Details "Failed to check network security protocols: $($_.Exception.Message)" -Category "NetworkSecurityProtocols" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $networkProtocolInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $networkProtocolInfo
}

# Export the function
Export-ModuleMember -Function Test-NetworkSecurityProtocols 