# -----------------------------------------------------------------------------
# Network Adapters and Firewall Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests network adapters and firewall configuration for security compliance.

.DESCRIPTION
    This function analyzes network adapters, firewall profiles, and network connections
    to identify potential security issues and misconfigurations.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of network connections.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-NetworkAdaptersAndFirewall -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-NetworkAdaptersAndFirewall {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$DetailedAnalysis
    )

    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-NetworkAdaptersAndFirewall" -Category "Network" -Description "Analysis of network adapters and firewall configuration"

    try {
        # Get network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        # Get firewall profiles
        $firewall = Get-NetFirewallProfile
        
        # Get network connections
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }

        # Check network adapters
        if ($adapters.Count -eq 0) {
            Add-Finding -TestResult $result -FindingName "Network Adapters" -Status "Warning" `
                -Description "No active network adapters found" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "NetworkAdapters"
                    Status = "No Active Adapters"
                    Recommendation = "Check network adapter configuration and connectivity"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Network Adapters" -Status "Pass" `
                -Description "Found $($adapters.Count) active network adapters" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "NetworkAdapters"
                    Count = $adapters.Count
                    Adapters = $adapters | ForEach-Object {
                        @{
                            Name = $_.Name
                            InterfaceDescription = $_.InterfaceDescription
                            MacAddress = $_.MacAddress
                            LinkSpeed = $_.LinkSpeed
                            Status = $_.Status
                            MediaType = $_.MediaType
                        }
                    }
                }
        }

        # Check firewall configuration
        foreach ($profile in $firewall) {
            if (-not $profile.Enabled) {
                Add-Finding -TestResult $result -FindingName "Windows Firewall: $($profile.Name)" -Status "Fail" `
                    -Description "Firewall is disabled for $($profile.Name) profile" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "Firewall"
                        Profile = $profile.Name
                        Status = "Disabled"
                        Recommendation = "Enable Windows Firewall for all profiles"
                    }
            }
            elseif ($profile.DefaultInboundAction -eq "Allow") {
                Add-Finding -TestResult $result -FindingName "Windows Firewall: $($profile.Name)" -Status "Warning" `
                    -Description "Default inbound action is set to Allow for $($profile.Name) profile" -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "Firewall"
                        Profile = $profile.Name
                        DefaultInboundAction = "Allow"
                        RecommendedValue = "Block"
                        Recommendation = "Change default inbound action to Block for better security"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Firewall: $($profile.Name)" -Status "Pass" `
                    -Description "Firewall is properly configured for $($profile.Name) profile" -RiskLevel "Info" `
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
                    Protocol = $conn.Protocol
                }
            }
        }

        if ($suspiciousConnections.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Suspicious Connections" -Status "Warning" `
                -Description "Found $($suspiciousConnections.Count) suspicious connections" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "NetworkConnections"
                    Count = $suspiciousConnections.Count
                    Connections = $suspiciousConnections
                    Recommendation = "Review these connections and consider blocking if not needed"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Suspicious Connections" -Status "Pass" `
                -Description "No suspicious connections found" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "NetworkConnections"
                    Status = "No Suspicious Connections"
                }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during network adapters and firewall analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-NetworkAdaptersAndFirewall 