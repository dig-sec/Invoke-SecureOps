# -----------------------------------------------------------------------------
# Network Security Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for network security configurations and settings.

.DESCRIPTION
    This function analyzes network security settings, including
    firewall rules, network protocols, and security policies.

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

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-NetworkSecurity -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-NetworkSecurity {
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
        [switch]$CollectEvidence
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-NetworkSecurity" `
                                  -Category "Security" `
                                  -Description "Analyzes network security settings" `
                                  -Status "Info" `
                                  -RiskLevel "Info"
    
    try {
        # Check Windows Firewall status
        $firewall = Get-NetFirewallProfile
        foreach ($profile in $firewall) {
            Add-Finding -TestResult $result `
                -Name "Firewall Profile: $($profile.Name)" `
                -Status $(if ($profile.Enabled) { "Pass" } else { "Critical" }) `
                -RiskLevel $(if ($profile.Enabled) { "Info" } else { "Critical" }) `
                -Description "Windows Firewall is $(if ($profile.Enabled) { 'enabled' } else { 'disabled' }) for $($profile.Name) profile" `
                -TechnicalDetails @{
                    Profile = $profile.Name
                    Enabled = $profile.Enabled
                    DefaultInboundAction = $profile.DefaultInboundAction
                    DefaultOutboundAction = $profile.DefaultOutboundAction
                    LogAllowed = $profile.LogAllowed
                    LogBlocked = $profile.LogBlocked
                    LogFileName = $profile.LogFileName
                    LogMaxSizeKilobytes = $profile.LogMaxSizeKilobytes
                    Recommendation = if (-not $profile.Enabled) { "Enable Windows Firewall for $($profile.Name) profile" }
                }
        }
        
        # Check network protocols
        $protocols = Get-NetIPProtocol
        foreach ($protocol in $protocols) {
            if ($protocol.DisplayName -match "TCP|UDP") {
                Add-Finding -TestResult $result `
                    -Name "Network Protocol: $($protocol.DisplayName)" `
                    -Status "Info" `
                    -RiskLevel "Info" `
                    -Description "Network protocol $($protocol.DisplayName) is $(if ($protocol.Enabled) { 'enabled' } else { 'disabled' })" `
                    -TechnicalDetails @{
                        Protocol = $protocol.DisplayName
                        Enabled = $protocol.Enabled
                        ProtocolNumber = $protocol.ProtocolNumber
                        Recommendation = "Review protocol usage and disable if not needed"
                    }
            }
        }
        
        # Check network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            Add-Finding -TestResult $result `
                -Name "Network Adapter: $($adapter.Name)" `
                -Status "Info" `
                -RiskLevel "Info" `
                -Description "Network adapter $($adapter.Name) is active" `
                -TechnicalDetails @{
                    Name = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    LinkSpeed = $adapter.LinkSpeed
                    MacAddress = $adapter.MacAddress
                    Recommendation = "Regularly monitor network adapter status and performance"
                }
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result `
                    -FindingName "Network Adapter: $($adapter.Name)" `
                    -EvidenceType "Configuration" `
                    -EvidenceData @{
                        Name = $adapter.Name
                        InterfaceDescription = $adapter.InterfaceDescription
                        Status = $adapter.Status
                        LinkSpeed = $adapter.LinkSpeed
                        MacAddress = $adapter.MacAddress
                        IPAddresses = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex).IPAddress
                    } `
                    -Description "Network adapter configuration details"
            }
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during network security test: $_"
        Add-Finding -TestResult $result `
            -Name "Test Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error during network security test: $_" `
            -TechnicalDetails @{
                Recommendation = "Check system permissions and network access"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-NetworkSecurity 