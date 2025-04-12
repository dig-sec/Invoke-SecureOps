# -----------------------------------------------------------------------------
# Network Configuration Test Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests network configuration settings and security.

.DESCRIPTION
    This function analyzes network configuration settings for security compliance.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-NetworkConfiguration -OutputPath ".\results\network.json" -PrettyOutput
#>
function Test-NetworkConfiguration {
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
    $result = Initialize-JsonOutput -Category "Security" -RiskLevel "Info"
    $result.TestName = "Test-NetworkConfiguration"
    $result.Description = "Analyzes network configuration settings"

    try {
        # Check network adapters
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
        
        foreach ($adapter in $adapters) {
            Add-Finding -TestResult $result -FindingName "Network Adapter Status" -Status "Pass" `
                -Description "Network adapter $($adapter.Name) is $($adapter.Status)" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "Network Configuration"
                    AdapterName = $adapter.Name
                    Status = $adapter.Status
                    MediaType = $adapter.MediaType
                    LinkSpeed = $adapter.LinkSpeed
                }
        }

        # Check IP configuration
        $ipConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue
        
        foreach ($config in $ipConfig) {
            Add-Finding -TestResult $result -FindingName "IP Configuration" -Status "Pass" `
                -Description "IP configuration for interface $($config.InterfaceAlias)" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "Network Configuration"
                    Interface = $config.InterfaceAlias
                    IPv4Address = $config.IPv4Address.IPAddress
                    IPv6Address = $config.IPv6Address.IPAddress
                    DNSServer = $config.DNSServer.ServerAddresses
                }
        }

        # Check network bindings
        $bindings = Get-NetAdapterBinding -ErrorAction SilentlyContinue
        
        foreach ($binding in $bindings) {
            if ($binding.Enabled -and $binding.ComponentID -in @('ms_tcpip6', 'ms_rspndr', 'ms_lltdio')) {
                Add-Finding -TestResult $result -FindingName "Network Binding Security" -Status "Warning" `
                    -Description "Potentially unnecessary protocol enabled: $($binding.DisplayName)" `
                    -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "Network Configuration"
                        Protocol = $binding.DisplayName
                        ComponentID = $binding.ComponentID
                        Recommendation = "Consider disabling unnecessary network protocols"
                    }
            }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            $json = $result | ConvertTo-Json -Depth 10
            if ($PrettyOutput) {
                $json = $json | ConvertFrom-Json | ConvertTo-Json -Depth 10
            }
            $json | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
            Write-Host "Test result exported to $OutputPath"
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during network configuration analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            $json = $result | ConvertTo-Json -Depth 10
            if ($PrettyOutput) {
                $json = $json | ConvertFrom-Json | ConvertTo-Json -Depth 10
            }
            $json | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
            Write-Host "Test result exported to $OutputPath"
        }
        return $result
    }
}

# Only export if we're in a module context
if ($MyInvocation.ScriptName -ne '') {
    Export-ModuleMember -Function Test-NetworkConfiguration
} 