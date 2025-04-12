# -----------------------------------------------------------------------------
# WiFi Security Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for WiFi security settings and configurations.

.DESCRIPTION
    This function analyzes the system's WiFi security settings, including network profiles,
    encryption types, and authentication methods to ensure proper wireless security.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of WiFi settings.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-WiFiSecurity -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-WiFiSecurity {
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
    $result = Initialize-TestResult -TestName "Test-WiFiSecurity" -Category "Network" `
        -Description "Analyzes WiFi security settings and configurations"

    try {
        # Get WiFi profiles
        $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile\s+: (.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
        
        if (-not $wifiProfiles) {
            Add-Finding -TestResult $result -FindingName "No WiFi Profiles" -Status "Info" `
                -Description "No WiFi profiles found on this system" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "WiFi"
                    Status = "No Profiles"
                }
            return $result
        }

        foreach ($profile in $wifiProfiles) {
            # Get detailed profile information
            $profileInfo = netsh wlan show profile name="$profile" key=clear
            
            # Extract security information
            $securityType = ($profileInfo | Select-String "Security\s+: (.*)").Matches.Groups[1].Value.Trim()
            $authentication = ($profileInfo | Select-String "Authentication\s+: (.*)").Matches.Groups[1].Value.Trim()
            $encryption = ($profileInfo | Select-String "Cipher\s+: (.*)").Matches.Groups[1].Value.Trim()

            # Check for open networks
            if ($securityType -eq "Open") {
                Add-Finding -TestResult $result -FindingName "Open WiFi Network" -Status "Critical" `
                    -Description "Found open WiFi network: $profile" -RiskLevel "Critical" `
                    -AdditionalInfo @{
                        Component = "WiFi"
                        Network = $profile
                        SecurityType = $securityType
                        Recommendation = "Remove or secure open WiFi network"
                    }
            }

            # Check for weak encryption
            if ($encryption -match "WEP|TKIP") {
                Add-Finding -TestResult $result -FindingName "Weak WiFi Encryption" -Status "Warning" `
                    -Description "Network '$profile' uses weak encryption: $encryption" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "WiFi"
                        Network = $profile
                        Encryption = $encryption
                        Recommendation = "Upgrade to WPA2 or WPA3 encryption"
                    }
            }

            # Check for WPA2/WPA3
            if ($securityType -match "WPA2|WPA3") {
                Add-Finding -TestResult $result -FindingName "Strong WiFi Security" -Status "Pass" `
                    -Description "Network '$profile' uses strong encryption: $securityType" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "WiFi"
                        Network = $profile
                        SecurityType = $securityType
                        Encryption = $encryption
                    }
            }

            # Check for enterprise authentication
            if ($authentication -match "Enterprise|802.1X") {
                Add-Finding -TestResult $result -FindingName "Enterprise WiFi Authentication" -Status "Pass" `
                    -Description "Network '$profile' uses enterprise authentication" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "WiFi"
                        Network = $profile
                        Authentication = $authentication
                    }
            }
        }

        # Check for WiFi AutoConnect settings
        $autoConnect = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name "DefaultConnectionSettings" -ErrorAction SilentlyContinue
        if ($autoConnect) {
            Add-Finding -TestResult $result -FindingName "WiFi AutoConnect" -Status "Info" `
                -Description "WiFi AutoConnect settings are configured" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "WiFi"
                    Setting = "AutoConnect"
                    Status = "Configured"
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
            -Description "Error during WiFi security analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-WiFiSecurity 