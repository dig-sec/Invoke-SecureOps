# -----------------------------------------------------------------------------
# Firewall Status Analysis Module
# -----------------------------------------------------------------------------

function Test-FirewallStatus {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence
    )

    Write-SectionHeader "Firewall Status Check"
    Write-Output "Analyzing firewall status..."

    # Initialize test result using helper function
    $testResult = Initialize-TestResult -TestName "Test-FirewallStatus" -Category "Firewall" -Description "Windows Firewall status check" -RiskLevel "High"
    
    try {
        # Get firewall profiles
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        
        foreach ($profile in $firewallProfiles) {
            $profileName = $profile.Name
            $enabled = $profile.Enabled
            $defaultInboundAction = $profile.DefaultInboundAction
            $defaultOutboundAction = $profile.DefaultOutboundAction
            
            if (-not $enabled) {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Firewall Profile Status - $profileName" `
                    -Status "Warning" `
                    -Description "Firewall profile '$profileName' is disabled" `
                    -RiskLevel "High" `
                    -TechnicalDetails @{
                        Profile = $profileName
                        Enabled = $enabled
                        DefaultInboundAction = $defaultInboundAction
                        DefaultOutboundAction = $defaultOutboundAction
                    }
            }
            elseif ($defaultInboundAction -eq "Allow") {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Firewall Default Inbound Action - $profileName" `
                    -Status "Warning" `
                    -Description "Firewall profile '$profileName' has default inbound action set to Allow" `
                    -RiskLevel "Medium" `
                    -TechnicalDetails @{
                        Profile = $profileName
                        Enabled = $enabled
                        DefaultInboundAction = $defaultInboundAction
                        DefaultOutboundAction = $defaultOutboundAction
                    }
            }
            
            if ($CollectEvidence) {
                $testResult = Add-Evidence -TestResult $testResult `
                    -FindingName "Firewall Profile Evidence - $profileName" `
                    -EvidenceType "Configuration" `
                    -EvidenceData $profile `
                    -Description "Firewall profile configuration for $profileName"
            }
        }
        
        return $testResult
    }
    catch {
        Write-Error "Error checking firewall status: $_"
        $testResult = Add-Finding -TestResult $testResult `
            -FindingName "Test Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error occurred during firewall status check" `
            -TechnicalDetails @{
                Error = $_.Exception.Message
                StackTrace = $_.ScriptStackTrace
            }
        return $testResult
    }
}

# Export the function
Export-ModuleMember -Function Test-FirewallStatus 