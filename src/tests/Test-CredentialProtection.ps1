# -----------------------------------------------------------------------------
# Credential Protection Analysis Module
# -----------------------------------------------------------------------------

function Test-CredentialProtection {
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

    Write-SectionHeader "Credential Protection Check"
    Write-Output "Analyzing credential protection settings..."

    # Initialize test result using helper function
    $testResult = Initialize-TestResult -TestName "Test-CredentialProtection" -Category "Security" -Description "Credential protection security check" -RiskLevel "High"
    
    try {
        # Check Credential Guard status
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        
        if ($deviceGuard.SecurityServicesConfigured -contains 1) {
            if ($deviceGuard.SecurityServicesRunning -contains 1) {
                $testResult = Add-Finding -TestResult $testResult `
                    -Name "Credential Guard Status" `
                    -Status "Pass" `
                    -Description "Credential Guard is configured and running" `
                    -RiskLevel "Info" `
                    -TechnicalDetails @{
                        SecurityServicesConfigured = $deviceGuard.SecurityServicesConfigured
                        SecurityServicesRunning = $deviceGuard.SecurityServicesRunning
                        VirtualizationBasedSecurityStatus = $deviceGuard.VirtualizationBasedSecurityStatus
                    }
            }
            else {
                $testResult = Add-Finding -TestResult $testResult `
                    -Name "Credential Guard Status" `
                    -Status "Warning" `
                    -Description "Credential Guard is configured but not running" `
                    -RiskLevel "High" `
                    -TechnicalDetails @{
                        SecurityServicesConfigured = $deviceGuard.SecurityServicesConfigured
                        SecurityServicesRunning = $deviceGuard.SecurityServicesRunning
                        VirtualizationBasedSecurityStatus = $deviceGuard.VirtualizationBasedSecurityStatus
                    }
            }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Credential Guard Status" `
                -Status "Warning" `
                -Description "Credential Guard is not configured" `
                -RiskLevel "High" `
                -TechnicalDetails @{
                    SecurityServicesConfigured = $deviceGuard.SecurityServicesConfigured
                    SecurityServicesRunning = $deviceGuard.SecurityServicesRunning
                    VirtualizationBasedSecurityStatus = $deviceGuard.VirtualizationBasedSecurityStatus
                }
        }

        # Check WDigest authentication
        $wdigestKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        
        if ($null -eq $wdigestKey -or $wdigestKey.UseLogonCredential -eq 0) {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "WDigest Authentication" `
                -Status "Pass" `
                -Description "WDigest authentication is properly configured" `
                -RiskLevel "Info" `
                -TechnicalDetails @{
                    UseLogonCredential = $wdigestKey.UseLogonCredential
                    KeyExists = $null -ne $wdigestKey
                }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "WDigest Authentication" `
                -Status "Warning" `
                -Description "WDigest authentication is enabled, which may store credentials in memory" `
                -RiskLevel "High" `
                -TechnicalDetails @{
                    UseLogonCredential = $wdigestKey.UseLogonCredential
                    KeyExists = $true
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Credential Protection Analysis"
        $testResult = Add-Finding -TestResult $testResult `
            -Name "Credential Protection Error" `
            -Status "Error" `
            -Description "Failed to check credential protection: $($_.Exception.Message)" `
            -RiskLevel "High" `
            -TechnicalDetails $errorInfo
    }

    # Export results if output path provided
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-CredentialProtection 