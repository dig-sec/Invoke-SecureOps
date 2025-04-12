# -----------------------------------------------------------------------------
# Credential Protection Analysis Module
# -----------------------------------------------------------------------------

function Test-CredentialProtection {
    param (
        [string]$OutputPath = ".\credential_protection.json"
    )

    Write-SectionHeader "Credential Protection Check"
    Write-Output "Analyzing credential protection settings..."

    # Initialize JSON output object using common function
    $credentialInfo = Initialize-JsonOutput -Category "CredentialProtection" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Check Credential Guard
        $credentialGuard = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        
        # Check LSA Protection
        $lsaProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        
        # Check Credential Manager service
        $credentialManager = Get-Service -Name "CredentialManager" -ErrorAction SilentlyContinue
        
        $credentialInfo.CredentialGuard = @{
            SecurityServicesRunning = $credentialGuard.SecurityServicesRunning
            VirtualizationBasedSecurityStatus = $credentialGuard.VirtualizationBasedSecurityStatus
        }
        $credentialInfo.LSAProtection = @{
            RunAsPPL = $lsaProtection.RunAsPPL
        }
        $credentialInfo.CredentialManager = @{
            Status = $credentialManager.Status
        }

        # Add findings based on credential protection status
        if ($credentialGuard.SecurityServicesRunning -notcontains "CredentialGuard") {
            Add-Finding -CheckName "Credential Guard" -Status "Warning" `
                -Details "Credential Guard is not running" -Category "CredentialProtection" `
                -AdditionalInfo @{
                    Component = "CredentialGuard"
                    Status = "Disabled"
                    Services = $credentialGuard.SecurityServicesRunning
                }
        }
        else {
            Add-Finding -CheckName "Credential Guard" -Status "Pass" `
                -Details "Credential Guard is running" -Category "CredentialProtection" `
                -AdditionalInfo @{
                    Component = "CredentialGuard"
                    Status = "Enabled"
                    Services = $credentialGuard.SecurityServicesRunning
                }
        }

        if (-not $lsaProtection.RunAsPPL) {
            Add-Finding -CheckName "LSA Protection" -Status "Warning" `
                -Details "LSA Protection is not enabled" -Category "CredentialProtection" `
                -AdditionalInfo @{
                    Component = "LSAProtection"
                    Status = "Disabled"
                    RunAsPPL = $lsaProtection.RunAsPPL
                }
        }
        else {
            Add-Finding -CheckName "LSA Protection" -Status "Pass" `
                -Details "LSA Protection is enabled" -Category "CredentialProtection" `
                -AdditionalInfo @{
                    Component = "LSAProtection"
                    Status = "Enabled"
                    RunAsPPL = $lsaProtection.RunAsPPL
                }
        }

        if ($credentialManager.Status -ne "Running") {
            Add-Finding -CheckName "Credential Manager" -Status "Warning" `
                -Details "Credential Manager service is not running" -Category "CredentialProtection" `
                -AdditionalInfo @{
                    Component = "CredentialManager"
                    Status = $credentialManager.Status
                    ExpectedStatus = "Running"
                }
        }
        else {
            Add-Finding -CheckName "Credential Manager" -Status "Pass" `
                -Details "Credential Manager service is running" -Category "CredentialProtection" `
                -AdditionalInfo @{
                    Component = "CredentialManager"
                    Status = "Running"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Credential Protection Analysis"
        Add-Finding -CheckName "Credential Protection" -Status "Error" `
            -Details "Failed to check credential protection: $($_.Exception.Message)" -Category "CredentialProtection" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $credentialInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $credentialInfo
}

# Export the function
Export-ModuleMember -Function Test-CredentialProtection 