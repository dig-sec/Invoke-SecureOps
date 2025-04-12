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
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
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

        # Check Credential Guard
        if ($credentialGuard.SecurityServicesRunning -contains 1) {
            Add-Finding -TestResult $credentialInfo -FindingName "Credential Guard" -Status "Pass" `
                -Description "Credential Guard is enabled" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "CredentialGuard"
                    Status = "Enabled"
                    SecurityServices = $credentialGuard.SecurityServicesRunning
                }
        } else {
            Add-Finding -TestResult $credentialInfo -FindingName "Credential Guard" -Status "Warning" `
                -Description "Credential Guard is not enabled" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "CredentialGuard"
                    Status = "Disabled"
                    SecurityServices = $credentialGuard.SecurityServicesRunning
                }
        }

        # Check LSA Protection
        if ($lsaProtection.RunAsPPL -eq 1) {
            Add-Finding -TestResult $credentialInfo -FindingName "LSA Protection" -Status "Pass" `
                -Description "LSA Protection is enabled" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "LSAProtection"
                    Status = "Enabled"
                    RunAsPPL = $lsaProtection.RunAsPPL
                }
        } else {
            Add-Finding -TestResult $credentialInfo -FindingName "LSA Protection" -Status "Warning" `
                -Description "LSA Protection is not enabled" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "LSAProtection"
                    Status = "Disabled"
                    RunAsPPL = $lsaProtection.RunAsPPL
                }
        }

        # Check Credential Manager service
        if ($credentialManager.Status -eq "Running") {
            Add-Finding -TestResult $credentialInfo -FindingName "Credential Manager" -Status "Pass" `
                -Description "Credential Manager service is running" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "CredentialManager"
                    Status = "Running"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Credential Protection Analysis"
        Add-Finding -TestResult $credentialInfo -FindingName "Credential Protection" -Status "Error" `
            -Description "Failed to check credential protection: $($_.Exception.Message)" -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-TestResult -TestResult $credentialInfo -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        Write-Output "Results exported to: $OutputPath"
    }

    return $credentialInfo
}

# Export the function
Export-ModuleMember -Function Test-CredentialProtection 