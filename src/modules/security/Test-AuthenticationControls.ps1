# -----------------------------------------------------------------------------
# Authentication Controls Analysis Module
# -----------------------------------------------------------------------------

function Test-AuthenticationControls {
    param (
        [string]$OutputPath = ".\authentication_controls.json"
    )

    Write-SectionHeader "Authentication Controls Check"
    Write-Output "Analyzing authentication controls..."

    # Initialize JSON output object using common function
    $authInfo = Initialize-JsonOutput -Category "AuthenticationControls" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Check password policy
        $passwordPolicy = net accounts | Select-String -Pattern "Maximum password age|Minimum password length|Password history|Lockout duration|Lockout threshold"
        
        # Check account lockout policy
        $lockoutPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ErrorAction SilentlyContinue
        
        # Check NTLM settings
        $ntlmSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ErrorAction SilentlyContinue
        
        # Parse password policy
        $authInfo.PasswordPolicy = @{
            MaxPasswordAge = ($passwordPolicy | Select-String "Maximum password age").ToString().Split(":")[1].Trim()
            MinPasswordLength = ($passwordPolicy | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
            PasswordHistory = ($passwordPolicy | Select-String "Password history").ToString().Split(":")[1].Trim()
            LockoutDuration = ($passwordPolicy | Select-String "Lockout duration").ToString().Split(":")[1].Trim()
            LockoutThreshold = ($passwordPolicy | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
        }
        
        $authInfo.AccountLockout = @{
            LockoutDuration = $lockoutPolicy.LockoutDuration
            LockoutThreshold = $lockoutPolicy.LockoutThreshold
            LockoutWindow = $lockoutPolicy.LockoutWindow
        }
        
        $authInfo.NTLMSettings = @{
            RestrictSendingNTLMTraffic = $ntlmSettings.RestrictSendingNTLMTraffic
            AuditReceivingNTLMTraffic = $ntlmSettings.AuditReceivingNTLMTraffic
        }

        # Add findings based on password policy
        if ([int]$authInfo.PasswordPolicy.MaxPasswordAge -gt 90) {
            Add-Finding -CheckName "Password Age" -Status "Warning" `
                -Details "Maximum password age exceeds 90 days" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "PasswordPolicy"
                    CurrentValue = $authInfo.PasswordPolicy.MaxPasswordAge
                    RecommendedValue = "90 days or less"
                }
        }
        else {
            Add-Finding -CheckName "Password Age" -Status "Pass" `
                -Details "Maximum password age is within recommended range" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "PasswordPolicy"
                    CurrentValue = $authInfo.PasswordPolicy.MaxPasswordAge
                }
        }

        if ([int]$authInfo.PasswordPolicy.MinPasswordLength -lt 8) {
            Add-Finding -CheckName "Password Length" -Status "Warning" `
                -Details "Minimum password length is less than 8 characters" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "PasswordPolicy"
                    CurrentValue = $authInfo.PasswordPolicy.MinPasswordLength
                    RecommendedValue = "8 or more characters"
                }
        }
        else {
            Add-Finding -CheckName "Password Length" -Status "Pass" `
                -Details "Minimum password length meets requirements" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "PasswordPolicy"
                    CurrentValue = $authInfo.PasswordPolicy.MinPasswordLength
                }
        }

        # Add findings based on account lockout
        if ([int]$authInfo.AccountLockout.LockoutThreshold -eq 0) {
            Add-Finding -CheckName "Account Lockout" -Status "Warning" `
                -Details "Account lockout is disabled" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "AccountLockout"
                    Status = "Disabled"
                    LockoutThreshold = $authInfo.AccountLockout.LockoutThreshold
                }
        }
        else {
            Add-Finding -CheckName "Account Lockout" -Status "Pass" `
                -Details "Account lockout is enabled" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "AccountLockout"
                    Status = "Enabled"
                    LockoutThreshold = $authInfo.AccountLockout.LockoutThreshold
                    LockoutDuration = $authInfo.AccountLockout.LockoutDuration
                }
        }

        # Add findings based on NTLM settings
        if ($authInfo.NTLMSettings.RestrictSendingNTLMTraffic -eq 0) {
            Add-Finding -CheckName "NTLM Restrictions" -Status "Warning" `
                -Details "NTLM traffic restrictions are not configured" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "NTLMSettings"
                    Status = "Unrestricted"
                    RestrictSendingNTLMTraffic = $authInfo.NTLMSettings.RestrictSendingNTLMTraffic
                }
        }
        else {
            Add-Finding -CheckName "NTLM Restrictions" -Status "Pass" `
                -Details "NTLM traffic restrictions are configured" -Category "AuthenticationControls" `
                -AdditionalInfo @{
                    Component = "NTLMSettings"
                    Status = "Restricted"
                    RestrictSendingNTLMTraffic = $authInfo.NTLMSettings.RestrictSendingNTLMTraffic
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Authentication Controls Analysis"
        Add-Finding -CheckName "Authentication Controls" -Status "Error" `
            -Details "Failed to check authentication controls: $($_.Exception.Message)" -Category "AuthenticationControls" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $authInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $authInfo
}

# Export the function
Export-ModuleMember -Function Test-AuthenticationControls 