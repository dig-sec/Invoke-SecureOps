# -----------------------------------------------------------------------------
# PowerShell Security Analysis Module
# -----------------------------------------------------------------------------

function Test-PowerShellSecurity {
    param (
        [string]$OutputPath = ".\powershell_security.json"
    )

    Write-SectionHeader "PowerShell Security Check"
    Write-Output "Analyzing PowerShell security settings..."

    # Initialize JSON output object using common function
    $powershellSecurityInfo = Initialize-JsonOutput -Category "PowerShellSecurity" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Get PowerShell execution policy
        $executionPolicy = Get-ExecutionPolicy -List
        
        # Get PowerShell module logging status
        $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
        
        # Get PowerShell script block logging status
        $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        
        # Get PowerShell transcription status
        $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue

        $powershellSecurityInfo.ExecutionPolicy = @{
            Policies = $executionPolicy | ForEach-Object {
                @{
                    Scope = $_.Scope
                    Policy = $_.ExecutionPolicy
                }
            }
        }
        
        $powershellSecurityInfo.ModuleLogging = @{
            Enabled = $moduleLogging.EnableModuleLogging -eq 1
            Path = $moduleLogging.ModuleLoggingPath
        }
        
        $powershellSecurityInfo.ScriptBlockLogging = @{
            Enabled = $scriptBlockLogging.EnableScriptBlockLogging -eq 1
        }
        
        $powershellSecurityInfo.Transcription = @{
            Enabled = $transcription.EnableTranscripting -eq 1
            Path = $transcription.OutputDirectory
        }

        # Check execution policy
        $unrestrictedPolicies = @()
        foreach ($policy in $executionPolicy) {
            if ($policy.ExecutionPolicy -eq "Unrestricted") {
                $unrestrictedPolicies += @{
                    Scope = $policy.Scope
                    Policy = $policy.ExecutionPolicy
                }
            }
        }

        if ($unrestrictedPolicies.Count -gt 0) {
            Add-Finding -CheckName "PowerShell Execution Policy" -Status "Warning" `
                -Details "Found $($unrestrictedPolicies.Count) scopes with Unrestricted policy" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    Status = "Unrestricted Found"
                    Policies = $unrestrictedPolicies
                    Recommendation = "Consider setting more restrictive execution policies"
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Execution Policy" -Status "Pass" `
                -Details "No Unrestricted execution policies found" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    Status = "Properly Restricted"
                }
        }

        # Check module logging
        if (-not $powershellSecurityInfo.ModuleLogging.Enabled) {
            Add-Finding -CheckName "PowerShell Module Logging" -Status "Warning" `
                -Details "Module logging is not enabled" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "ModuleLogging"
                    Status = "Disabled"
                    Recommendation = "Enable PowerShell module logging for better security monitoring"
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Module Logging" -Status "Pass" `
                -Details "Module logging is enabled" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "ModuleLogging"
                    Status = "Enabled"
                    LogPath = $powershellSecurityInfo.ModuleLogging.Path
                }
        }

        # Check script block logging
        if (-not $powershellSecurityInfo.ScriptBlockLogging.Enabled) {
            Add-Finding -CheckName "PowerShell Script Block Logging" -Status "Warning" `
                -Details "Script block logging is not enabled" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "ScriptBlockLogging"
                    Status = "Disabled"
                    Recommendation = "Enable PowerShell script block logging for better security monitoring"
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Script Block Logging" -Status "Pass" `
                -Details "Script block logging is enabled" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "ScriptBlockLogging"
                    Status = "Enabled"
                }
        }

        # Check transcription
        if (-not $powershellSecurityInfo.Transcription.Enabled) {
            Add-Finding -CheckName "PowerShell Transcription" -Status "Warning" `
                -Details "PowerShell transcription is not enabled" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "Transcription"
                    Status = "Disabled"
                    Recommendation = "Enable PowerShell transcription for better security monitoring"
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Transcription" -Status "Pass" `
                -Details "PowerShell transcription is enabled" -Category "PowerShellSecurity" `
                -AdditionalInfo @{
                    Component = "Transcription"
                    Status = "Enabled"
                    LogPath = $powershellSecurityInfo.Transcription.Path
                }
        }

        $powershellSecurityInfo.UnrestrictedPolicies = $unrestrictedPolicies
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "PowerShell Security Analysis"
        Add-Finding -CheckName "PowerShell Security" -Status "Error" `
            -Details "Failed to check PowerShell security: $($_.Exception.Message)" -Category "PowerShellSecurity" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $powershellSecurityInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $powershellSecurityInfo
}

# Export the function
Export-ModuleMember -Function Test-PowerShellSecurity 