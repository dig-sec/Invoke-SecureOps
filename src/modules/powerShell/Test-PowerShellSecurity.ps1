# -----------------------------------------------------------------------------
# PowerShell Execution Policy and Logging Analysis Module
# -----------------------------------------------------------------------------

function Test-PowerShellExecutionPolicy {
    param (
        [string]$OutputPath = ".\powershell_execution_policy.json"
    )

    Write-SectionHeader "PowerShell Execution Policy Check"
    Write-Output "Analyzing PowerShell execution policy and logging settings..."

    # Initialize JSON output object using common function
    $psInfo = Initialize-JsonOutput -Category "PowerShellExecutionPolicy" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Get PowerShell execution policy
        $executionPolicy = Get-ExecutionPolicy
        
        # Get PowerShell version
        $psVersion = $PSVersionTable.PSVersion
        
        # Get PowerShell module logging settings
        $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
        
        # Get PowerShell script block logging settings
        $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        
        $psInfo.ExecutionPolicy = $executionPolicy
        $psInfo.PowerShellVersion = $psVersion.ToString()
        $psInfo.ModuleLogging = @{
            Enabled = $moduleLogging.EnableModuleLogging
        }
        $psInfo.ScriptBlockLogging = @{
            Enabled = $scriptBlockLogging.EnableScriptBlockLogging
        }

        # Add findings based on PowerShell security settings
        if ($executionPolicy -eq "Unrestricted") {
            Add-Finding -CheckName "PowerShell Execution Policy" -Status "Fail" `
                -Details "Execution policy is set to Unrestricted" -Category "PowerShellExecutionPolicy" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    CurrentValue = $executionPolicy
                    RecommendedValue = "RemoteSigned or Restricted"
                }
        }
        elseif ($executionPolicy -eq "RemoteSigned") {
            Add-Finding -CheckName "PowerShell Execution Policy" -Status "Pass" `
                -Details "Execution policy is set to RemoteSigned" -Category "PowerShellExecutionPolicy" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    CurrentValue = $executionPolicy
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Execution Policy" -Status "Info" `
                -Details "Execution policy is set to $executionPolicy" -Category "PowerShellExecutionPolicy" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    CurrentValue = $executionPolicy
                }
        }

        if (-not $moduleLogging.EnableModuleLogging) {
            Add-Finding -CheckName "PowerShell Module Logging" -Status "Warning" `
                -Details "Module logging is not enabled" -Category "PowerShellExecutionPolicy" `
                -AdditionalInfo @{
                    Component = "ModuleLogging"
                    Status = "Disabled"
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Module Logging" -Status "Pass" `
                -Details "Module logging is enabled" -Category "PowerShellExecutionPolicy" `
                -AdditionalInfo @{
                    Component = "ModuleLogging"
                    Status = "Enabled"
                }
        }

        if (-not $scriptBlockLogging.EnableScriptBlockLogging) {
            Add-Finding -CheckName "PowerShell Script Block Logging" -Status "Warning" `
                -Details "Script block logging is not enabled" -Category "PowerShellExecutionPolicy" `
                -AdditionalInfo @{
                    Component = "ScriptBlockLogging"
                    Status = "Disabled"
                }
        }
        else {
            Add-Finding -CheckName "PowerShell Script Block Logging" -Status "Pass" `
                -Details "Script block logging is enabled" -Category "PowerShellExecutionPolicy" `
                -AdditionalInfo @{
                    Component = "ScriptBlockLogging"
                    Status = "Enabled"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "PowerShell Execution Policy Analysis"
        Add-Finding -CheckName "PowerShell Execution Policy" -Status "Error" `
            -Details "Failed to check PowerShell execution policy: $($_.Exception.Message)" -Category "PowerShellExecutionPolicy" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $psInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $psInfo
}

# Export the function
Export-ModuleMember -Function Test-PowerShellExecutionPolicy 