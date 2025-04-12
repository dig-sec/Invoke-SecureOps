# -----------------------------------------------------------------------------
# PowerShell Execution Policy and Logging Analysis Module
# -----------------------------------------------------------------------------

function Test-PowerShellSecurity {
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

    Write-SectionHeader "PowerShell Security Check"
    Write-Output "Analyzing PowerShell security settings..."

    # Initialize test result
    $testResult = Initialize-TestResult -Name "Test-PowerShellSecurity"

    try {
        # Get PowerShell execution policy
        $executionPolicy = Get-ExecutionPolicy
        
        # Get PowerShell version
        $psVersion = $PSVersionTable.PSVersion
        
        # Get PowerShell module logging settings
        $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
        
        # Get PowerShell script block logging settings
        $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        
        # Add findings based on PowerShell security settings
        if ($executionPolicy -eq "Unrestricted") {
            Add-Finding -TestResult $testResult -FindingName "PowerShell Execution Policy" -Status "Fail" `
                -Description "Execution policy is set to Unrestricted" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    CurrentValue = $executionPolicy
                    RecommendedValue = "RemoteSigned or Restricted"
                }
        }
        elseif ($executionPolicy -eq "RemoteSigned") {
            Add-Finding -TestResult $testResult -FindingName "PowerShell Execution Policy" -Status "Pass" `
                -Description "Execution policy is set to RemoteSigned" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    CurrentValue = $executionPolicy
                }
        }
        else {
            Add-Finding -TestResult $testResult -FindingName "PowerShell Execution Policy" -Status "Info" `
                -Description "Execution policy is set to $executionPolicy" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "ExecutionPolicy"
                    CurrentValue = $executionPolicy
                }
        }

        if (-not $moduleLogging.EnableModuleLogging) {
            Add-Finding -TestResult $testResult -FindingName "PowerShell Module Logging" -Status "Warning" `
                -Description "Module logging is not enabled" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "ModuleLogging"
                    Status = "Disabled"
                }
        }
        else {
            Add-Finding -TestResult $testResult -FindingName "PowerShell Module Logging" -Status "Pass" `
                -Description "Module logging is enabled" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "ModuleLogging"
                    Status = "Enabled"
                }
        }

        if (-not $scriptBlockLogging.EnableScriptBlockLogging) {
            Add-Finding -TestResult $testResult -FindingName "PowerShell Script Block Logging" -Status "Warning" `
                -Description "Script block logging is not enabled" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "ScriptBlockLogging"
                    Status = "Disabled"
                }
        }
        else {
            Add-Finding -TestResult $testResult -FindingName "PowerShell Script Block Logging" -Status "Pass" `
                -Description "Script block logging is enabled" -RiskLevel "Info" `
                -AdditionalInfo @{
                    Component = "ScriptBlockLogging"
                    Status = "Enabled"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "PowerShell Security Analysis"
        Add-Finding -TestResult $testResult -FindingName "PowerShell Security" -Status "Error" `
            -Description "Failed to check PowerShell security settings: $($_.Exception.Message)" -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    # Export results if output path provided
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-PowerShellSecurity 