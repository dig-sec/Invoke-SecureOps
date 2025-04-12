# -----------------------------------------------------------------------------
# Authentication Controls Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for authentication controls and settings.

.DESCRIPTION
    This function analyzes the system's authentication controls, including password policies,
    account lockout settings, and other security-related authentication configurations.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of authentication settings.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-AuthenticationControls -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-AuthenticationControls {
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
    $result = Initialize-TestResult -TestName "Test-AuthenticationControls" -Category "Security" `
        -Description "Analyzes authentication controls and settings"

    try {
        # Check password policies
        $passwordPolicy = net accounts
        $maxPasswordAge = ($passwordPolicy | Select-String "Maximum password age").ToString() -replace ".*: ", ""
        $minPasswordLength = ($passwordPolicy | Select-String "Minimum password length").ToString() -replace ".*: ", ""
        $passwordHistory = ($passwordPolicy | Select-String "Remember").ToString() -replace ".*: ", ""

        # Check maximum password age
        if ([int]$maxPasswordAge -gt 90) {
            Add-Finding -TestResult $result -FindingName "Password Age" -Status "Warning" `
                -Description "Maximum password age exceeds 90 days" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "Password Policy"
                    Setting = "Maximum Password Age"
                    CurrentValue = "$maxPasswordAge days"
                    RecommendedValue = "90 days or less"
                    Recommendation = "Reduce maximum password age to 90 days or less"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Password Age" -Status "Pass" `
                -Description "Maximum password age is within acceptable range" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Password Policy"
                    Setting = "Maximum Password Age"
                    CurrentValue = "$maxPasswordAge days"
                }
        }

        # Check minimum password length
        if ([int]$minPasswordLength -lt 12) {
            Add-Finding -TestResult $result -FindingName "Password Length" -Status "Warning" `
                -Description "Minimum password length is less than 12 characters" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "Password Policy"
                    Setting = "Minimum Password Length"
                    CurrentValue = "$minPasswordLength characters"
                    RecommendedValue = "12 characters or more"
                    Recommendation = "Increase minimum password length to 12 characters"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Password Length" -Status "Pass" `
                -Description "Minimum password length meets requirements" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Password Policy"
                    Setting = "Minimum Password Length"
                    CurrentValue = "$minPasswordLength characters"
                }
        }

        # Check password history
        if ([int]$passwordHistory -lt 24) {
            Add-Finding -TestResult $result -FindingName "Password History" -Status "Warning" `
                -Description "Password history is less than 24 passwords" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "Password Policy"
                    Setting = "Password History"
                    CurrentValue = "$passwordHistory passwords"
                    RecommendedValue = "24 passwords or more"
                    Recommendation = "Increase password history to 24 passwords"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Password History" -Status "Pass" `
                -Description "Password history meets requirements" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Password Policy"
                    Setting = "Password History"
                    CurrentValue = "$passwordHistory passwords"
                }
        }

        # Check account lockout settings
        $lockoutThreshold = ($passwordPolicy | Select-String "Lockout threshold").ToString() -replace ".*: ", ""
        $lockoutDuration = ($passwordPolicy | Select-String "Lockout duration").ToString() -replace ".*: ", ""
        $lockoutWindow = ($passwordPolicy | Select-String "Lockout observation window").ToString() -replace ".*: ", ""

        if ([int]$lockoutThreshold -eq 0) {
            Add-Finding -TestResult $result -FindingName "Account Lockout" -Status "Critical" `
                -Description "Account lockout is disabled" -RiskLevel "Critical" `
                -AdditionalInfo @{
                    Component = "Account Lockout"
                    Setting = "Lockout Threshold"
                    CurrentValue = "Disabled"
                    RecommendedValue = "5 attempts"
                    Recommendation = "Enable account lockout with a threshold of 5 attempts"
                }
        }
        else {
            Add-Finding -TestResult $result -FindingName "Account Lockout" -Status "Pass" `
                -Description "Account lockout is enabled" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Account Lockout"
                    Setting = "Lockout Threshold"
                    CurrentValue = "$lockoutThreshold attempts"
                }
        }

        # Check for password complexity requirements
        $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
        Remove-Item "$env:TEMP\secpol.cfg" -Force

        $passwordComplexity = $secpolContent | Where-Object { $_ -match "PasswordComplexity" }
        if ($passwordComplexity -match "PasswordComplexity\s*=\s*(\d+)") {
            $complexityEnabled = $matches[1] -eq "1"
            if (-not $complexityEnabled) {
                Add-Finding -TestResult $result -FindingName "Password Complexity Disabled" -Status "Critical" `
                    -Description "Password complexity requirements are disabled" -RiskLevel "Critical" `
                    -AdditionalInfo @{
                        Component = "Password Policy"
                        Setting = "Password Complexity"
                        CurrentValue = "Disabled"
                        RecommendedValue = "Enabled"
                        Recommendation = "Enable password complexity requirements"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Password Complexity" -Status "Pass" `
                    -Description "Password complexity requirements are enabled" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Password Policy"
                        Setting = "Password Complexity"
                        CurrentValue = "Enabled"
                    }
                }
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
            -Description "Error during authentication controls analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-AuthenticationControls 