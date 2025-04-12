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
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-AuthenticationControls" -Category "Security" -Description "Analyzes Windows authentication and password policies"
    
    try {
        # Get password policy settings
        $netAccounts = net accounts | Out-String
        
        # Check maximum password age
        $maxPwdAge = [int]($netAccounts | Select-String -Pattern "Maximum password age \(days\):\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -Name "Maximum Password Age" `
            -Status $(if ($maxPwdAge -le 90) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($maxPwdAge -le 90) { "Info" } else { "Medium" }) `
            -Description "Maximum password age is set to $maxPwdAge days" `
            -Recommendation $(if ($maxPwdAge -le 90) { "No action required" } else { "Consider reducing maximum password age to 90 days or less" })
        
        # Check minimum password length
        $minPwdLength = [int]($netAccounts | Select-String -Pattern "Minimum password length:\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -Name "Minimum Password Length" `
            -Status $(if ($minPwdLength -ge 12) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($minPwdLength -ge 12) { "Info" } else { "Medium" }) `
            -Description "Minimum password length is set to $minPwdLength characters" `
            -Recommendation $(if ($minPwdLength -ge 12) { "No action required" } else { "Consider increasing minimum password length to at least 12 characters" })
        
        # Check password history
        $pwdHistory = [int]($netAccounts | Select-String -Pattern "Length of password history maintained:\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -Name "Password History" `
            -Status $(if ($pwdHistory -ge 24) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($pwdHistory -ge 24) { "Info" } else { "Medium" }) `
            -Description "Password history is set to remember $pwdHistory previous passwords" `
            -Recommendation $(if ($pwdHistory -ge 24) { "No action required" } else { "Consider increasing password history to at least 24 passwords" })
        
        # Check account lockout threshold
        $lockoutThreshold = [int]($netAccounts | Select-String -Pattern "Lockout threshold:\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -Name "Account Lockout Threshold" `
            -Status $(if ($lockoutThreshold -gt 0 -and $lockoutThreshold -le 5) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($lockoutThreshold -gt 0 -and $lockoutThreshold -le 5) { "Info" } else { "Medium" }) `
            -Description "Account lockout threshold is set to $lockoutThreshold failed attempts" `
            -Recommendation $(if ($lockoutThreshold -gt 0 -and $lockoutThreshold -le 5) { "No action required" } else { "Configure account lockout threshold between 1 and 5 failed attempts" })
        
        # Check lockout duration
        $lockoutDuration = [int]($netAccounts | Select-String -Pattern "Lockout duration \(minutes\):\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -Name "Account Lockout Duration" `
            -Status $(if ($lockoutDuration -ge 15) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($lockoutDuration -ge 15) { "Info" } else { "Medium" }) `
            -Description "Account lockout duration is set to $lockoutDuration minutes" `
            -Recommendation $(if ($lockoutDuration -ge 15) { "No action required" } else { "Consider increasing account lockout duration to at least 15 minutes" })
        
        # Check password complexity requirements
        try {
            $tempFile = [System.IO.Path]::GetTempFileName()
            $securityPolicy = secedit /export /cfg $tempFile | Out-String
            $complexityEnabled = Select-String -Path $tempFile -Pattern "PasswordComplexity\s*=\s*1"
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            
            Add-Finding -TestResult $result -Name "Password Complexity" `
                -Status $(if ($complexityEnabled) { "Pass" } else { "Warning" }) `
                -RiskLevel $(if ($complexityEnabled) { "Info" } else { "Medium" }) `
                -Description "Password complexity requirements are $(if ($complexityEnabled) { 'enabled' } else { 'disabled' })" `
                -Recommendation $(if ($complexityEnabled) { "No action required" } else { "Enable password complexity requirements" })
        }
        catch {
            Add-Finding -TestResult $result -Name "Password Complexity Check Failed" `
                -Status "Warning" -RiskLevel "Medium" `
                -Description "Unable to check password complexity requirements: $_" `
                -Recommendation "Verify access to security policy settings"
        }
        
        if ($CollectEvidence) {
            Add-Evidence -TestResult $result -FindingName "Authentication Settings" `
                -EvidenceType "CommandOutput" -EvidenceData $netAccounts `
                -Description "Output of net accounts command showing password and lockout policies"
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during authentication controls test: $_"
        Add-Finding -TestResult $result -Name "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "An error occurred while checking authentication controls: $_" `
            -Recommendation "Check system permissions and policy access"
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-AuthenticationControls 