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
        $maxPasswordAge = [int]($netAccounts | Select-String -Pattern "Maximum password age \(days\):\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -FindingName "Maximum Password Age" `
            -Status $(if ($maxPasswordAge -le 90) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($maxPasswordAge -le 90) { "Info" } else { "Medium" }) `
            -Description "Maximum password age is set to $maxPasswordAge days" `
            -TechnicalDetails @{
                Setting = "MaximumPasswordAge"
                Value = $maxPasswordAge
                Recommendation = if ($maxPasswordAge -gt 90) { "Set maximum password age to 90 days or less" }
            }
        
        # Check minimum password length
        $minPasswordLength = [int]($netAccounts | Select-String -Pattern "Minimum password length:\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -FindingName "Minimum Password Length" `
            -Status $(if ($minPasswordLength -ge 12) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($minPasswordLength -ge 12) { "Info" } else { "Medium" }) `
            -Description "Minimum password length is set to $minPasswordLength characters" `
            -TechnicalDetails @{
                Setting = "MinimumPasswordLength"
                Value = $minPasswordLength
                Recommendation = if ($minPasswordLength -lt 12) { "Set minimum password length to at least 12 characters" }
            }
        
        # Check password history
        $passwordHistory = [int]($netAccounts | Select-String -Pattern "Length of password history maintained:\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -FindingName "Password History" `
            -Status $(if ($passwordHistory -ge 24) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($passwordHistory -ge 24) { "Info" } else { "Medium" }) `
            -Description "Password history size is set to $passwordHistory" `
            -TechnicalDetails @{
                Setting = "PasswordHistorySize"
                Value = $passwordHistory
                Recommendation = if ($passwordHistory -lt 24) { "Set password history to at least 24 previous passwords" }
            }
        
        # Check account lockout threshold
        $lockoutThreshold = [int]($netAccounts | Select-String -Pattern "Lockout threshold:\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -FindingName "Account Lockout Threshold" `
            -Status $(if ($lockoutThreshold -gt 0 -and $lockoutThreshold -le 5) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($lockoutThreshold -gt 0 -and $lockoutThreshold -le 5) { "Info" } else { "Medium" }) `
            -Description "Account lockout threshold is set to $lockoutThreshold attempts" `
            -TechnicalDetails @{
                Setting = "LockoutThreshold"
                Value = $lockoutThreshold
                Recommendation = if ($lockoutThreshold -eq 0 -or $lockoutThreshold -gt 5) { "Set account lockout threshold between 1 and 5 attempts" }
            }
        
        # Check account lockout duration
        $lockoutDuration = [int]($netAccounts | Select-String -Pattern "Lockout duration \(minutes\):\s+(\d+)" | ForEach-Object { $_.Matches.Groups[1].Value })
        Add-Finding -TestResult $result -FindingName "Account Lockout Duration" `
            -Status $(if ($lockoutDuration -ge 15) { "Pass" } else { "Warning" }) `
            -RiskLevel $(if ($lockoutDuration -ge 15) { "Info" } else { "Medium" }) `
            -Description "Account lockout duration is set to $lockoutDuration minutes" `
            -TechnicalDetails @{
                Setting = "LockoutDuration"
                Value = $lockoutDuration
                Recommendation = if ($lockoutDuration -lt 15) { "Set account lockout duration to at least 15 minutes" }
            }
        
        # Check password complexity requirements
        try {
            $tempFile = [System.IO.Path]::GetTempFileName()
            $securityPolicy = secedit /export /cfg $tempFile | Out-String
            $complexityEnabled = Select-String -Path $tempFile -Pattern "PasswordComplexity\s*=\s*1"
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            
            if ($complexityEnabled) {
                Add-Finding -TestResult $result -FindingName "Password Complexity" `
                    -Status "Pass" `
                    -RiskLevel "Info" `
                    -Description "Password complexity requirements are enabled" `
                    -TechnicalDetails @{
                        Setting = "PasswordComplexity"
                        Value = $complexityEnabled
                        Recommendation = "Continue enforcing password complexity requirements"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Password Complexity Check Failed" `
                    -Status "Warning" `
                    -RiskLevel "Medium" `
                    -Description "Password complexity requirements are disabled" `
                    -TechnicalDetails @{
                        Setting = "PasswordComplexity"
                        Value = $complexityEnabled
                        Recommendation = "Enable password complexity requirements"
                    }
            }
        }
        catch {
            Add-Finding -TestResult $result -FindingName "Password Complexity Check Failed" `
                -Status "Warning" -RiskLevel "Medium" `
                -Description "Unable to check password complexity requirements: $_" `
                -TechnicalDetails @{
                    Recommendation = "Verify access to security policy settings"
                }
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
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error during authentication controls test: $_" `
            -TechnicalDetails @{
                Recommendation = "Check system permissions and security policy access"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-AuthenticationControls 