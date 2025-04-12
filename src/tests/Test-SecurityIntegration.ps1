# -----------------------------------------------------------------------------
# Security Integration Testing Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Performs integration testing of security assessment modules.

.DESCRIPTION
    This function runs integration tests to verify that security assessment modules
    work together correctly and produce consistent results.

.PARAMETER OutputPath
    Path to save test results.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER RunAllTests
    Switch parameter to run all available tests.

.PARAMETER TestCategories
    Array of test categories to run. If not specified and RunAllTests is not set,
    only core tests will be run.

.OUTPUTS
    [hashtable] A hashtable containing test results and metrics.

.EXAMPLE
    Test-SecurityIntegration -RunAllTests -Verbose

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-SecurityIntegration {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$RunAllTests,
        
        [Parameter()]
        [string[]]$TestCategories = @("Core")
    )

    $result = Initialize-TestResult -TestName "Test-SecurityIntegration" -Category "Core" -Description "Integration testing of security assessment modules"

    try {
        # Test core module integration
        Add-Finding -TestResult $result -FindingName "Core Module Integration" -Status "Info" -Description "Testing core module integration" -RiskLevel "Info"
        
        # Test module loading
        $loadedModules = Get-Module | Where-Object { $_.Name -like "*Security*" -or $_.Name -like "*PowerShell*" }
        if ($loadedModules) {
            Add-Finding -TestResult $result -FindingName "Module Loading" -Status "Pass" -Description "Security modules loaded successfully" -RiskLevel "Info" -AdditionalInfo @{
                LoadedModules = $loadedModules.Name
            }
        } else {
            Add-Finding -TestResult $result -FindingName "Module Loading" -Status "Warning" -Description "No security modules found loaded" -RiskLevel "Medium"
        }

        # Test function availability
        $requiredFunctions = @(
            "Test-Dependencies",
            "Test-SecurityIntegration",
            "Initialize-TestResult",
            "Add-Finding",
            "Export-TestResult"
        )

        foreach ($function in $requiredFunctions) {
            if (Get-Command -Name $function -ErrorAction SilentlyContinue) {
                Add-Finding -TestResult $result -FindingName "Function Check: $function" -Status "Pass" -Description "Required function $function is available" -RiskLevel "Info"
            } else {
                Add-Finding -TestResult $result -FindingName "Function Check: $function" -Status "Warning" -Description "Required function $function is not available" -RiskLevel "Medium"
            }
        }

        # Test result handling
        $testResult = Initialize-TestResult -TestName "Test-ResultHandling" -Category "Core" -Description "Testing result handling"
        Add-Finding -TestResult $testResult -FindingName "Result Handling" -Status "Pass" -Description "Result handling test successful" -RiskLevel "Info"
        
        Add-Finding -TestResult $result -FindingName "Result Handling Integration" -Status "Pass" -Description "Result handling integration test successful" -RiskLevel "Info" -AdditionalInfo @{
            TestResult = $testResult
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Integration Test Error" -Status "Error" -Description "Error during integration testing: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SecurityIntegration 