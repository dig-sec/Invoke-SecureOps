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
    Path to save test results. Defaults to '.\integration_test_results.json'.

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
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\integration_test_results.json",
        
        [Parameter(Mandatory = $false)]
        [switch]$RunAllTests,
        
        [Parameter(Mandatory = $false)]
        [string[]]$TestCategories = @("Core"),
        
        [Parameter(Mandatory = $false)]
        [switch]$Verbose
    )

    try {
        Write-SectionHeader "Security Integration Testing"
        Write-Output "Starting integration tests..."

        # Initialize results object
        $testResults = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            TestSuite = "Security Integration Tests"
            Categories = @()
            TotalTests = 0
            PassedTests = 0
            FailedTests = 0
            SkippedTests = 0
            StartTime = Get-Date
            EndTime = $null
            Duration = 0
            Results = @()
        }

        # Define test categories and their dependencies
        $testMatrix = @{
            Core = @{
                Name = "Core Security Tests"
                Dependencies = @()
                Tests = @(
                    @{
                        Name = "Test-Dependencies"
                        Category = "Core"
                        Priority = "High"
                        Dependencies = @()
                    },
                    @{
                        Name = "Test-OptimizationSettings"
                        Category = "Core"
                        Priority = "Medium"
                        Dependencies = @("Test-Dependencies")
                    }
                )
            }
            PowerShell = @{
                Name = "PowerShell Security Tests"
                Dependencies = @("Core")
                Tests = @(
                    @{
                        Name = "Test-PowerShellSecurity"
                        Category = "PowerShell"
                        Priority = "High"
                        Dependencies = @("Test-Dependencies")
                    },
                    @{
                        Name = "Test-PowerShellLogging"
                        Category = "PowerShell"
                        Priority = "High"
                        Dependencies = @("Test-PowerShellSecurity")
                    }
                )
            }
            Defender = @{
                Name = "Windows Defender Tests"
                Dependencies = @("Core")
                Tests = @(
                    @{
                        Name = "Test-DefenderStatus"
                        Category = "Defender"
                        Priority = "High"
                        Dependencies = @("Test-Dependencies")
                    },
                    @{
                        Name = "Test-DefenderConfiguration"
                        Category = "Defender"
                        Priority = "High"
                        Dependencies = @("Test-DefenderStatus")
                    }
                )
            }
            Network = @{
                Name = "Network Security Tests"
                Dependencies = @("Core")
                Tests = @(
                    @{
                        Name = "Test-FirewallStatus"
                        Category = "Network"
                        Priority = "High"
                        Dependencies = @("Test-Dependencies")
                    },
                    @{
                        Name = "Test-NetworkSecurityProtocols"
                        Category = "Network"
                        Priority = "Medium"
                        Dependencies = @("Test-FirewallStatus")
                    }
                )
            }
            Credentials = @{
                Name = "Credential Protection Tests"
                Dependencies = @("Core")
                Tests = @(
                    @{
                        Name = "Test-CredentialProtection"
                        Category = "Credentials"
                        Priority = "High"
                        Dependencies = @("Test-Dependencies")
                    },
                    @{
                        Name = "Test-LSAProtection"
                        Category = "Credentials"
                        Priority = "High"
                        Dependencies = @("Test-CredentialProtection")
                    }
                )
            }
        }

        # Determine which categories to test
        $categoriesToTest = @()
        if ($RunAllTests) {
            $categoriesToTest = $testMatrix.Keys
        }
        else {
            $categoriesToTest = $TestCategories
        }

        # Validate categories
        foreach ($category in $categoriesToTest) {
            if (-not $testMatrix.ContainsKey($category)) {
                Write-Warning "Unknown test category: $category"
                continue
            }

            $testResults.Categories += $category
            
            # Check category dependencies
            foreach ($dependency in $testMatrix[$category].Dependencies) {
                if ($dependency -notin $categoriesToTest) {
                    Write-Warning "Adding required dependency category: $dependency"
                    $categoriesToTest += $dependency
                }
            }
        }

        # Initialize optimization settings
        $optimizationSettings = Initialize-OptimizationSettings -MaxParallelJobs 4

        # Run tests for each category
        foreach ($category in $categoriesToTest) {
            Write-Output "`nRunning tests for category: $category"
            $categoryInfo = $testMatrix[$category]
            
            # Run tests in dependency order
            $testsToRun = $categoryInfo.Tests | Sort-Object { $_.Dependencies.Count }
            
            foreach ($test in $testsToRun) {
                $testResult = @{
                    Name = $test.Name
                    Category = $test.Category
                    Priority = $test.Priority
                    Status = "Unknown"
                    StartTime = Get-Date
                    EndTime = $null
                    Duration = 0
                    Error = $null
                    Dependencies = $test.Dependencies
                    DependenciesStatus = @{}
                }

                # Check dependencies
                $canRun = $true
                foreach ($dependency in $test.Dependencies) {
                    $dependencyResult = $testResults.Results | Where-Object { $_.Name -eq $dependency } | Select-Object -First 1
                    if ($dependencyResult) {
                        $testResult.DependenciesStatus[$dependency] = $dependencyResult.Status
                        if ($dependencyResult.Status -ne "Pass") {
                            $canRun = $false
                            break
                        }
                    }
                    else {
                        Write-Warning "Dependency not found: $dependency"
                        $canRun = $false
                        break
                    }
                }

                if (-not $canRun) {
                    $testResult.Status = "Skipped"
                    $testResult.Error = "Dependencies not met"
                    $testResults.SkippedTests++
                }
                else {
                    try {
                        # Run the test
                        Write-Output "Running test: $($test.Name)"
                        $result = & $test.Name
                        
                        if ($result.Status -eq "Pass") {
                            $testResult.Status = "Pass"
                            $testResults.PassedTests++
                        }
                        else {
                            $testResult.Status = "Fail"
                            $testResult.Error = $result.Details
                            $testResults.FailedTests++
                        }
                    }
                    catch {
                        $testResult.Status = "Error"
                        $testResult.Error = $_.Exception.Message
                        $testResults.FailedTests++
                    }
                }

                # Calculate test duration
                $testResult.EndTime = Get-Date
                $testResult.Duration = ($testResult.EndTime - $testResult.StartTime).TotalSeconds

                $testResults.Results += $testResult
                $testResults.TotalTests++

                # Output test result
                $statusColor = switch ($testResult.Status) {
                    "Pass" { "Green" }
                    "Fail" { "Red" }
                    "Error" { "Magenta" }
                    "Skipped" { "Yellow" }
                    default { "White" }
                }
                Write-Host "[$($testResult.Status)] $($test.Name)" -ForegroundColor $statusColor
                
                if ($testResult.Error) {
                    Write-Host "  Error: $($testResult.Error)" -ForegroundColor Gray
                }
            }
        }

        # Calculate total duration
        $testResults.EndTime = Get-Date
        $testResults.Duration = ($testResults.EndTime - $testResults.StartTime).TotalSeconds

        # Output summary
        Write-Output "`nTest Summary:"
        Write-Output "- Total Tests: $($testResults.TotalTests)"
        Write-Output "- Passed: $($testResults.PassedTests)"
        Write-Output "- Failed: $($testResults.FailedTests)"
        Write-Output "- Skipped: $($testResults.SkippedTests)"
        Write-Output "- Duration: $($testResults.Duration) seconds"

        # Export results
        $testResults | ConvertTo-Json -Depth 10 | Out-File $OutputPath
        Write-Output "`nTest results exported to: $OutputPath"

        return $testResults
    }
    catch {
        Write-Error "Error during integration testing: $_"
        throw
    }
}

# Export the function
Export-ModuleMember -Function Test-SecurityIntegration 