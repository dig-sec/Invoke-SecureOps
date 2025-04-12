# -----------------------------------------------------------------------------
# Security Test Execution Manager
# -----------------------------------------------------------------------------

# Function to initialize test execution
function Initialize-TestExecution {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$AssessmentName = "Security Assessment",
        
        [Parameter()]
        [string]$Description = "Comprehensive security assessment",
        
        [Parameter()]
        [string]$Version = "1.0.0",
        
        [Parameter()]
        [hashtable]$Metadata = @{},
        
        [Parameter()]
        [hashtable]$Configuration = @{}
    )
    
    # Import required modules
    Import-Module "$PSScriptRoot\Test-ConfigurationManager.ps1" -Force
    Import-Module "$PSScriptRoot\Test-ResultManager.ps1" -Force
    Import-Module "$PSScriptRoot\Test-Registry.ps1" -Force
    
    # Get configuration
    $config = Get-TestConfiguration
    if ($Configuration.Count -gt 0) {
        $config = Set-TestConfiguration -Configuration $Configuration
    }
    
    # Initialize results
    $results = Initialize-TestResults -AssessmentName $AssessmentName `
                                    -Description $Description `
                                    -Version $Version `
                                    -Metadata $Metadata
    
    return @{
        Configuration = $config
        Results = $results
        StartTime = Get-Date
    }
}

# Function to execute a single test
function Invoke-SingleTest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$TestContext,
        
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [scriptblock]$TestFunction,
        
        [Parameter()]
        [hashtable]$TestParameters = @{}
    )
    
    $config = $TestContext.Configuration
    $results = $TestContext.Results
    
    Write-Verbose "Executing test: $TestName"
    
    try {
        # Execute test with timeout
        $job = Start-Job -ScriptBlock {
            param($TestFunction, $TestParameters)
            & $TestFunction @TestParameters
        } -ArgumentList $TestFunction, $TestParameters
        
        # Wait for job with timeout
        $completed = Wait-Job -Job $job -Timeout $config.Execution.TimeoutSeconds
        
        if ($completed) {
            $testResult = Receive-Job -Job $job
            
            # Add result to test context
            Add-TestResult -Results $results `
                          -TestName $TestName `
                          -TestResult $testResult
            
            Remove-Job -Job $job
            return $true
        }
        else {
            Stop-Job -Job $job
            Remove-Job -Job $job
            
            # Add timeout result
            $timeoutResult = @{
                Status = "Fail"
                Description = "Test execution timed out"
                Findings = @(
                    @{
                        Title = "Test Execution Timeout"
                        Description = "The test exceeded the maximum execution time of $($config.Execution.TimeoutSeconds) seconds"
                        Severity = "High"
                        Recommendation = "Review the test implementation for performance issues or increase the timeout value"
                    }
                )
            }
            
            Add-TestResult -Results $results `
                          -TestName $TestName `
                          -TestResult $timeoutResult
            
            return $false
        }
    }
    catch {
        Write-Error "Error executing test $TestName : $_"
        
        # Add error result
        $errorResult = @{
            Status = "Fail"
            Description = "Test execution failed"
            Findings = @(
                @{
                    Title = "Test Execution Error"
                    Description = $_.Exception.Message
                    Severity = "High"
                    Recommendation = "Review the test implementation and error details"
                }
            )
        }
        
        Add-TestResult -Results $results `
                      -TestName $TestName `
                      -TestResult $errorResult
        
        return $false
    }
}

# Function to execute tests by category
function Invoke-TestCategory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$TestContext,
        
        [Parameter(Mandatory)]
        [string]$Category,
        
        [Parameter()]
        [string[]]$SpecificTests = @(),
        
        [Parameter()]
        [switch]$SkipDependencies
    )
    
    $config = $TestContext.Configuration
    
    if (-not $config.Categories.ContainsKey($Category)) {
        Write-Error "Category '$Category' not found in configuration"
        return $false
    }
    
    $categoryConfig = $config.Categories[$Category]
    
    if (-not $categoryConfig.Enabled) {
        Write-Warning "Category '$Category' is disabled in configuration"
        return $false
    }
    
    # Check dependencies
    if (-not $SkipDependencies -and $categoryConfig.Dependencies.Count -gt 0) {
        foreach ($dependency in $categoryConfig.Dependencies) {
            Write-Verbose "Checking dependency: $dependency"
            if (-not (Invoke-TestCategory -TestContext $TestContext -Category $dependency)) {
                Write-Warning "Dependency '$dependency' failed for category '$Category'"
                return $false
            }
        }
    }
    
    # Get test functions for category
    $testFunctions = Get-ChildItem -Path "$PSScriptRoot\..\$Category\*.ps1" -ErrorAction SilentlyContinue
    
    if (-not $testFunctions) {
        Write-Warning "No test functions found for category '$Category'"
        return $false
    }
    
    $success = $true
    
    foreach ($testFile in $testFunctions) {
        $testName = $testFile.BaseName
        
        if ($SpecificTests.Count -gt 0 -and $testName -notin $SpecificTests) {
            continue
        }
        
        # Import test function
        . $testFile.FullName
        
        # Execute test
        $testSuccess = Invoke-SingleTest -TestContext $TestContext `
                                       -TestName $testName `
                                       -TestFunction (Get-Item "function:$testName").ScriptBlock
        
        if (-not $testSuccess) {
            $success = $false
        }
    }
    
    return $success
}

# Function to execute all tests
function Invoke-AllTests {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$TestContext,
        
        [Parameter()]
        [string[]]$Categories = @(),
        
        [Parameter()]
        [string[]]$SpecificTests = @(),
        
        [Parameter()]
        [switch]$SkipDependencies
    )
    
    $config = $TestContext.Configuration
    
    # Determine categories to run
    $categoriesToRun = if ($Categories.Count -gt 0) {
        $Categories | Where-Object { $config.Categories.ContainsKey($_) }
    }
    else {
        $config.Categories.Keys | Where-Object { $config.Categories[$_].Enabled }
    }
    
    if ($categoriesToRun.Count -eq 0) {
        Write-Warning "No valid categories specified for execution"
        return $false
    }
    
    $success = $true
    
    foreach ($category in $categoriesToRun) {
        Write-Verbose "Executing category: $category"
        $categorySuccess = Invoke-TestCategory -TestContext $TestContext `
                                             -Category $category `
                                             -SpecificTests $SpecificTests `
                                             -SkipDependencies $SkipDependencies
        
        if (-not $categorySuccess) {
            $success = $false
        }
    }
    
    # Complete test results
    Complete-TestResults -Results $TestContext.Results
    
    return $success
}

# Function to export execution results
function Export-ExecutionResults {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$TestContext,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet("JSON", "HTML", "Markdown", "Text")]
        [string]$Format = "JSON",
        
        [Parameter()]
        [switch]$PrettyPrint,
        
        [Parameter()]
        [switch]$IncludeMetadata,
        
        [Parameter()]
        [switch]$UseEmoji
    )
    
    $results = $TestContext.Results
    
    switch ($Format) {
        "JSON" {
            return Export-TestResults -Results $results `
                                    -Path $OutputPath `
                                    -PrettyPrint:$PrettyPrint `
                                    -ExcludeMetadata:(-not $IncludeMetadata)
        }
        default {
            return New-TestReport -Results $results `
                                -Path $OutputPath `
                                -Format $Format `
                                -IncludeMetadata:$IncludeMetadata `
                                -UseEmoji:$UseEmoji
        }
    }
}

# Export functions
Export-ModuleMember -Function Initialize-TestExecution,
                              Invoke-SingleTest,
                              Invoke-TestCategory,
                              Invoke-AllTests,
                              Export-ExecutionResults 