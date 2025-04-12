# -----------------------------------------------------------------------------
# Security Test Execution Module
# -----------------------------------------------------------------------------

# Function to run security tests
function Invoke-SecurityTests {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Categories,
        
        [Parameter()]
        [string[]]$Tags,
        
        [Parameter()]
        [string[]]$SpecificTests,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$Verbose
    )
    
    # Initialize results
    $results = @{
        ExecutionTime = Get-Date
        Environment = @{
            ComputerName = $env:COMPUTERNAME
            OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        }
        Tests = @{}
        Summary = @{
            TotalTests = 0
            PassedTests = 0
            FailedTests = 0
            SkippedTests = 0
            Categories = @{}
            Tags = @{}
        }
    }
    
    # Get tests to run
    $tests = @()
    if ($SpecificTests) {
        foreach ($testName in $SpecificTests) {
            $test = Get-TestMetadata -TestName $testName
            if ($test) {
                $tests += $test
            }
            else {
                Write-Warning "Test '$testName' not found in registry"
            }
        }
    }
    elseif ($Categories) {
        foreach ($category in $Categories) {
            $tests += Get-TestsByCategory -Category $category
        }
    }
    elseif ($Tags) {
        foreach ($tag in $Tags) {
            $tests += Get-TestsByTag -Tag $tag
        }
    }
    else {
        $tests = Get-AllTests
    }
    
    # Validate dependencies
    $testOrder = @()
    $processedTests = @{}
    
    foreach ($test in $tests) {
        if (-not $processedTests.ContainsKey($test.Name)) {
            $testOrder += $test
            $processedTests[$test.Name] = $true
            
            # Add dependencies
            if ($test.Dependencies) {
                foreach ($dep in $test.Dependencies) {
                    $depTest = Get-TestMetadata -TestName $dep
                    if ($depTest -and -not $processedTests.ContainsKey($dep)) {
                        $testOrder += $depTest
                        $processedTests[$dep] = $true
                    }
                }
            }
        }
    }
    
    # Run tests in order
    foreach ($test in $testOrder) {
        $testName = $test.Name
        Write-Verbose "Running test: $testName"
        
        try {
            # Run test function
            $testResult = & $testName
            
            # Store result
            $results.Tests[$testName] = @{
                Category = $test.Category
                Description = $test.Description
                Tags = $test.Tags
                ComplianceReferences = $test.ComplianceReferences
                Result = $testResult
                ExecutionTime = Get-Date
                Status = if ($testResult.Status -eq "Pass") { "Pass" } else { "Fail" }
            }
            
            # Update summary
            $results.Summary.TotalTests++
            if ($testResult.Status -eq "Pass") {
                $results.Summary.PassedTests++
            }
            else {
                $results.Summary.FailedTests++
            }
            
            # Update category counts
            if (-not $results.Summary.Categories.ContainsKey($test.Category)) {
                $results.Summary.Categories[$test.Category] = @{
                    Total = 0
                    Passed = 0
                    Failed = 0
                }
            }
            $results.Summary.Categories[$test.Category].Total++
            if ($testResult.Status -eq "Pass") {
                $results.Summary.Categories[$test.Category].Passed++
            }
            else {
                $results.Summary.Categories[$test.Category].Failed++
            }
            
            # Update tag counts
            foreach ($tag in $test.Tags) {
                if (-not $results.Summary.Tags.ContainsKey($tag)) {
                    $results.Summary.Tags[$tag] = @{
                        Total = 0
                        Passed = 0
                        Failed = 0
                    }
                }
                $results.Summary.Tags[$tag].Total++
                if ($testResult.Status -eq "Pass") {
                    $results.Summary.Tags[$tag].Passed++
                }
                else {
                    $results.Summary.Tags[$tag].Failed++
                }
            }
        }
        catch {
            Write-Warning "Failed to run test '$testName': $_"
            $results.Tests[$testName] = @{
                Category = $test.Category
                Description = $test.Description
                Tags = $test.Tags
                ComplianceReferences = $test.ComplianceReferences
                Error = $_.Exception.Message
                ExecutionTime = Get-Date
                Status = "Error"
            }
            
            # Update summary
            $results.Summary.TotalTests++
            $results.Summary.FailedTests++
            
            # Update category counts
            if (-not $results.Summary.Categories.ContainsKey($test.Category)) {
                $results.Summary.Categories[$test.Category] = @{
                    Total = 0
                    Passed = 0
                    Failed = 0
                }
            }
            $results.Summary.Categories[$test.Category].Total++
            $results.Summary.Categories[$test.Category].Failed++
            
            # Update tag counts
            foreach ($tag in $test.Tags) {
                if (-not $results.Summary.Tags.ContainsKey($tag)) {
                    $results.Summary.Tags[$tag] = @{
                        Total = 0
                        Passed = 0
                        Failed = 0
                    }
                }
                $results.Summary.Tags[$tag].Total++
                $results.Summary.Tags[$tag].Failed++
            }
        }
    }
    
    # Export results
    if ($OutputPath) {
        $json = $results | ConvertTo-Json -Depth 10
        if ($PrettyOutput) {
            $json = $json | ForEach-Object { [System.Web.HttpUtility]::JavaScriptStringEncode($_, $true) }
        }
        $json | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Output "Test results exported to $OutputPath"
    }
    
    return $results
}

# Function to get test execution summary
function Get-TestSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ResultsPath
    )
    
    if (-not (Test-Path $ResultsPath)) {
        throw "Results file '$ResultsPath' does not exist"
    }
    
    $results = Get-Content -Path $ResultsPath -Raw | ConvertFrom-Json
    
    return @{
        ExecutionTime = $results.ExecutionTime
        Environment = $results.Environment
        TotalTests = $results.Summary.TotalTests
        PassedTests = $results.Summary.PassedTests
        FailedTests = $results.Summary.FailedTests
        SkippedTests = $results.Summary.SkippedTests
        Categories = $results.Summary.Categories
        Tags = $results.Summary.Tags
    }
}

# Export functions
Export-ModuleMember -Function Invoke-SecurityTests,
                              Get-TestSummary 