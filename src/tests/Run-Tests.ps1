# Test Runner Script
[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$TestNames,
    
    [Parameter()]
    [string[]]$Categories,
    
    [Parameter()]
    [switch]$All,
    
    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\..\..\results",
    
    [Parameter()]
    [switch]$PrettyOutput,
    
    [Parameter()]
    [switch]$DetailedAnalysis,
    
    [Parameter()]
    [string]$BaselinePath,
    
    [Parameter()]
    [switch]$CollectEvidence,
    
    [Parameter()]
    [hashtable]$CustomComparators = @{},
    
    [Parameter()]
    [switch]$Parallel,
    
    [Parameter()]
    [int]$MaxParallelJobs = 5,
    
    [Parameter()]
    [switch]$GenerateReport,
    
    [Parameter()]
    [string]$ReportFormat = "HTML",
    
    [Parameter()]
    [switch]$ContinueOnFailure,
    
    [Parameter()]
    [switch]$VerboseOutput
)

# Set up error handling
$ErrorActionPreference = "Stop"
if ($VerboseOutput) {
    $VerbosePreference = "Continue"
}

# Resolve the output path to be in the root directory
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
Write-Verbose "Using output path: $OutputPath"

# Create output directory if it doesn't exist
if ($OutputPath -and -not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Verbose "Created output directory: $OutputPath"
}

# Import required modules
$modulePath = Join-Path $PSScriptRoot "SecureOpsTests.psm1"
if (-not (Test-Path $modulePath)) {
    throw "Required module not found: $modulePath"
}
Import-Module $modulePath -Force

# Initialize test results container
$script:TestResults = @{
    StartTime = Get-Date
    EndTime = $null
    TotalTests = 0
    PassedTests = 0
    FailedTests = 0
    SkippedTests = 0
    Results = @()
    Categories = @{}
    Summary = @{}
}

# Load test categories
$categoriesPath = Join-Path $PSScriptRoot "TestCategories.json"
if (-not (Test-Path $categoriesPath)) {
    throw "Test categories configuration not found: $categoriesPath"
}
$categoriesConfig = Get-Content $categoriesPath | ConvertFrom-Json

function Get-TestsToRun {
    param(
        [string[]]$TestNames,
        [string[]]$Categories,
        [switch]$All
    )
    
    $testsToRun = @()
    
    if ($All) {
        # Get all test files from the directory
        $testFiles = Get-ChildItem -Path $PSScriptRoot -Filter "Test-*.ps1" | Where-Object { $_.Name -ne "Test-Template.ps1" }
        $testsToRun = $testFiles | ForEach-Object { $_.BaseName }
    }
    elseif ($TestNames) {
        $testsToRun = $TestNames
    }
    elseif ($Categories) {
        foreach ($category in $Categories) {
            if ($categoriesConfig.$category) {
                $testsToRun += $categoriesConfig.$category.tests
            }
            else {
                Write-Warning "Category '$category' not found in configuration"
            }
        }
    }
    
    return $testsToRun | Select-Object -Unique
}

function Invoke-Test {
    param(
        [string]$TestName,
        [hashtable]$Parameters
    )
    
    try {
        Write-Verbose "Running test: $TestName"
        
        # Verify test function exists
        if (-not (Get-Command $TestName -ErrorAction SilentlyContinue)) {
            Write-Warning "Test function not found: $TestName"
            $script:TestResults.SkippedTests++
            return $null
        }
        
        # Execute test
        $result = & $TestName @Parameters
        
        if ($result) {
            $script:TestResults.Results += $result
            $script:TestResults.TotalTests++
            
            if ($result.Status -eq "Pass") {
                $script:TestResults.PassedTests++
            }
            elseif ($result.Status -in @("Error", "Critical")) {
                $script:TestResults.FailedTests++
            }
            
            # Export individual test result
            if ($OutputPath) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $resultPath = Join-Path $OutputPath "${TestName}_${timestamp}.json"
                $result | ConvertTo-Json -Depth 10 | Set-Content $resultPath
                Write-Verbose "Results exported to: $resultPath"
            }
        }
        
        return $result
    }
    catch {
        Write-Error "Error running test $TestName : $_"
        $script:TestResults.FailedTests++
        if (-not $ContinueOnFailure) {
            throw
        }
        return $null
    }
}

function Export-TestReport {
    param(
        [string]$OutputPath,
        [string]$Format = "HTML"
    )
    
    if (-not $OutputPath) {
        Write-Warning "No output path specified for report"
        return
    }
    
    $reportPath = Join-Path $OutputPath "test_report.$($Format.ToLower())"
    
    switch ($Format.ToLower()) {
        "html" {
            $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { margin-bottom: 20px; }
        .test-result { margin-bottom: 10px; padding: 10px; border: 1px solid #ccc; }
        .pass { background-color: #dff0d8; }
        .fail { background-color: #f2dede; }
        .warning { background-color: #fcf8e3; }
        .error { background-color: #f2dede; }
        .critical { background-color: #d9534f; color: white; }
        .info { background-color: #d9edf7; }
    </style>
</head>
<body>
    <h1>Security Test Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Start Time: $($script:TestResults.StartTime)</p>
        <p>End Time: $($script:TestResults.EndTime)</p>
        <p>Total Tests: $($script:TestResults.TotalTests)</p>
        <p>Passed: $($script:TestResults.PassedTests)</p>
        <p>Failed: $($script:TestResults.FailedTests)</p>
        <p>Skipped: $($script:TestResults.SkippedTests)</p>
    </div>
"@
            
            foreach ($result in $script:TestResults.Results) {
                if (-not $result) { continue }
                
                $status = if ($result.Status) { $result.Status.ToLower() } else { "info" }
                $htmlReport += @"
    <div class="test-result $status">
        <h3>$($result.TestName)</h3>
        <p>Status: $($result.Status)</p>
        <p>Risk Level: $($result.RiskLevel)</p>
        <p>Description: $($result.Description)</p>
        <h4>Findings:</h4>
        <ul>
"@
                
                if ($result.Findings) {
                    foreach ($finding in $result.Findings) {
                        $htmlReport += @"
            <li>
                <strong>$($finding.Name)</strong><br>
                Status: $($finding.Status)<br>
                Risk Level: $($finding.RiskLevel)<br>
                Description: $($finding.Description)<br>
                $(if ($finding.Recommendation) { "Recommendation: $($finding.Recommendation)<br>" })
            </li>
"@
                    }
                }
                else {
                    $htmlReport += @"
            <li>No findings reported</li>
"@
                }
                
                $htmlReport += @"
        </ul>
    </div>
"@
            }
            
            $htmlReport += @"
</body>
</html>
"@
            
            $htmlReport | Set-Content $reportPath -Force
            Write-Verbose "Report exported to: $reportPath"
        }
        
        "json" {
            $script:TestResults | ConvertTo-Json -Depth 10 | Set-Content $reportPath -Force
            Write-Verbose "Report exported to: $reportPath"
        }
        
        default {
            Write-Warning "Unsupported report format: $Format"
        }
    }
}

# Main execution
try {
    Write-Verbose "Starting test execution..."
    
    # Get tests to run
    $testsToRun = Get-TestsToRun -TestNames $TestNames -Categories $Categories -All:$All
    
    if (-not $testsToRun) {
        throw "No tests selected for execution"
    }
    
    Write-Verbose "Selected tests: $($testsToRun -join ', ')"
    
    # Prepare test parameters
    $testParams = @{
        OutputPath = $OutputPath
        PrettyOutput = $PrettyOutput
        DetailedAnalysis = $DetailedAnalysis
        BaselinePath = $BaselinePath
        CollectEvidence = $CollectEvidence
    }
    
    # Execute tests
    foreach ($test in $testsToRun) {
        if ($Parallel) {
            # TODO: Implement parallel execution
            Write-Warning "Parallel execution not yet implemented"
        }
        else {
            Invoke-Test -TestName $test -Parameters $testParams
        }
    }
    
    # Update end time
    $script:TestResults.EndTime = Get-Date
    
    # Generate report if requested
    if ($GenerateReport) {
        Export-TestReport -OutputPath $OutputPath -Format $ReportFormat
    }
    
    Write-Verbose "Test execution completed"
}
catch {
    Write-Error "Error during test execution: $_"
    throw
} 