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
    [string]$OutputPath = ".\results",
    
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

# Import required modules
Import-Module "$PSScriptRoot\SecureOpsTests.psm1" -Force

# Initialize test results container
$global:TestResults = @{
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
$categoriesConfig = Get-Content "$PSScriptRoot\TestCategories.json" | ConvertFrom-Json

function Get-TestsToRun {
    param(
        [string[]]$TestNames,
        [string[]]$Categories,
        [switch]$All
    )
    
    $testsToRun = @()
    
    if ($All) {
        $categoriesConfig.PSObject.Properties | ForEach-Object {
            $testsToRun += $_.Value.tests
        }
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
        $result = & $TestName @Parameters
        
        $global:TestResults.Results += $result
        $global:TestResults.TotalTests++
        
        if ($result.Status -eq "Pass") {
            $global:TestResults.PassedTests++
        }
        else {
            $global:TestResults.FailedTests++
        }
        
        return $result
    }
    catch {
        Write-Error "Error running test $TestName : $_"
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
        <p>Start Time: $($global:TestResults.StartTime)</p>
        <p>End Time: $($global:TestResults.EndTime)</p>
        <p>Total Tests: $($global:TestResults.TotalTests)</p>
        <p>Passed: $($global:TestResults.PassedTests)</p>
        <p>Failed: $($global:TestResults.FailedTests)</p>
        <p>Skipped: $($global:TestResults.SkippedTests)</p>
    </div>
"@
            
            foreach ($result in $global:TestResults.Results) {
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
            
            $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
        }
        "json" {
            $global:TestResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath
        }
        default {
            Write-Warning "Unsupported report format: $Format"
        }
    }
    
    Write-Output "Report exported to: $reportPath"
}

# Main execution
try {
    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath | Out-Null
    }
    
    # Get tests to run
    $testsToRun = Get-TestsToRun -TestNames $TestNames -Categories $Categories -All:$All
    
    # Prepare test parameters
    $testParams = @{
        OutputPath = $OutputPath
        PrettyOutput = $PrettyOutput
        DetailedAnalysis = $DetailedAnalysis
        CollectEvidence = $CollectEvidence
        CustomComparators = $CustomComparators
    }
    
    if ($BaselinePath) {
        $testParams["BaselinePath"] = $BaselinePath
    }
    
    # Run tests
    if ($Parallel) {
        $jobs = @()
        foreach ($test in $testsToRun) {
            $jobs += Start-Job -ScriptBlock {
                param($TestName, $Params)
                Import-Module "$using:PSScriptRoot\SecureOpsTests.psm1" -Force
                & $TestName @Params
            } -ArgumentList $test, $testParams
            
            # Limit concurrent jobs
            while ((Get-Job -State Running).Count -ge $MaxParallelJobs) {
                Start-Sleep -Seconds 1
            }
        }
        
        # Wait for all jobs to complete
        $jobs | Wait-Job | Receive-Job
    }
    else {
        foreach ($test in $testsToRun) {
            Invoke-Test -TestName $test -Parameters $testParams
        }
    }
    
    # Set end time
    $global:TestResults.EndTime = Get-Date
    
    # Generate report if requested
    if ($GenerateReport) {
        Export-TestReport -OutputPath $OutputPath -Format $ReportFormat
    }
    
    # Output summary
    Write-Output "`nTest Execution Summary:"
    Write-Output "Total Tests: $($global:TestResults.TotalTests)"
    Write-Output "Passed: $($global:TestResults.PassedTests)"
    Write-Output "Failed: $($global:TestResults.FailedTests)"
    Write-Output "Skipped: $($global:TestResults.SkippedTests)"
    Write-Output "Duration: $($global:TestResults.EndTime - $global:TestResults.StartTime)"
}
catch {
    Write-Error "Error during test execution: $_"
    throw
} 