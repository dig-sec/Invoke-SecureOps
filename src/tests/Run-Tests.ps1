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
$VerbosePreference = if ($VerboseOutput) { "Continue" } else { "SilentlyContinue" }

# Import the SecureOps module
Import-Module "$PSScriptRoot\..\modules\SecureOps.psd1" -Force

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Get all test functions from the module
$testFunctions = Get-Command -Module SecureOps -CommandType Function | Where-Object { $_.Name -like 'Test-*' }

# Filter tests based on parameters
if ($TestNames) {
    $testFunctions = $testFunctions | Where-Object { $_.Name -in $TestNames }
}
elseif ($Categories) {
    # TODO: Implement category filtering
    Write-Warning "Category filtering not yet implemented"
    return
}
elseif (-not $All) {
    Write-Warning "No test selection criteria provided. Use -All to run all tests."
    return
}

# Run tests
$results = @()
foreach ($test in $testFunctions) {
    Write-Verbose "Running test: $($test.Name)"
    try {
        $parameters = @{}
        
        # Only add parameters that the function accepts
        if ($test.Parameters.ContainsKey('OutputPath')) { $parameters['OutputPath'] = $OutputPath }
        if ($test.Parameters.ContainsKey('PrettyOutput')) { $parameters['PrettyOutput'] = $PrettyOutput }
        if ($test.Parameters.ContainsKey('DetailedAnalysis')) { $parameters['DetailedAnalysis'] = $DetailedAnalysis }
        if ($test.Parameters.ContainsKey('BaselinePath')) { $parameters['BaselinePath'] = $BaselinePath }
        if ($test.Parameters.ContainsKey('CollectEvidence')) { $parameters['CollectEvidence'] = $CollectEvidence }
        if ($test.Parameters.ContainsKey('CustomComparators')) { $parameters['CustomComparators'] = $CustomComparators }
        
        # Invoke the test function with only the parameters it accepts
        $result = & $test.Name @parameters
        
        if ($result) {
            $results += $result
            
            # Export individual test results
            if ($OutputPath) {
                $outputFile = Join-Path $OutputPath "$($test.Name)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                Export-TestResult -TestResult $result -OutputPath $outputFile -PrettyOutput:$PrettyOutput
                Write-Verbose "Results exported to: $outputFile"
            }
        }
    }
    catch {
        Write-Warning "Error running test $($test.Name): $_"
        if (-not $ContinueOnFailure) {
            throw
        }
    }
}

# Generate report if requested
if ($GenerateReport -and $results) {
    $reportPath = Join-Path $OutputPath "security_assessment_report.$($ReportFormat.ToLower())"
    Export-TestResults -TestResults $results -OutputPath $reportPath -Format $ReportFormat
    Write-Verbose "Report generated: $reportPath"
}

return $results 