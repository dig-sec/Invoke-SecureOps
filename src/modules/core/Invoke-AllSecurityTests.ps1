# -----------------------------------------------------------------------------
# Run All Security Tests Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Runs all security tests sequentially and stops on the first error.

.DESCRIPTION
    This function executes all security tests in sequence and stops when it encounters
    the first error. This is useful for troubleshooting issues with individual tests.

.PARAMETER OutputDirectory
    The directory where test results will be saved. Defaults to ".\results".

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis in each test.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.OUTPUTS
    [hashtable] A hashtable containing the results of all tests and any errors encountered.

.EXAMPLE
    Invoke-AllSecurityTests -OutputDirectory ".\results" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Invoke-AllSecurityTests {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputDirectory = ".\results",
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$DetailedAnalysis,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [string]$BaselinePath
    )

    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    }

    # Initialize results array
    $results = @()
    $testFunctions = @(
        'Test-Dependencies',
        'Test-SuspiciousConnections',
        'Test-SuspiciousFiles',
        'Test-SuspiciousRegistry',
        'Test-UACStatus',
        'Test-WindowsServices'
    )

    foreach ($testFunction in $testFunctions) {
        Write-Host "`nRunning $testFunction..." -ForegroundColor Cyan
        
        try {
            # Build parameters hashtable
            $params = @{
                OutputPath = Join-Path -Path $OutputDirectory -ChildPath "$($testFunction.ToLower()).json"
                PrettyOutput = $PrettyOutput
            }
            
            if ($DetailedAnalysis) {
                $params['DetailedAnalysis'] = $true
            }
            
            if ($CollectEvidence) {
                $params['CollectEvidence'] = $true
            }
            
            if ($BaselinePath) {
                $params['BaselinePath'] = $BaselinePath
            }
            
            # Invoke the test function
            $result = & $testFunction @params
            
            # Check if the test had any errors
            $hasError = $result.Findings | Where-Object { $_.Status -eq "Error" }
            
            if ($hasError) {
                Write-Host "Error in $testFunction. Stopping test execution." -ForegroundColor Red
                $results += @{
                    TestFunction = $testFunction
                    Status = "Error"
                    Result = $result
                }
                break
            }
            
            $results += @{
                TestFunction = $testFunction
                Status = "Success"
                Result = $result
            }
            
            Write-Host "Completed $testFunction successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Error executing $testFunction : $_" -ForegroundColor Red
            $results += @{
                TestFunction = $testFunction
                Status = "Error"
                Error = $_.Exception.Message
            }
            break
        }
    }

    return @{
        Results = $results
        TotalTests = $testFunctions.Count
        CompletedTests = ($results | Where-Object { $_.Status -eq "Success" }).Count
        FailedTests = ($results | Where-Object { $_.Status -eq "Error" }).Count
    }
} 