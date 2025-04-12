# -----------------------------------------------------------------------------
# Test Execution Module
# -----------------------------------------------------------------------------

function Invoke-AllSecurityTests {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Categories = @(),
        
        [Parameter()]
        [switch]$RunAll,
        
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
        [switch]$AutoFix,
        
        [Parameter()]
        [switch]$WhatIf
    )
    
    # Initialize test result
    $testResult = Initialize-TestResult -TestName "Security Assessment" `
                                      -Category "Security" `
                                      -Description "Comprehensive security assessment" `
                                      -RiskLevel "Info"
    
    try {
        Write-Log -Message "Starting security assessment" -Level 'Info'
        
        # Check dependencies first
        $dependencies = Test-Dependencies -RequiredModules @(
            "Microsoft.PowerShell.Security",
            "Microsoft.PowerShell.Management",
            "Microsoft.PowerShell.Utility"
        ) -RequiredCommands @(
            "Get-Service",
            "Get-Process",
            "Get-NetTCPConnection"
        ) -RequiredServices @(
            "wuauserv",
            "MpsSvc"
        )
        
        if ($dependencies.Status -eq "Error") {
            Write-Log -Message "Dependency check failed. Aborting assessment." -Level 'Error'
            return $dependencies
        }
        
        # Get all test functions
        $testFunctions = Get-ChildItem -Path "$PSScriptRoot\..\tests" -Filter "Test-*.ps1" |
            ForEach-Object { $_.BaseName }
        
        # Filter by category if specified
        if (-not $RunAll -and $Categories.Count -gt 0) {
            $testFunctions = $testFunctions | Where-Object {
                $testCategory = (Get-Command $_ -ErrorAction SilentlyContinue).Parameters.Category.DefaultValue
                $Categories -contains $testCategory
            }
        }
        
        # Create results directory if it doesn't exist
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Run each test
        $results = @()
        foreach ($test in $testFunctions) {
            Write-Log -Message "Running test: $test" -Level 'Info'
            
            try {
                $result = & $test -OutputPath $OutputPath `
                                -PrettyOutput:$PrettyOutput `
                                -DetailedAnalysis:$DetailedAnalysis `
                                -BaselinePath $BaselinePath `
                                -CollectEvidence:$CollectEvidence `
                                -CustomComparators $CustomComparators
                
                $results += $result
                
                # Update overall status
                switch ($result.Status) {
                    "Critical" { 
                        $testResult.Status = "Critical"
                        $testResult.RiskLevel = "Critical"
                    }
                    "Error" {
                        if ($testResult.Status -ne "Critical") {
                            $testResult.Status = "Error"
                            $testResult.RiskLevel = "High"
                        }
                    }
                    "Warning" {
                        if ($testResult.Status -notin @("Critical", "Error")) {
                            $testResult.Status = "Warning"
                            $testResult.RiskLevel = "Medium"
                        }
                    }
                }
                
                # Add findings
                if ($result.Findings) {
                    $testResult.Findings += $result.Findings
                }
                
                # Add evidence
                if ($result.Evidence) {
                    $testResult.Evidence += $result.Evidence
                }
            }
            catch {
                Write-Log -Message "Error running test $test`: $_" -Level 'Error'
                Add-Finding -TestResult $testResult `
                    -FindingName "Test Error: $test" `
                    -Status "Error" `
                    -RiskLevel "High" `
                    -Description "Error running test: $_" `
                    -TechnicalDetails @{
                        TestName = $test
                        ErrorMessage = $_.Exception.Message
                        ErrorType = $_.Exception.GetType().FullName
                        StackTrace = $_.ScriptStackTrace
                    }
            }
        }
        
        # Auto-fix if requested
        if ($AutoFix) {
            Write-Log -Message "Attempting to fix identified issues" -Level 'Info'
            
            foreach ($finding in $testResult.Findings) {
                if ($finding.Status -in @("Critical", "Error", "Warning")) {
                    try {
                        # Add auto-fix logic here
                        Write-Log -Message "Auto-fixing issue: $($finding.Name)" -Level 'Info'
                    }
                    catch {
                        Write-Log -Message "Error auto-fixing issue $($finding.Name)`: $_" -Level 'Error'
                    }
                }
            }
        }
        
        # Export results
        if ($OutputPath) {
            Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $testResult
    }
    catch {
        Write-Log -Message "Error during security assessment: $_" -Level 'Error'
        Add-Finding -TestResult $testResult `
            -FindingName "Assessment Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error during security assessment: $_" `
            -TechnicalDetails @{
                ErrorMessage = $_.Exception.Message
                ErrorType = $_.Exception.GetType().FullName
                StackTrace = $_.ScriptStackTrace
            }
        return $testResult
    }
}

# Export the function
Export-ModuleMember -Function Invoke-AllSecurityTests 