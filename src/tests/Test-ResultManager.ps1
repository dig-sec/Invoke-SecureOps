# -----------------------------------------------------------------------------
# Security Test Result Manager
# -----------------------------------------------------------------------------

# Function to initialize test results collection
function Initialize-TestResults {
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
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput
    )
    
    $results = @{
        AssessmentName = $AssessmentName
        Description = $Description
        Version = $Version
        Metadata = $Metadata
        StartTime = Get-Date
        EndTime = $null
        Environment = @{
            ComputerName = $env:COMPUTERNAME
            OSVersion = [System.Environment]::OSVersion.VersionString
            PowerShellVersion = $PSVersionTable.PSVersion
            ExecutionPolicy = Get-ExecutionPolicy
        }
        Tests = @{}
        Summary = @{
            TotalTests = 0
            PassedTests = 0
            FailedTests = 0
            SkippedTests = 0
            Categories = @{}
            Tags = @{}
            RiskLevels = @{
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
                Info = 0
            }
        }
    }
    
    return $results
}

# Function to add test result
function Add-TestResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Results,
        
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [hashtable]$TestResult
    )
    
    # Add test result
    $Results.Tests[$TestName] = $TestResult
    
    # Update summary
    $Results.Summary.TotalTests++
    
    switch ($TestResult.Status) {
        'Pass' { $Results.Summary.PassedTests++ }
        'Fail' { $Results.Summary.FailedTests++ }
        'Skip' { $Results.Summary.SkippedTests++ }
    }
    
    # Update category stats
    if (-not $Results.Summary.Categories.ContainsKey($TestResult.Category)) {
        $Results.Summary.Categories[$TestResult.Category] = @{
            Total = 0
            Passed = 0
            Failed = 0
            Skipped = 0
        }
    }
    $Results.Summary.Categories[$TestResult.Category].Total++
    switch ($TestResult.Status) {
        'Pass' { $Results.Summary.Categories[$TestResult.Category].Passed++ }
        'Fail' { $Results.Summary.Categories[$TestResult.Category].Failed++ }
        'Skip' { $Results.Summary.Categories[$TestResult.Category].Skipped++ }
    }
    
    # Update tag stats
    foreach ($tag in $TestResult.Tags) {
        if (-not $Results.Summary.Tags.ContainsKey($tag)) {
            $Results.Summary.Tags[$tag] = @{
                Total = 0
                Passed = 0
                Failed = 0
                Skipped = 0
            }
        }
        $Results.Summary.Tags[$tag].Total++
        switch ($TestResult.Status) {
            'Pass' { $Results.Summary.Tags[$tag].Passed++ }
            'Fail' { $Results.Summary.Tags[$tag].Failed++ }
            'Skip' { $Results.Summary.Tags[$tag].Skipped++ }
        }
    }
    
    # Update risk level stats
    if ($TestResult.Status -eq 'Fail') {
        $Results.Summary.RiskLevels[$TestResult.RiskLevel]++
    }
}

# Function to finalize test results
function Complete-TestResults {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Results
    )
    
    $Results.EndTime = Get-Date
    $Results.Duration = $Results.EndTime - $Results.StartTime
    
    return $Results
}

# Function to export test results
function Export-TestResults {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Results,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput
    )
    
    $json = $Results | ConvertTo-Json -Depth 10
    if ($PrettyOutput) {
        $json = $json | ForEach-Object { [System.Text.RegularExpressions.Regex]::Replace($_, '^(\s*)"([^"]+)":', '$1"$2":', [System.Text.RegularExpressions.RegexOptions]::Multiline) }
    }
    
    $json | Out-File -FilePath $OutputPath -Encoding UTF8
}

# Function to generate test report
function New-TestReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Results,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet('Text', 'HTML', 'Markdown')]
        [string]$Format = 'Text'
    )
    
    $report = switch ($Format) {
        'Text' {
            @"
Security Test Report
===================
Generated: $(Get-Date)
Duration: $($Results.Duration)

Environment
----------
Computer Name: $($Results.Environment.ComputerName)
OS Version: $($Results.Environment.OSVersion)
PowerShell Version: $($Results.Environment.PowerShellVersion)
Execution Policy: $($Results.Environment.ExecutionPolicy)

Summary
-------
Total Tests: $($Results.Summary.TotalTests)
Passed: $($Results.Summary.PassedTests)
Failed: $($Results.Summary.FailedTests)
Skipped: $($Results.Summary.SkippedTests)

Risk Levels
----------
Critical: $($Results.Summary.RiskLevels.Critical)
High: $($Results.Summary.RiskLevels.High)
Medium: $($Results.Summary.RiskLevels.Medium)
Low: $($Results.Summary.RiskLevels.Low)
Info: $($Results.Summary.RiskLevels.Info)

Categories
----------
"@
            foreach ($category in $Results.Summary.Categories.Keys | Sort-Object) {
                $stats = $Results.Summary.Categories[$category]
                $report += "`n$category`n"
                $report += "Total: $($stats.Total), Passed: $($stats.Passed), Failed: $($stats.Failed), Skipped: $($stats.Skipped)`n"
            }
            
            $report += "`nTest Results`n------------`n"
            foreach ($testName in $Results.Tests.Keys | Sort-Object) {
                $test = $Results.Tests[$testName]
                $report += "`n$testName`n"
                $report += "Category: $($test.Category)`n"
                $report += "Status: $($test.Status)`n"
                $report += "Risk Level: $($test.RiskLevel)`n"
                if ($test.Status -eq 'Fail') {
                    $report += "Findings:`n"
                    foreach ($finding in $test.Findings) {
                        $report += "  - $($finding.Description)`n"
                    }
                }
            }
            
            $report
        }
        
        'HTML' {
            # HTML report template
            @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        .summary { background-color: #f5f5f5; padding: 10px; margin: 10px 0; }
        .test { border: 1px solid #ddd; margin: 10px 0; padding: 10px; }
        .pass { color: green; }
        .fail { color: red; }
        .skip { color: orange; }
    </style>
</head>
<body>
    <h1>Security Test Report</h1>
    <p>Generated: $(Get-Date)</p>
    <p>Duration: $($Results.Duration)</p>
    
    <h2>Environment</h2>
    <div class="summary">
        <p>Computer Name: $($Results.Environment.ComputerName)</p>
        <p>OS Version: $($Results.Environment.OSVersion)</p>
        <p>PowerShell Version: $($Results.Environment.PowerShellVersion)</p>
        <p>Execution Policy: $($Results.Environment.ExecutionPolicy)</p>
    </div>
    
    <h2>Summary</h2>
    <div class="summary">
        <p>Total Tests: $($Results.Summary.TotalTests)</p>
        <p>Passed: $($Results.Summary.PassedTests)</p>
        <p>Failed: $($Results.Summary.FailedTests)</p>
        <p>Skipped: $($Results.Summary.SkippedTests)</p>
    </div>
    
    <h2>Risk Levels</h2>
    <div class="summary">
        <p>Critical: $($Results.Summary.RiskLevels.Critical)</p>
        <p>High: $($Results.Summary.RiskLevels.High)</p>
        <p>Medium: $($Results.Summary.RiskLevels.Medium)</p>
        <p>Low: $($Results.Summary.RiskLevels.Low)</p>
        <p>Info: $($Results.Summary.RiskLevels.Info)</p>
    </div>
    
    <h2>Test Results</h2>
"@
            foreach ($testName in $Results.Tests.Keys | Sort-Object) {
                $test = $Results.Tests[$testName]
                $report += @"
    <div class="test">
        <h3>$testName</h3>
        <p>Category: $($test.Category)</p>
        <p>Status: <span class="$($test.Status.ToLower())">$($test.Status)</span></p>
        <p>Risk Level: $($test.RiskLevel)</p>
"@
                if ($test.Status -eq 'Fail') {
                    $report += "        <h4>Findings:</h4>`n        <ul>`n"
                    foreach ($finding in $test.Findings) {
                        $report += "            <li>$($finding.Description)</li>`n"
                    }
                    $report += "        </ul>`n"
                }
                $report += "    </div>`n"
            }
            
            $report += "</body></html>"
        }
        
        'Markdown' {
            @"
# Security Test Report
Generated: $(Get-Date)
Duration: $($Results.Duration)

## Environment
- Computer Name: $($Results.Environment.ComputerName)
- OS Version: $($Results.Environment.OSVersion)
- PowerShell Version: $($Results.Environment.PowerShellVersion)
- Execution Policy: $($Results.Environment.ExecutionPolicy)

## Summary
- Total Tests: $($Results.Summary.TotalTests)
- Passed: $($Results.Summary.PassedTests)
- Failed: $($Results.Summary.FailedTests)
- Skipped: $($Results.Summary.SkippedTests)

## Risk Levels
- Critical: $($Results.Summary.RiskLevels.Critical)
- High: $($Results.Summary.RiskLevels.High)
- Medium: $($Results.Summary.RiskLevels.Medium)
- Low: $($Results.Summary.RiskLevels.Low)
- Info: $($Results.Summary.RiskLevels.Info)

## Test Results
"@
            foreach ($testName in $Results.Tests.Keys | Sort-Object) {
                $test = $Results.Tests[$testName]
                $report += @"

### $testName
- Category: $($test.Category)
- Status: $($test.Status)
- Risk Level: $($test.RiskLevel)
"@
                if ($test.Status -eq 'Fail') {
                    $report += "`n#### Findings:`n"
                    foreach ($finding in $test.Findings) {
                        $report += "- $($finding.Description)`n"
                    }
                }
            }
            
            $report
        }
    }
    
    if ($OutputPath) {
        $report | Out-File -FilePath $OutputPath -Encoding UTF8
    }
    
    return $report
}

# Export functions
Export-ModuleMember -Function Initialize-TestResults,
                              Add-TestResult,
                              Complete-TestResults,
                              Export-TestResults,
                              New-TestReport 