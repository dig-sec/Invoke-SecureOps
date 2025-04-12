# -----------------------------------------------------------------------------
# Standard Test Function Template
# -----------------------------------------------------------------------------

function Test-StandardTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\standard_template.json",
        
        [Parameter(Mandatory = $false)]
        [switch]$Pretty,
        
        [Parameter(Mandatory = $false)]
        [switch]$Verbose
    )
    
    # Initialize results object
    $results = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $env:COMPUTERNAME
        TestName = "Test-StandardTemplate"
        Category = "Standard"
        RiskLevel = "Medium"
        ActionLevel = "Review"
        Status = "Unknown"
        Findings = @()
        StartTime = Get-Date
        EndTime = $null
        Duration = 0
        Error = $null
    }
    
    # Helper function for adding findings
    function Add-TestFinding {
        param (
            [Parameter(Mandatory = $true)]
            [string]$CheckName,
            
            [Parameter(Mandatory = $true)]
            [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Error')]
            [string]$Status,
            
            [Parameter(Mandatory = $false)]
            [string]$Details,
            
            [Parameter(Mandatory = $false)]
            [string]$Category = "Standard",
            
            [Parameter(Mandatory = $false)]
            [object]$AdditionalInfo
        )
        
        $finding = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            CheckName = $CheckName
            Status = $Status
            Details = $Details
            Category = $Category
            AdditionalInfo = $AdditionalInfo
        }
        
        $results.Findings += $finding
        
        # Output finding with color coding
        switch ($Status) {
            'Pass' { Write-Host "[PASS] $CheckName" -ForegroundColor Green }
            'Fail' { Write-Host "[FAIL] $CheckName" -ForegroundColor Red }
            'Warning' { Write-Host "[WARN] $CheckName" -ForegroundColor Yellow }
            'Info' { Write-Host "[INFO] $CheckName" -ForegroundColor Cyan }
            'Error' { Write-Host "[ERROR] $CheckName" -ForegroundColor Magenta }
        }
        
        if ($Details) {
            Write-Host "  $Details" -ForegroundColor Gray
        }
    }
    
    # Helper function for writing section headers
    function Write-TestSectionHeader {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Title
        )
        
        Write-Output "`n============================================="
        Write-Output " $Title"
        Write-Output "=============================================`n"
    }
    
    # Helper function for exporting results
    function Export-TestResults {
        param (
            [string]$FilePath,
            [switch]$Pretty
        )
        
        if ($Pretty) {
            $results | ConvertTo-Json -Depth 10 | Out-File $FilePath
        }
        else {
            $results | ConvertTo-Json -Compress | Out-File $FilePath
        }
    }
    
    # Main test execution
    try {
        Write-TestSectionHeader "Standard Template Test"
        
        # Example test checks
        Add-TestFinding -CheckName "Example Check 1" -Status "Pass" -Details "This is a passing check"
        Add-TestFinding -CheckName "Example Check 2" -Status "Warning" -Details "This is a warning check"
        
        # Determine overall status based on findings
        $hasError = $results.Findings | Where-Object { $_.Status -eq "Error" }
        $hasFail = $results.Findings | Where-Object { $_.Status -eq "Fail" }
        $hasWarning = $results.Findings | Where-Object { $_.Status -eq "Warning" }
        
        if ($hasError) {
            $results.Status = "Error"
        }
        elseif ($hasFail) {
            $results.Status = "Fail"
        }
        elseif ($hasWarning) {
            $results.Status = "Warning"
        }
        else {
            $results.Status = "Pass"
        }
    }
    catch {
        $results.Status = "Error"
        $results.Error = $_.Exception.Message
        
        Add-TestFinding -CheckName "Test Execution" -Status "Error" -Details "Failed to execute test: $($_.Exception.Message)"
    }
    finally {
        # Calculate duration
        $results.EndTime = Get-Date
        $results.Duration = ($results.EndTime - $results.StartTime).TotalSeconds
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResults -FilePath $OutputPath -Pretty:$Pretty
            if ($Verbose) {
                Write-Output "Results exported to: $OutputPath"
            }
        }
    }
    
    # Return results object
    return $results
}

# Export the function
Export-ModuleMember -Function Test-StandardTemplate 