function Write-SectionHeader {
    param(
        [string]$Title,
        [string]$Subtitle = ""
    )
    
    Write-Host "`n# -----------------------------------------------------------------------------"
    Write-Host "# $Title"
    if ($Subtitle) {
        Write-Host "# $Subtitle"
    }
    Write-Host "# -----------------------------------------------------------------------------`n"
}

function Initialize-JsonOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $false)]
        [string]$RiskLevel = "Medium",
        
        [Parameter(Mandatory = $false)]
        [string]$ActionLevel = "Review"
    )

    return @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        RiskLevel = $RiskLevel
        ActionLevel = $ActionLevel
        Findings = @()
        Status = "Pass"
        Details = ""
    }
}

function Add-Finding {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory = $true)]
        [string]$FindingName,
        
        [Parameter(Mandatory = $true)]
        [string]$Status,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [string]$RiskLevel = "Medium",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AdditionalInfo = @{}
    )

    $finding = @{
        Name = $FindingName
        Status = $Status
        Description = $Description
        RiskLevel = $RiskLevel
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AdditionalInfo = $AdditionalInfo
    }

    $TestResult.Findings += $finding
    
    # Update overall test status based on finding
    if ($Status -eq "Fail" -or $Status -eq "Critical") {
        $TestResult.Status = "Fail"
    } elseif ($Status -eq "Warning" -and $TestResult.Status -ne "Fail") {
        $TestResult.Status = "Warning"
    }

    return $TestResult
}

function Write-ErrorInfo {
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    return @{
        Context = $Context
        ErrorMessage = $ErrorRecord.Exception.Message
        ErrorType = $ErrorRecord.Exception.GetType().Name
        ScriptStackTrace = $ErrorRecord.ScriptStackTrace
        ErrorCategory = $ErrorRecord.CategoryInfo.Category
        ErrorDetails = $ErrorRecord.ErrorDetails
        TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# Export all functions
Export-ModuleMember -Function Write-SectionHeader, Initialize-JsonOutput, Add-Finding, Write-ErrorInfo 