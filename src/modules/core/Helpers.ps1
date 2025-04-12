# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Write-SectionHeader {
    param(
        [string]$Title
    )
    Write-Output "`n=== $Title ===`n"
}

function Initialize-JsonOutput {
    param(
        [string]$Category = "General",
        [string]$RiskLevel = "Info",
        [string]$ActionLevel = "Review"
    )
    
    return @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        RiskLevel = $RiskLevel
        ActionLevel = $ActionLevel
        Status = "Pass"
        Description = ""
        Findings = @()
        Details = @{}
        Evidence = @()
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory=$true)]
        [string]$FindingName,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Pass", "Warning", "Critical", "Error")]
        [string]$Status,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Info", "Low", "Medium", "High", "Critical")]
        [string]$RiskLevel,
        
        [Parameter()]
        [hashtable]$AdditionalInfo = @{}
    )
    
    $finding = @{
        Name = $FindingName
        Description = $Description
        Status = $Status
        RiskLevel = $RiskLevel
        AdditionalInfo = $AdditionalInfo
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $TestResult.Findings += $finding
    
    # Update overall test status based on finding status
    switch ($Status) {
        "Critical" { 
            $TestResult.Status = "Critical"
            $TestResult.RiskLevel = "Critical"
        }
        "Warning" {
            if ($TestResult.Status -ne "Critical") {
                $TestResult.Status = "Warning"
                if ($TestResult.RiskLevel -notin @("Critical", "High")) {
                    $TestResult.RiskLevel = "Medium"
                }
            }
        }
        "Error" {
            if ($TestResult.Status -notin @("Critical", "Warning")) {
                $TestResult.Status = "Error"
                if ($TestResult.RiskLevel -notin @("Critical", "High", "Medium")) {
                    $TestResult.RiskLevel = "High"
                }
            }
        }
    }
}

function Write-ErrorInfo {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Context = "Unknown"
    )
    
    return @{
        Context = $Context
        ErrorMessage = $ErrorRecord.Exception.Message
        ErrorType = $ErrorRecord.Exception.GetType().Name
        ScriptStackTrace = $ErrorRecord.ScriptStackTrace
        ErrorCategory = $ErrorRecord.CategoryInfo.Category
        ErrorDetails = $ErrorRecord.ErrorDetails
    }
}

function Add-Evidence {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory=$true)]
        [string]$FindingName,
        
        [Parameter(Mandatory=$true)]
        [string]$EvidenceType,
        
        [Parameter(Mandatory=$true)]
        [object]$EvidenceData,
        
        [Parameter(Mandatory=$true)]
        [string]$Description
    )
    
    if (-not $TestResult.Evidence) {
        $TestResult.Evidence = @()
    }
    
    $evidence = @{
        FindingName = $FindingName
        Type = $EvidenceType
        Data = $EvidenceData
        Description = $Description
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $TestResult.Evidence += $evidence
}

function Export-TestResult {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput
    )
    
    # Create directory if it doesn't exist
    $directory = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    
    # Convert to JSON
    if ($PrettyOutput) {
        $json = $TestResult | ConvertTo-Json -Depth 10
    } else {
        $json = $TestResult | ConvertTo-Json -Depth 10 -Compress
    }
    
    # Write to file
    $json | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Output "Test result exported to $OutputPath"
}

# Only export if we're in a module context
if ($MyInvocation.ScriptName -ne '') {
    Export-ModuleMember -Function Write-SectionHeader, Initialize-JsonOutput, Add-Finding, Write-ErrorInfo, Add-Evidence, Export-TestResult
} 