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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory)]
        [string]$FindingName,
        
        [Parameter()]
        [string]$Status = "Info",
        
        [Parameter()]
        [string]$RiskLevel = "Info",
        
        [Parameter()]
        [string]$Description = "",
        
        [Parameter()]
        [string]$Recommendation = "",
        
        [Parameter()]
        [string]$ComplianceReference = "",
        
        [Parameter()]
        [string]$MitigationStrategy = "",
        
        [Parameter()]
        [hashtable]$TechnicalDetails = @{},
        
        [Parameter()]
        [hashtable]$CustomData = @{}
    )
    
    try {
        Write-Log -Message "Adding finding: $FindingName (Status: $Status, Risk: $RiskLevel)" -Level 'Debug'
        
        $finding = @{
            Name = $FindingName
            Status = $Status
            RiskLevel = $RiskLevel
            Description = $Description
            Recommendation = $Recommendation
            ComplianceReference = $ComplianceReference
            MitigationStrategy = $MitigationStrategy
            TechnicalDetails = $TechnicalDetails
            CustomData = $CustomData
            Timestamp = Get-Date
        }
        
        $TestResult.Findings += $finding
        
        # Update overall test status based on finding
        switch ($Status) {
            "Critical" { 
                $TestResult.Status = "Critical"
                $TestResult.RiskLevel = "Critical"
                Write-Log -Message "Test status updated to Critical due to finding: $FindingName" -Level 'Warning'
            }
            "Error" {
                if ($TestResult.Status -ne "Critical") {
                    $TestResult.Status = "Error"
                    $TestResult.RiskLevel = "High"
                    Write-Log -Message "Test status updated to Error due to finding: $FindingName" -Level 'Warning'
                }
            }
            "Warning" {
                if ($TestResult.Status -notin @("Critical", "Error")) {
                    $TestResult.Status = "Warning"
                    $TestResult.RiskLevel = "Medium"
                    Write-Log -Message "Test status updated to Warning due to finding: $FindingName" -Level 'Info'
                }
            }
            "Pass" {
                if ($TestResult.Status -notin @("Critical", "Error", "Warning")) {
                    $TestResult.Status = "Pass"
                    $TestResult.RiskLevel = "Info"
                    Write-Log -Message "Test status updated to Pass due to finding: $FindingName" -Level 'Info'
                }
            }
        }
        
        return $TestResult
    }
    catch {
        Write-Log -Message "Error adding finding: $_" -Level 'Error'
        throw
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory)]
        [string]$FindingName,
        
        [Parameter()]
        [string]$EvidenceType = "Configuration",
        
        [Parameter()]
        [object]$EvidenceData,
        
        [Parameter()]
        [string]$Description = "",
        
        [Parameter()]
        [hashtable]$Metadata = @{}
    )
    
    try {
        Write-Log -Message "Adding evidence for finding: $FindingName" -Level 'Debug'
        
        $evidence = @{
            FindingName = $FindingName
            EvidenceType = $EvidenceType
            EvidenceData = $EvidenceData
            Description = $Description
            Metadata = $Metadata
            Timestamp = Get-Date
        }
        
        $TestResult.Evidence += $evidence
        return $TestResult
    }
    catch {
        Write-Log -Message "Error adding evidence: $_" -Level 'Error'
        throw
    }
}

function Export-TestResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$TestResult,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [string]$Format = "JSON"
    )
    
    try {
        Write-Log -Message "Exporting test results for $($TestResult.TestName)" -Level 'Debug'
        
        $TestResult.EndTime = Get-Date
        $TestResult.Duration = ($TestResult.EndTime - $TestResult.StartTime).TotalMinutes
        
        if ($OutputPath) {
            $outputFile = Join-Path $OutputPath "$($TestResult.TestName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').$($Format.ToLower())"
            
            switch ($Format.ToLower()) {
                "json" {
                    $jsonParams = @{
                        Depth = 10
                    }
                    if ($PrettyOutput) {
                        $jsonParams["Compress"] = $false
                    }
                    $TestResult | ConvertTo-Json @jsonParams | Out-File -FilePath $outputFile
                }
                "xml" {
                    $TestResult | ConvertTo-Xml -NoTypeInformation | Out-File -FilePath $outputFile
                }
                default {
                    Write-Log -Message "Unsupported format: $Format" -Level 'Warning'
                    return
                }
            }
            
            Write-Log -Message "Results exported to: $outputFile" -Level 'Info'
        }
        
        return $TestResult
    }
    catch {
        Write-Log -Message "Error exporting test results: $_" -Level 'Error'
        throw
    }
}

# Initialize logging
$script:LogPath = Join-Path $PSScriptRoot "logs"
if (-not (Test-Path $script:LogPath)) {
    New-Item -ItemType Directory -Path $script:LogPath -Force | Out-Null
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $logFile = Join-Path $script:LogPath "secureops_$(Get-Date -Format 'yyyyMMdd').log"
    
    Add-Content -Path $logFile -Value $logMessage
    
    switch ($Level) {
        'Error' { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        'Debug' { Write-Debug $Message }
        default { Write-Verbose $Message }
    }
}

function Initialize-TestResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [string]$Category,
        
        [Parameter()]
        [string]$Description = "",
        
        [Parameter()]
        [string]$Status = "Info",
        
        [Parameter()]
        [string]$RiskLevel = "Info",
        
        [Parameter()]
        [string]$Recommendation = "",
        
        [Parameter()]
        [string[]]$Tags = @(),
        
        [Parameter()]
        [string]$ComplianceReference = "",
        
        [Parameter()]
        [string]$MitigationStrategy = "",
        
        [Parameter()]
        [string[]]$Dependencies = @(),
        
        [Parameter()]
        [hashtable]$CustomData = @{}
    )
    
    Write-Log -Message "Initializing test result for $TestName" -Level 'Debug'
    
    return @{
        TestName = $TestName
        Category = $Category
        Description = $Description
        Status = $Status
        RiskLevel = $RiskLevel
        Recommendation = $Recommendation
        Tags = $Tags
        ComplianceReference = $ComplianceReference
        MitigationStrategy = $MitigationStrategy
        Dependencies = $Dependencies
        CustomData = $CustomData
        Findings = @()
        Evidence = @()
        StartTime = Get-Date
        EndTime = $null
        Metadata = @{
            PowerShellVersion = $PSVersionTable.PSVersion
            OSVersion = [System.Environment]::OSVersion.Version
            ExecutionPolicy = Get-ExecutionPolicy
            UserContext = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
    }
}

# Only export if we're in a module context
if ($MyInvocation.ScriptName -ne '') {
    Export-ModuleMember -Function Write-SectionHeader, Initialize-JsonOutput, Add-Finding, Write-ErrorInfo, Add-Evidence, Export-TestResult
} 