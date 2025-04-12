# -----------------------------------------------------------------------------
# SecureOps Tests Module
# -----------------------------------------------------------------------------

# Helper functions for test modules
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
    }
}

function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory, ParameterSetName = "Name")]
        [string]$Name,
        
        [Parameter(Mandatory, ParameterSetName = "FindingName")]
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
        [hashtable]$CustomData = @{},
        
        [Parameter()]
        [hashtable]$AdditionalInfo = @{},
        
        [Parameter()]
        [string]$CheckName = ""
    )
    
    $findingName = if ($PSCmdlet.ParameterSetName -eq "Name") { $Name } else { $FindingName }
    
    # Merge AdditionalInfo into TechnicalDetails if provided
    if ($AdditionalInfo.Count -gt 0) {
        $TechnicalDetails = $AdditionalInfo
    }
    
    # Use CheckName as part of finding name if provided
    if ($CheckName) {
        $findingName = "$CheckName - $findingName"
    }
    
    $finding = @{
        Name = $findingName
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
        }
        "Error" {
            if ($TestResult.Status -ne "Critical") {
                $TestResult.Status = "Error"
                $TestResult.RiskLevel = "High"
            }
        }
        "Warning" {
            if ($TestResult.Status -notin @("Critical", "Error")) {
                $TestResult.Status = "Warning"
                $TestResult.RiskLevel = "Medium"
            }
        }
        "Pass" {
            if ($TestResult.Status -notin @("Critical", "Error", "Warning")) {
                $TestResult.Status = "Pass"
                $TestResult.RiskLevel = "Info"
            }
        }
    }
    
    return $TestResult
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
    
    $TestResult.EndTime = Get-Date
    
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
                Write-Warning "Unsupported format: $Format"
                return
            }
        }
        
        Write-Output "Results exported to: $outputFile"
    }
    
    return $TestResult
}

# Import helper functions first
$helperPath = Join-Path -Path $PSScriptRoot -ChildPath "..\modules\core\Helpers.ps1"
if (Test-Path $helperPath) {
    . $helperPath
} else {
    # Try alternate path
    $helperPath = Join-Path -Path $PSScriptRoot -ChildPath "Helpers.ps1"
    if (Test-Path $helperPath) {
        . $helperPath
    } else {
        Write-Warning "Could not find Helpers.ps1 in any expected location"
    }
}

# Import all test modules
$testPath = $PSScriptRoot
$testModules = @()
Get-ChildItem -Path $testPath -Filter "Test-*.ps1" | ForEach-Object {
    try {
        . $_.FullName
        $testModules += $_.BaseName
        Write-Verbose "Loaded test module: $($_.Name)"
    } catch {
        Write-Warning "Failed to load test module $($_.Name): $_"
    }
}

# Export helper functions first
Export-ModuleMember -Function Initialize-TestResult, Add-Finding, Add-Evidence, Export-TestResult

# Export test modules that were successfully loaded
$testModules | ForEach-Object {
    if (Get-Command $_ -ErrorAction SilentlyContinue) {
        Export-ModuleMember -Function $_
        Write-Verbose "Exported test module: $_"
    }
} 