# -----------------------------------------------------------------------------
# Security Test Base Template
# -----------------------------------------------------------------------------

# Function to initialize a test result
function Initialize-TestResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [string]$Category,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [Parameter()]
        [ValidateSet('Pass', 'Fail', 'Skip')]
        [string]$Status = 'Pass',
        
        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$RiskLevel = 'Medium',
        
        [Parameter()]
        [string[]]$Tags = @(),
        
        [Parameter()]
        [string[]]$ComplianceReferences = @(),
        
        [Parameter()]
        [string[]]$Recommendations = @(),
        
        [Parameter()]
        [hashtable]$BaselineData = @{},
        
        [Parameter()]
        [hashtable]$CurrentData = @{},
        
        [Parameter()]
        [hashtable]$Findings = @{},
        
        [Parameter()]
        [hashtable]$Metadata = @{}
    )
    
    $result = @{
        TestName = $TestName
        Category = $Category
        Description = $Description
        Status = $Status
        RiskLevel = $RiskLevel
        Tags = $Tags
        ComplianceReferences = $ComplianceReferences
        Recommendations = $Recommendations
        BaselineData = $BaselineData
        CurrentData = $CurrentData
        Findings = $Findings
        Metadata = $Metadata
        ExecutionTime = Get-Date
    }
    
    return $result
}

# Function to add a finding to a test result
function Add-TestFinding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory)]
        [string]$Title,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity = 'Medium',
        
        [Parameter()]
        [string[]]$Tags = @(),
        
        [Parameter()]
        [string[]]$ComplianceReferences = @(),
        
        [Parameter()]
        [string[]]$Recommendations = @(),
        
        [Parameter()]
        [hashtable]$TechnicalDetails = @{},
        
        [Parameter()]
        [hashtable]$Evidence = @{}
    )
    
    $finding = @{
        Title = $Title
        Description = $Description
        Severity = $Severity
        Tags = $Tags
        ComplianceReferences = $ComplianceReferences
        Recommendations = $Recommendations
        TechnicalDetails = $TechnicalDetails
        Evidence = $Evidence
        Timestamp = Get-Date
    }
    
    $TestResult.Findings[$Title] = $finding
    
    # Update test result status based on finding severity
    if ($Severity -eq 'Critical' -or $Severity -eq 'High') {
        $TestResult.Status = 'Fail'
        $TestResult.RiskLevel = $Severity
    }
    elseif ($TestResult.Status -ne 'Fail' -and $Severity -eq 'Medium') {
        $TestResult.Status = 'Fail'
        $TestResult.RiskLevel = 'Medium'
    }
    
    return $TestResult
}

# Function to compare baseline and current data
function Compare-BaselineData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$BaselineData,
        
        [Parameter(Mandatory)]
        [hashtable]$CurrentData,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{},
        
        [Parameter()]
        [double]$NumericTolerance = 0.0
    )
    
    $changes = @{
        Added = @{}
        Removed = @{}
        Modified = @{}
        Unchanged = @{}
    }
    
    # Check for added and modified items
    foreach ($key in $CurrentData.Keys) {
        if (-not $BaselineData.ContainsKey($key)) {
            $changes.Added[$key] = $CurrentData[$key]
        }
        else {
            $baselineValue = $BaselineData[$key]
            $currentValue = $CurrentData[$key]
            
            # Use custom comparator if provided
            if ($CustomComparators.ContainsKey($key)) {
                $isEqual = & $CustomComparators[$key] $baselineValue $currentValue
            }
            # Handle numeric comparisons with tolerance
            elseif ($baselineValue -is [double] -and $currentValue -is [double]) {
                $isEqual = [Math]::Abs($baselineValue - $currentValue) -le $NumericTolerance
            }
            # Default comparison
            else {
                $isEqual = $baselineValue -eq $currentValue
            }
            
            if ($isEqual) {
                $changes.Unchanged[$key] = $currentValue
            }
            else {
                $changes.Modified[$key] = @{
                    Baseline = $baselineValue
                    Current = $currentValue
                }
            }
        }
    }
    
    # Check for removed items
    foreach ($key in $BaselineData.Keys) {
        if (-not $CurrentData.ContainsKey($key)) {
            $changes.Removed[$key] = $BaselineData[$key]
        }
    }
    
    return $changes
}

# Function to add evidence to a finding
function Add-Evidence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Finding,
        
        [Parameter(Mandatory)]
        [string]$Type,
        
        [Parameter(Mandatory)]
        [object]$Data,
        
        [Parameter()]
        [string]$Description,
        
        [Parameter()]
        [hashtable]$Metadata = @{}
    )
    
    $evidence = @{
        Type = $Type
        Data = $Data
        Description = $Description
        Metadata = $Metadata
        Timestamp = Get-Date
    }
    
    if (-not $Finding.Evidence.ContainsKey($Type)) {
        $Finding.Evidence[$Type] = @()
    }
    
    $Finding.Evidence[$Type] += $evidence
    
    return $Finding
}

# Function to export test result
function Export-TestResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$TestResult,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$ExcludeMetadata
    )
    
    $exportData = $TestResult.Clone()
    
    if ($ExcludeMetadata) {
        $exportData.Remove('Metadata')
    }
    
    $json = $exportData | ConvertTo-Json -Depth 10
    if ($PrettyOutput) {
        $json = $json | ForEach-Object { [System.Web.HttpUtility]::JavaScriptStringEncode($_, $true) }
    }
    
    if ($OutputPath) {
        $json | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Output "Test result exported to $OutputPath"
    }
    
    return $json
}

# Export functions
Export-ModuleMember -Function Initialize-TestResult,
                              Add-TestFinding,
                              Compare-BaselineData,
                              Add-Evidence,
                              Export-TestResult 