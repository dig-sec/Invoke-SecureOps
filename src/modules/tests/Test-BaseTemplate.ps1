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
        Metadata = $Metadata
        Findings = @()
        ExecutionTime = Get-Date
    }
    
    return $result
}

# Function to add a finding to test result
function Add-Finding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$TestResult,
        
        [Parameter(Mandatory)]
        [string]$FindingName,
        
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Error', 'Skip')]
        [string]$Status,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$RiskLevel = 'Medium',
        
        [Parameter()]
        [hashtable]$AdditionalInfo = @{}
    )
    
    $finding = @{
        Name = $FindingName
        Status = $Status
        Description = $Description
        RiskLevel = $RiskLevel
        AdditionalInfo = $AdditionalInfo
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $TestResult.Findings) {
        $TestResult.Findings = @()
    }
    
    $TestResult.Findings += $finding
    
    # Update overall test status based on finding
    switch ($Status) {
        'Error' { 
            $TestResult.Status = 'Error'
            $TestResult.RiskLevel = 'High'
        }
        'Fail' {
            if ($TestResult.Status -ne 'Error') {
                $TestResult.Status = 'Fail'
                if ($RiskLevel -eq 'Critical' -or $RiskLevel -eq 'High') {
                    $TestResult.RiskLevel = $RiskLevel
                }
            }
        }
        'Warning' {
            if ($TestResult.Status -notin @('Error', 'Fail')) {
                $TestResult.Status = 'Warning'
                if ($RiskLevel -eq 'Critical' -or $RiskLevel -eq 'High') {
                    $TestResult.RiskLevel = $RiskLevel
                }
            }
        }
        'Info' {
            if ($TestResult.Status -notin @('Error', 'Fail', 'Warning')) {
                $TestResult.Status = 'Info'
            }
        }
        'Pass' {
            if ($TestResult.Status -notin @('Error', 'Fail', 'Warning', 'Info')) {
                $TestResult.Status = 'Pass'
            }
        }
    }
    
    return $finding
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
    
    if ($PrettyOutput) {
        $json = $exportData | ConvertTo-Json -Depth 10 -Compress:$false
    }
    else {
        $json = $exportData | ConvertTo-Json -Depth 10 -Compress
    }
    
    if ($OutputPath) {
        $json | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
        Write-Output "Test result exported to $OutputPath"
    }
    
    return $json
}

# Export functions
Export-ModuleMember -Function Initialize-TestResult,
                              Add-Finding,
                              Compare-BaselineData,
                              Add-Evidence,
                              Export-TestResult 