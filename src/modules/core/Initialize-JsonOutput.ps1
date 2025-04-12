# -----------------------------------------------------------------------------
# JSON Output Initialization Module
# -----------------------------------------------------------------------------

function Initialize-JsonOutput {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Category,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$RiskLevel,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Info', 'Review', 'Action', 'Critical')]
        [string]$ActionLevel,
        
        [string]$Description = "",
        
        [hashtable]$AdditionalInfo = @{}
    )

    # Create base output object
    $output = @{
        Category = $Category
        RiskLevel = $RiskLevel
        ActionLevel = $ActionLevel
        Description = $Description
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        AdditionalInfo = $AdditionalInfo
    }

    return $output
}

# Export the function
Export-ModuleMember -Function Initialize-JsonOutput 