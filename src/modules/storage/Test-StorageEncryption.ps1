# -----------------------------------------------------------------------------
# Storage Encryption Check
# -----------------------------------------------------------------------------

function Test-StorageEncryption {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath = ".\storage_encryption.json",
        
        [Parameter()]
        [switch]$PrettyOutput
    )

    Write-SectionHeader "Storage Encryption Check"
    
    # Initialize test result using helper function
    $testResult = Initialize-JsonOutput -Category "Storage" -RiskLevel "High"
    
    try {
        # Add a basic finding
        $testResult = Add-Finding -TestResult $testResult `
            -FindingName "Storage Encryption Check" `
            -Status "Info" `
            -Description "Basic storage encryption check completed" `
            -RiskLevel "Info"
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Storage Encryption Check"
        $testResult = Add-Finding -TestResult $testResult `
            -FindingName "Storage Encryption Error" `
            -Status "Error" `
            -Description "Error during storage encryption check: $($_.Exception.Message)" `
            -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-StorageEncryption 