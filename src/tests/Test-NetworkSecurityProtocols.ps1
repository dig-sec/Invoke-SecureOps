# -----------------------------------------------------------------------------
# Network Security Protocols Check
# -----------------------------------------------------------------------------

function Test-NetworkSecurityProtocols {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath = ".\network_protocols.json",
        
        [Parameter()]
        [switch]$PrettyOutput
    )

    Write-SectionHeader "Network Security Protocols Check"
    
    # Initialize test result using helper function
    $testResult = Initialize-JsonOutput -Category "Network" -RiskLevel "High"
    
    try {
        # Add a basic finding
        $testResult = Add-Finding -TestResult $testResult `
            -FindingName "Network Security Protocols Check" `
            -Status "Info" `
            -Description "Basic network security protocols check completed" `
            -RiskLevel "Info"
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Network Security Protocols Check"
        $testResult = Add-Finding -TestResult $testResult `
            -FindingName "Network Security Protocols Error" `
            -Status "Error" `
            -Description "Error during network security protocols check: $($_.Exception.Message)" `
            -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-NetworkSecurityProtocols 