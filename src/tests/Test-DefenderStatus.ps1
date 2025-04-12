# -----------------------------------------------------------------------------
# Windows Defender Status Analysis Module
# -----------------------------------------------------------------------------

function Test-DefenderStatus {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence
    )

    Write-SectionHeader "Windows Defender Status Check"
    Write-Output "Analyzing Windows Defender status..."

    # Initialize test result using helper function
    $testResult = Initialize-TestResult -TestName "Test-DefenderStatus" -Category "Defender" -Description "Windows Defender status check" -RiskLevel "High"
    
    try {
        # Get Windows Defender status
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        # Check if real-time protection is enabled
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Real-Time Protection" `
                -Status "Warning" `
                -Description "Real-time protection is disabled" `
                -RiskLevel "High" `
                -TechnicalDetails @{
                    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                    RealTimeProtectionState = $defenderStatus.RealTimeProtectionState
                }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Real-Time Protection" `
                -Status "Pass" `
                -Description "Real-time protection is enabled" `
                -RiskLevel "Info" `
                -TechnicalDetails @{
                    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                    RealTimeProtectionState = $defenderStatus.RealTimeProtectionState
                }
        }

        # Check antivirus signature status
        $signatureAge = $defenderStatus.AntivirusSignatureAge
        if ($signatureAge -gt 7) {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Antivirus Signatures" `
                -Status "Warning" `
                -Description "Antivirus signatures are more than 7 days old" `
                -RiskLevel "High" `
                -TechnicalDetails @{
                    SignatureAge = $signatureAge
                    SignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                    SignatureVersion = $defenderStatus.AntivirusSignatureVersion
                }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Antivirus Signatures" `
                -Status "Pass" `
                -Description "Antivirus signatures are up to date" `
                -RiskLevel "Info" `
                -TechnicalDetails @{
                    SignatureAge = $signatureAge
                    SignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                    SignatureVersion = $defenderStatus.AntivirusSignatureVersion
                }
        }

        # Check quick scan status
        $lastQuickScan = $defenderStatus.QuickScanEndTime
        if ($lastQuickScan -lt (Get-Date).AddDays(-7)) {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Quick Scan Status" `
                -Status "Warning" `
                -Description "No quick scan has been performed in the last 7 days" `
                -RiskLevel "Medium" `
                -TechnicalDetails @{
                    LastQuickScan = $lastQuickScan
                    QuickScanAge = ((Get-Date) - $lastQuickScan).Days
                }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Quick Scan Status" `
                -Status "Pass" `
                -Description "Quick scan has been performed recently" `
                -RiskLevel "Info" `
                -TechnicalDetails @{
                    LastQuickScan = $lastQuickScan
                    QuickScanAge = ((Get-Date) - $lastQuickScan).Days
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Windows Defender Status Analysis"
        $testResult = Add-Finding -TestResult $testResult `
            -Name "Defender Status Error" `
            -Status "Error" `
            -Description "Failed to check Windows Defender status: $($_.Exception.Message)" `
            -RiskLevel "High" `
            -TechnicalDetails $errorInfo
    }

    # Export results if output path provided
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-DefenderStatus 