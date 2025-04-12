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
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
    )
    
    Write-SectionHeader "Windows Defender Status Analysis"
    Write-Output "Analyzing Windows Defender status..."

    # Initialize test result
    $testResult = Initialize-TestResult -TestName "Test-DefenderStatus" `
                                      -Category "Security" `
                                      -Description "Analyzes Windows Defender antivirus protection status"
    
    try {
        # Get Windows Defender status
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        # Collect baseline data if provided
        $baselineData = $null
        if ($BaselinePath -and (Test-Path $BaselinePath)) {
            $baselineData = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
        }
        
        # Check antivirus protection
        if (-not $defenderStatus.AntivirusEnabled) {
            Add-Finding -TestResult $testResult `
                       -FindingName "Antivirus Protection Status" `
                       -Status "Warning" `
                       -Description "Windows Defender antivirus protection is not enabled" `
                       -RiskLevel "High" `
                       -AdditionalInfo @{
                           Status = $defenderStatus.AntivirusEnabled
                           LastUpdate = $defenderStatus.AntivirusSignatureAge
                           Recommendation = "Enable Windows Defender antivirus protection"
                       }
        }
        else {
            Add-Finding -TestResult $testResult `
                       -FindingName "Antivirus Protection Status" `
                       -Status "Pass" `
                       -Description "Windows Defender antivirus protection is enabled" `
                       -RiskLevel "Info" `
                       -AdditionalInfo @{
                           Status = $defenderStatus.AntivirusEnabled
                           LastUpdate = $defenderStatus.AntivirusSignatureAge
                       }
        }
        
        # Check real-time protection
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            Add-Finding -TestResult $testResult `
                       -FindingName "Real-time Protection Status" `
                       -Status "Warning" `
                       -Description "Windows Defender real-time protection is not enabled" `
                       -RiskLevel "High" `
                       -AdditionalInfo @{
                           Status = $defenderStatus.RealTimeProtectionEnabled
                           LastUpdate = $defenderStatus.AntivirusSignatureAge
                           Recommendation = "Enable Windows Defender real-time protection"
                       }
        }
        else {
            Add-Finding -TestResult $testResult `
                       -FindingName "Real-time Protection Status" `
                       -Status "Pass" `
                       -Description "Windows Defender real-time protection is enabled" `
                       -RiskLevel "Info" `
                       -AdditionalInfo @{
                           Status = $defenderStatus.RealTimeProtectionEnabled
                           LastUpdate = $defenderStatus.AntivirusSignatureAge
                       }
        }
        
        # Check signature age
        $currentDate = Get-Date
        try {
            $signatureAge = $defenderStatus.AntivirusSignatureAge
            
            if ($signatureAge -gt 7) {
                Add-Finding -TestResult $testResult `
                           -FindingName "Signature Age Status" `
                           -Status "Warning" `
                           -Description "Windows Defender antivirus signatures are $signatureAge days old" `
                           -RiskLevel "Medium" `
                           -AdditionalInfo @{
                               SignatureAge = $signatureAge
                               LastUpdate = $defenderStatus.AntivirusSignatureLastUpdated
                               Recommendation = "Update Windows Defender virus definitions"
                           }
            }
            else {
                Add-Finding -TestResult $testResult `
                           -FindingName "Signature Age Status" `
                           -Status "Pass" `
                           -Description "Windows Defender antivirus signatures are up to date" `
                           -RiskLevel "Info" `
                           -AdditionalInfo @{
                               SignatureAge = $signatureAge
                               LastUpdate = $defenderStatus.AntivirusSignatureLastUpdated
                           }
            }
        }
        catch {
            Add-Finding -TestResult $testResult `
                       -FindingName "Signature Age Check" `
                       -Status "Warning" `
                       -Description "Could not determine signature age: $($_.Exception.Message)" `
                       -RiskLevel "Medium" `
                       -AdditionalInfo @{
                           LastUpdate = $defenderStatus.AntivirusSignatureLastUpdated
                           Error = $_.Exception.Message
                           Recommendation = "Verify Windows Defender is functioning correctly"
                       }
        }
        
        # Compare with baseline if available
        if ($baselineData) {
            $comparison = Compare-BaselineData -BaselineData $baselineData `
                                             -CurrentData $defenderStatus `
                                             -CustomComparators $CustomComparators
            
            if ($comparison.Changes.Count -gt 0) {
                Add-Finding -TestResult $testResult `
                           -FindingName "Configuration Changes" `
                           -Status "Warning" `
                           -Description "Changes detected in Windows Defender configuration compared to baseline" `
                           -RiskLevel "Medium" `
                           -AdditionalInfo @{
                               Changes = $comparison.Changes
                               Recommendation = "Review configuration changes and update baseline if approved"
                           }
            }
            else {
                Add-Finding -TestResult $testResult `
                           -FindingName "Configuration Changes" `
                           -Status "Pass" `
                           -Description "No changes detected in Windows Defender configuration" `
                           -RiskLevel "Info" `
                           -AdditionalInfo @{
                               BaselineComparison = "Matches baseline configuration"
                           }
            }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Windows Defender Status Analysis"
        Add-Finding -TestResult $testResult `
                   -FindingName "Analysis Error" `
                   -Status "Error" `
                   -Description "Failed to analyze Windows Defender status: $($_.Exception.Message)" `
                   -RiskLevel "High" `
                   -AdditionalInfo $errorInfo
    }
    
    # Export results if output path provided
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
    }
    
    return $testResult
}

# Export function
Export-ModuleMember -Function Test-DefenderStatus 