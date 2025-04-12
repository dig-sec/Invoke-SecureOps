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
    
    # Initialize test result
    $testResult = Initialize-JsonOutput -Category "Security" -RiskLevel "High"
    
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
            $finding = Add-Finding -TestResult $testResult `
                                 -FindingName "Antivirus Protection Disabled" `
                                 -Status "Warning" `
                                 -Description "Windows Defender antivirus protection is not enabled" `
                                 -RiskLevel "High" `
                                 -AdditionalInfo @{
                                     Status = $defenderStatus.AntivirusEnabled
                                     LastUpdate = $defenderStatus.AntivirusSignatureAge
                                 }
            
            if ($CollectEvidence) {
                Add-Evidence -Finding $finding `
                            -Type "Configuration" `
                            -Data $defenderStatus `
                            -Description "Current Windows Defender configuration"
            }
        }
        
        # Check real-time protection
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            $finding = Add-Finding -TestResult $testResult `
                                 -FindingName "Real-time Protection Disabled" `
                                 -Status "Warning" `
                                 -Description "Windows Defender real-time protection is not enabled" `
                                 -RiskLevel "High" `
                                 -AdditionalInfo @{
                                     Status = $defenderStatus.RealTimeProtectionEnabled
                                     LastUpdate = $defenderStatus.AntivirusSignatureAge
                                 }
            
            if ($CollectEvidence) {
                Add-Evidence -Finding $finding `
                            -Type "Configuration" `
                            -Data $defenderStatus `
                            -Description "Current Windows Defender configuration"
            }
        }
        
        # Check signature age
        $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureAge
        if ($signatureAge.Days -gt 7) {
            $finding = Add-Finding -TestResult $testResult `
                                 -FindingName "Outdated Antivirus Signatures" `
                                 -Status "Warning" `
                                 -Description "Windows Defender antivirus signatures are $($signatureAge.Days) days old" `
                                 -RiskLevel "Medium" `
                                 -AdditionalInfo @{
                                     SignatureAge = $signatureAge.Days
                                     LastUpdate = $defenderStatus.AntivirusSignatureAge
                                 }
            
            if ($CollectEvidence) {
                Add-Evidence -Finding $finding `
                            -Type "Configuration" `
                            -Data @{
                                SignatureAge = $signatureAge.Days
                                LastUpdate = $defenderStatus.AntivirusSignatureAge
                            } `
                            -Description "Windows Defender signature age information"
            }
        }
        
        # Compare with baseline if available
        if ($baselineData) {
            $comparison = Compare-BaselineData -BaselineData $baselineData `
                                            -CurrentData $defenderStatus `
                                            -CustomComparators $CustomComparators
            
            if ($comparison.Changes.Count -gt 0) {
                $finding = Add-TestFinding -TestResult $testResult `
                                         -Title "Configuration Changes Detected" `
                                         -Description "Changes detected in Windows Defender configuration compared to baseline" `
                                         -Severity "Medium" `
                                         -Recommendation "Review changes and ensure they are authorized" `
                                         -Tags @("Defender", "Baseline") `
                                         -TechnicalDetails $comparison
                
                if ($CollectEvidence) {
                    Add-Evidence -Finding $finding `
                                -Type "BaselineComparison" `
                                -Data $comparison `
                                -Description "Changes detected compared to baseline"
                }
            }
        }
        
        # Export results if output path provided
        if ($OutputPath) {
            Export-TestResult -TestResult $testResult `
                            -OutputPath $OutputPath `
                            -PrettyOutput:$PrettyOutput
        }
        
        return $testResult
    }
    catch {
        Write-Error "Error analyzing Windows Defender status: $_"
        
        $finding = Add-Finding -TestResult $testResult `
                             -FindingName "Analysis Error" `
                             -Status "Error" `
                             -Description "Error analyzing Windows Defender status: $($_.Exception.Message)" `
                             -RiskLevel "High" `
                             -AdditionalInfo @{
                                 Error = $_.Exception.Message
                                 StackTrace = $_.ScriptStackTrace
                             }
        
        if ($OutputPath) {
            Export-TestResult -TestResult $testResult `
                            -OutputPath $OutputPath `
                            -PrettyOutput:$PrettyOutput
        }
        
        return $testResult
    }
}

# Export function
Export-ModuleMember -Function Test-DefenderStatus 