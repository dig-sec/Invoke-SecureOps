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
        [switch]$Verbose,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $testResult = Initialize-TestResult -TestName "Windows Defender Status" `
                                      -Category "Security" `
                                      -Description "Analyzes the status of Windows Defender antivirus protection" `
                                      -Tags @("Defender", "Antivirus", "Security") `
                                      -ComplianceReferences @(
                                          @{
                                              Framework = "CIS"
                                              Reference = "CIS 8.1"
                                              Description = "Ensure Windows Defender antivirus is enabled and up to date"
                                          }
                                      )
    
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
            $finding = Add-TestFinding -TestResult $testResult `
                                     -Title "Antivirus Protection Disabled" `
                                     -Description "Windows Defender antivirus protection is not enabled" `
                                     -Severity "High" `
                                     -Recommendation "Enable Windows Defender antivirus protection" `
                                     -Tags @("Defender", "Antivirus") `
                                     -ComplianceReferences @(
                                         @{
                                             Framework = "CIS"
                                             Reference = "CIS 8.1.1"
                                             Description = "Ensure Windows Defender antivirus is enabled"
                                         }
                                     ) `
                                     -MitigationStrategies @(
                                         @{
                                             Strategy = "Enable Windows Defender"
                                             Command = "Set-MpPreference -DisableRealtimeMonitoring $false"
                                             Description = "Enables real-time protection in Windows Defender"
                                         }
                                     )
            
            if ($CollectEvidence) {
                Add-Evidence -Finding $finding `
                            -Type "Configuration" `
                            -Data $defenderStatus `
                            -Description "Current Windows Defender configuration"
            }
        }
        
        # Check real-time protection
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            $finding = Add-TestFinding -TestResult $testResult `
                                     -Title "Real-time Protection Disabled" `
                                     -Description "Windows Defender real-time protection is not enabled" `
                                     -Severity "High" `
                                     -Recommendation "Enable Windows Defender real-time protection" `
                                     -Tags @("Defender", "RealTime") `
                                     -ComplianceReferences @(
                                         @{
                                             Framework = "CIS"
                                             Reference = "CIS 8.1.2"
                                             Description = "Ensure Windows Defender real-time protection is enabled"
                                         }
                                     ) `
                                     -MitigationStrategies @(
                                         @{
                                             Strategy = "Enable Real-time Protection"
                                             Command = "Set-MpPreference -DisableRealtimeMonitoring $false"
                                             Description = "Enables real-time protection in Windows Defender"
                                         }
                                     )
            
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
            $finding = Add-TestFinding -TestResult $testResult `
                                     -Title "Outdated Antivirus Signatures" `
                                     -Description "Windows Defender antivirus signatures are $($signatureAge.Days) days old" `
                                     -Severity "Medium" `
                                     -Recommendation "Update Windows Defender antivirus signatures" `
                                     -Tags @("Defender", "Signatures") `
                                     -ComplianceReferences @(
                                         @{
                                             Framework = "CIS"
                                             Reference = "CIS 8.1.3"
                                             Description = "Ensure Windows Defender antivirus signatures are up to date"
                                         }
                                     ) `
                                     -MitigationStrategies @(
                                         @{
                                             Strategy = "Update Signatures"
                                             Command = "Update-MpSignature"
                                             Description = "Updates Windows Defender antivirus signatures"
                                         }
                                     )
            
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
        
        $finding = Add-TestFinding -TestResult $testResult `
                                 -Title "Analysis Error" `
                                 -Description "Error analyzing Windows Defender status: $($_.Exception.Message)" `
                                 -Severity "High" `
                                 -Recommendation "Review error details and ensure proper permissions" `
                                 -Tags @("Defender", "Error")
        
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