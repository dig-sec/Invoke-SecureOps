# -----------------------------------------------------------------------------
# Patch Management Analysis Module
# -----------------------------------------------------------------------------

function Test-PatchManagement {
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

    Write-SectionHeader "Patch Management Check"
    Write-Output "Analyzing patch management status..."

    # Initialize test result using helper function
    $testResult = Initialize-TestResult -TestName "Test-PatchManagement" -Category "System" -Description "Windows patch management check" -RiskLevel "High"
    
    try {
        # Get Windows Update service status
        $wuaService = Get-Service -Name "wuauserv" -ErrorAction Stop
        
        if ($wuaService.Status -ne "Running") {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Windows Update Service" `
                -Status "Warning" `
                -Description "Windows Update service is not running" `
                -RiskLevel "High" `
                -TechnicalDetails @{
                    ServiceName = $wuaService.Name
                    Status = $wuaService.Status
                    StartType = $wuaService.StartType
                }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Windows Update Service" `
                -Status "Pass" `
                -Description "Windows Update service is running" `
                -RiskLevel "Info" `
                -TechnicalDetails @{
                    ServiceName = $wuaService.Name
                    Status = $wuaService.Status
                    StartType = $wuaService.StartType
                }
        }

        # Get update history
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $history = $searcher.GetTotalHistoryCount()
        $recentUpdates = $searcher.QueryHistory(0, $history)
        
        $lastUpdate = $recentUpdates | Where-Object { $_.Operation -eq 1 } | Sort-Object Date -Descending | Select-Object -First 1
        
        if ($lastUpdate) {
            $daysSinceLastUpdate = ((Get-Date) - $lastUpdate.Date).Days
            
            if ($daysSinceLastUpdate -gt 30) {
                $testResult = Add-Finding -TestResult $testResult `
                    -Name "Update History" `
                    -Status "Warning" `
                    -Description "No updates have been installed in the last 30 days" `
                    -RiskLevel "High" `
                    -TechnicalDetails @{
                        LastUpdateDate = $lastUpdate.Date
                        DaysSinceLastUpdate = $daysSinceLastUpdate
                        LastUpdateTitle = $lastUpdate.Title
                    }
            }
            else {
                $testResult = Add-Finding -TestResult $testResult `
                    -Name "Update History" `
                    -Status "Pass" `
                    -Description "System has been updated within the last 30 days" `
                    -RiskLevel "Info" `
                    -TechnicalDetails @{
                        LastUpdateDate = $lastUpdate.Date
                        DaysSinceLastUpdate = $daysSinceLastUpdate
                        LastUpdateTitle = $lastUpdate.Title
                    }
            }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -Name "Update History" `
                -Status "Warning" `
                -Description "No update history found" `
                -RiskLevel "High" `
                -TechnicalDetails @{
                    HistoryCount = $history
                    LastUpdateDate = "Unknown"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Patch Management Analysis"
        $testResult = Add-Finding -TestResult $testResult `
            -Name "Patch Management Error" `
            -Status "Error" `
            -Description "Failed to check patch management status: $($_.Exception.Message)" `
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
Export-ModuleMember -Function Test-PatchManagement 