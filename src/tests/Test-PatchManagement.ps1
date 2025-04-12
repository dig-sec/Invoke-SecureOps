# -----------------------------------------------------------------------------
# Patch Management Check
# -----------------------------------------------------------------------------

function Test-PatchManagement {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath = ".\patch_management.json",
        
        [Parameter()]
        [switch]$PrettyOutput
    )

    Write-SectionHeader "Patch Management Check"
    Write-Output "Analyzing Windows Update configuration and patch status..."

    # Initialize test result using helper function
    $testResult = Initialize-JsonOutput -Category "PatchManagement" -RiskLevel "High"
    
    try {
        # Check Windows Update service status
        $wuaService = Get-Service -Name "wuauserv"
        
        # Check Windows Update policy
        $autoUpdatePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        $autoUpdateSettings = Get-ItemProperty -Path $autoUpdatePath -ErrorAction SilentlyContinue
        
        # Check last update time
        $lastUpdate = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
        
        # Add findings based on service status
        if ($wuaService.Status -ne "Running") {
            $testResult = Add-Finding -TestResult $testResult `
                -FindingName "Windows Update Service" `
                -Status "Warning" `
                -Description "Windows Update service is not running" `
                -RiskLevel "High" `
                -AdditionalInfo @{
                    ServiceName = $wuaService.Name
                    Status = $wuaService.Status
                    StartType = $wuaService.StartType
                }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -FindingName "Windows Update Service" `
                -Status "Pass" `
                -Description "Windows Update service is running" `
                -RiskLevel "Info" `
                -AdditionalInfo @{
                    ServiceName = $wuaService.Name
                    Status = $wuaService.Status
                    StartType = $wuaService.StartType
                }
        }

        # Add finding for last update time
        if ($lastUpdate) {
            $daysSinceUpdate = (Get-Date) - $lastUpdate.InstalledOn
            if ($daysSinceUpdate.Days -gt 30) {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Last Update Time" `
                    -Status "Warning" `
                    -Description "System has not been updated in more than 30 days" `
                    -RiskLevel "High" `
                    -AdditionalInfo @{
                        LastUpdate = $lastUpdate.InstalledOn
                        DaysSinceUpdate = $daysSinceUpdate.Days
                        HotFixID = $lastUpdate.HotFixID
                    }
            }
            else {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Last Update Time" `
                    -Status "Pass" `
                    -Description "System updates are current" `
                    -RiskLevel "Info" `
                    -AdditionalInfo @{
                        LastUpdate = $lastUpdate.InstalledOn
                        DaysSinceUpdate = $daysSinceUpdate.Days
                        HotFixID = $lastUpdate.HotFixID
                    }
            }
        }
        else {
            $testResult = Add-Finding -TestResult $testResult `
                -FindingName "Last Update Time" `
                -Status "Warning" `
                -Description "Unable to determine last update time" `
                -RiskLevel "High" `
                -AdditionalInfo @{
                    Error = "No update history found"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Patch Management Check"
        $testResult = Add-Finding -TestResult $testResult `
            -FindingName "Patch Management Error" `
            -Status "Error" `
            -Description "Failed to check patch management: $($_.Exception.Message)" `
            -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-PatchManagement 