# -----------------------------------------------------------------------------
# Time Configuration Analysis Module
# -----------------------------------------------------------------------------

function Test-TimeConfiguration {
    param (
        [string]$OutputPath = ".\time_configuration.json"
    )

    Write-SectionHeader "Time Configuration Check"
    Write-Output "Analyzing system time configuration..."

    # Initialize JSON output object using common function
    $timeInfo = Initialize-JsonOutput -Category "TimeConfiguration" -RiskLevel "Medium" -ActionLevel "Review"

    try {
        # Get time service status
        $timeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        
        # Get time zone information
        $timeZone = Get-TimeZone
        
        # Get NTP server configuration
        $ntpServer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue
        
        $timeInfo.TimeServiceStatus = $timeService.Status
        $timeInfo.TimeZone = $timeZone.DisplayName
        $timeInfo.NTPServer = $ntpServer.NtpServer

        # Add findings based on time configuration
        if ($timeService.Status -ne "Running") {
            Add-Finding -CheckName "Time Service" -Status "Warning" `
                -Details "Windows Time service is not running" -Category "TimeConfiguration" `
                -AdditionalInfo @{
                    ServiceName = "W32Time"
                    CurrentStatus = $timeService.Status
                }
        }
        else {
            Add-Finding -CheckName "Time Service" -Status "Pass" `
                -Details "Windows Time service is running" -Category "TimeConfiguration" `
                -AdditionalInfo @{
                    ServiceName = "W32Time"
                    CurrentStatus = $timeService.Status
                }
        }
        
        if (-not $ntpServer.NTPServer) {
            Add-Finding -CheckName "NTP Configuration" -Status "Warning" `
                -Details "No NTP server configured" -Category "TimeConfiguration" `
                -AdditionalInfo @{
                    TimeZone = $timeZone.DisplayName
                }
        }
        else {
            Add-Finding -CheckName "NTP Configuration" -Status "Pass" `
                -Details "NTP server configured: $($ntpServer.NTPServer)" -Category "TimeConfiguration" `
                -AdditionalInfo @{
                    NTPServer = $ntpServer.NTPServer
                    TimeZone = $timeZone.DisplayName
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Time Configuration Analysis"
        Add-Finding -CheckName "Time Configuration" -Status "Fail" `
            -Details "Failed to check time configuration: $($_.Exception.Message)" -Category "TimeConfiguration" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $timeInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $timeInfo
}

# Export the function
Export-ModuleMember -Function Test-TimeConfiguration 