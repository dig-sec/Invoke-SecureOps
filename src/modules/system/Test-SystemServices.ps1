# -----------------------------------------------------------------------------
# System Services Analysis Module
# -----------------------------------------------------------------------------

function Test-SystemServices {
    param (
        [string]$OutputPath = ".\service_analysis.json"
    )

    Write-SectionHeader "System Services Analysis"
    Write-Output "Analyzing system services..."

    # Initialize JSON output object using common function
    $servicesInfo = Initialize-JsonOutput -Category "ServiceAnalysis" -RiskLevel "Medium" -ActionLevel "Review"
    $servicesInfo.TotalServices = 0
    $servicesInfo.RunningServices = 0
    $servicesInfo.StoppedServices = 0
    $servicesInfo.AutomaticServices = 0
    $servicesInfo.ManualServices = 0
    $servicesInfo.DisabledServices = 0

    # Get all services
    $services = Get-Service
    $servicesInfo.TotalServices = $services.Count
    $servicesInfo.RunningServices = ($services | Where-Object {$_.Status -eq 'Running'}).Count
    $servicesInfo.StoppedServices = ($services | Where-Object {$_.Status -eq 'Stopped'}).Count

    # Get service startup types
    $serviceConfigs = Get-WmiObject -Class Win32_Service | Select-Object Name, StartMode, State
    $servicesInfo.AutomaticServices = ($serviceConfigs | Where-Object {$_.StartMode -eq 'Auto'}).Count
    $servicesInfo.ManualServices = ($serviceConfigs | Where-Object {$_.StartMode -eq 'Manual'}).Count
    $servicesInfo.DisabledServices = ($serviceConfigs | Where-Object {$_.StartMode -eq 'Disabled'}).Count

    # Define potentially dangerous services
    $dangerousServices = @(
        @{
            Name = "RemoteRegistry"
            Description = "Allows remote registry modification"
            RiskLevel = "High"
        },
        @{
            Name = "Telnet"
            Description = "Unencrypted remote access"
            RiskLevel = "High"
        },
        @{
            Name = "TlntSvr"
            Description = "Telnet server"
            RiskLevel = "High"
        },
        @{
            Name = "FTPSVC"
            Description = "FTP server"
            RiskLevel = "High"
        },
        @{
            Name = "MSFTPSVC"
            Description = "Microsoft FTP server"
            RiskLevel = "High"
        },
        @{
            Name = "W3SVC"
            Description = "IIS web server"
            RiskLevel = "Medium"
        },
        @{
            Name = "IISADMIN"
            Description = "IIS admin service"
            RiskLevel = "Medium"
        },
        @{
            Name = "SNMP"
            Description = "Simple Network Management Protocol"
            RiskLevel = "Medium"
        },
        @{
            Name = "SNMPTRAP"
            Description = "SNMP trap service"
            RiskLevel = "Medium"
        }
    )

    # Check for dangerous services
    $servicesInfo.DangerousServices = @()
    foreach ($dangerousService in $dangerousServices) {
        $service = Get-Service -Name $dangerousService.Name -ErrorAction SilentlyContinue
        if ($service) {
            $serviceInfo = @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                Description = $dangerousService.Description
                RiskLevel = $dangerousService.RiskLevel
            }
            $servicesInfo.DangerousServices += $serviceInfo

            # Add finding for dangerous service
            $status = if ($service.Status -eq 'Running') { "Fail" } else { "Warning" }
            Add-Finding -CheckName "Dangerous Service: $($service.DisplayName)" -Status $status -Details "$($dangerousService.Description) - Service is $($service.Status)" -Category "Services"
        }
    }

    # Export results to JSON
    Export-ToJson -Data $servicesInfo -FilePath $OutputPath -Pretty

    # Add summary findings
    Add-Finding -CheckName "Service Analysis" -Status "Info" -Details "Analyzed $($servicesInfo.TotalServices) services" -Category "Services"
    
    if ($servicesInfo.DangerousServices.Count -gt 0) {
        $runningDangerousServices = $servicesInfo.DangerousServices | Where-Object { $_.Status -eq 'Running' }
        if ($runningDangerousServices.Count -gt 0) {
            Add-Finding -CheckName "Running Dangerous Services" -Status "Fail" -Details "Found $($runningDangerousServices.Count) running dangerous services" -Category "Services"
        }
    }
    else {
        Add-Finding -CheckName "Dangerous Services" -Status "Pass" -Details "No dangerous services found" -Category "Services"
    }

    return $servicesInfo
}

# Export the function
Export-ModuleMember -Function Test-SystemServices 