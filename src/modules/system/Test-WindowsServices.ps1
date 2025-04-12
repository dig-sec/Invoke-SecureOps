# -----------------------------------------------------------------------------
# Windows Services Analysis Module
# -----------------------------------------------------------------------------

function Test-WindowsServices {
    param (
        [string]$OutputPath = ".\windows_services.json"
    )

    Write-SectionHeader "Windows Services Check"
    Write-Output "Analyzing Windows services configuration..."

    # Initialize JSON output object using common function
    $servicesInfo = Initialize-JsonOutput -Category "WindowsServices" -RiskLevel "Medium" -ActionLevel "Review"

    try {
        # Get all services
        $allServices = Get-Service
        
        # Get service details with additional properties
        $serviceDetails = Get-WmiObject -Class Win32_Service | 
            Select-Object DisplayName, Name, StartMode, State, PathName, Description, 
            @{Name="LogOnAccount";Expression={$_.StartName}}
        
        # Define critical security services to check
        $criticalServices = @(
            @{Name="WinDefend"; DisplayName="Windows Defender"; Description="Provides real-time protection against malware"},
            @{Name="MpsSvc"; DisplayName="Windows Firewall"; Description="Provides network security through firewall rules"},
            @{Name="wuauserv"; DisplayName="Windows Update"; Description="Downloads and installs Windows updates"},
            @{Name="EventLog"; DisplayName="Windows Event Log"; Description="Logs system events for security auditing"},
            @{Name="SecurityHealthService"; DisplayName="Windows Security Health Service"; Description="Monitors system security health"},
            @{Name="DiagTrack"; DisplayName="Connected User Experiences and Telemetry"; Description="Collects diagnostic data"},
            @{Name="RemoteRegistry"; DisplayName="Remote Registry"; Description="Allows remote registry access"},
            @{Name="RemoteAccess"; DisplayName="Remote Access"; Description="Provides remote access capabilities"},
            @{Name="TlntSvr"; DisplayName="Telnet"; Description="Provides Telnet server capabilities"},
            @{Name="FTPSVC"; DisplayName="FTP Publishing Service"; Description="Provides FTP server capabilities"}
        )
        
        # Store all services in the output
        $servicesInfo.AllServices = $serviceDetails | ForEach-Object {
            @{
                DisplayName = $_.DisplayName
                Name = $_.Name
                StartMode = $_.StartMode
                State = $_.State
                PathName = $_.PathName
                Description = $_.Description
                LogOnAccount = $_.LogOnAccount
            }
        }
        
        # Check critical services
        $servicesInfo.CriticalServices = @()
        foreach ($criticalService in $criticalServices) {
            $service = $serviceDetails | Where-Object { $_.Name -eq $criticalService.Name }
            
            if ($service) {
                if ($service.State -ne "Running") {
                    Add-Finding -TestResult $servicesInfo -FindingName "Critical Service: $($service.DisplayName)" -Status "Warning" `
                        -Description "Critical security service is not running" -RiskLevel "High" `
                        -AdditionalInfo @{
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            Status = $service.State
                            StartMode = $service.StartMode
                            LogOnAccount = $service.LogOnAccount
                        }
                } elseif ($service.StartMode -ne "Auto") {
                    Add-Finding -TestResult $servicesInfo -FindingName "Critical Service: $($service.DisplayName)" -Status "Warning" `
                        -Description "Critical security service is not set to start automatically" -RiskLevel "Medium" `
                        -AdditionalInfo @{
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            Status = $service.State
                            StartMode = $service.StartMode
                            LogOnAccount = $service.LogOnAccount
                        }
                } else {
                    Add-Finding -TestResult $servicesInfo -FindingName "Critical Service: $($service.DisplayName)" -Status "Pass" `
                        -Description "Critical security service is running and set to start automatically" -RiskLevel "Info" `
                        -AdditionalInfo @{
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            Status = $service.State
                            StartMode = $service.StartMode
                            LogOnAccount = $service.LogOnAccount
                        }
                }
            } else {
                Add-Finding -TestResult $servicesInfo -FindingName "Critical Service: $($criticalService.DisplayName)" -Status "Warning" `
                    -Description "Critical security service not found" -RiskLevel "High" `
                    -AdditionalInfo @{
                        ServiceName = $criticalService.Name
                        DisplayName = $criticalService.DisplayName
                        Description = $criticalService.Description
                    }
            }
        }
        
        # Check for high privilege services
        $highPrivilegeServices = $serviceDetails | Where-Object { 
            $_.LogOnAccount -eq "LocalSystem" -or 
            $_.LogOnAccount -eq "NT AUTHORITY\SYSTEM" -or 
            $_.LogOnAccount -eq "NT AUTHORITY\LocalService" -or 
            $_.LogOnAccount -eq "NT AUTHORITY\NetworkService" 
        }
        
        Add-Finding -TestResult $servicesInfo -FindingName "High Privilege Services" -Status "Info" `
            -Description "Found $($highPrivilegeServices.Count) services running with high privileges" -RiskLevel "Info" `
            -AdditionalInfo @{
                HighPrivilegeCount = $highPrivilegeServices.Count
                Services = $highPrivilegeServices | Select-Object DisplayName, Name, LogOnAccount
            }
        
        # Check for dangerous services
        $dangerousServices = @(
            @{Name="RemoteRegistry"; DisplayName="Remote Registry"; Description="Allows remote registry access"},
            @{Name="TelnetServer"; DisplayName="Telnet Server"; Description="Provides Telnet access"},
            @{Name="TlntSvr"; DisplayName="Telnet Server"; Description="Provides Telnet access"},
            @{Name="FTPSVC"; DisplayName="FTP Server"; Description="Provides FTP access"},
            @{Name="MSFTPSVC"; DisplayName="FTP Server"; Description="Provides FTP access"},
            @{Name="W3SVC"; DisplayName="World Wide Web Publishing Service"; Description="Provides web server functionality"},
            @{Name="IISADMIN"; DisplayName="IIS Admin"; Description="Manages IIS services"},
            @{Name="TermService"; DisplayName="Remote Desktop Services"; Description="Provides remote desktop access"}
        )
        
        $servicesInfo.DangerousServices = @()
        foreach ($dangerousService in $dangerousServices) {
            $service = $serviceDetails | Where-Object { $_.Name -eq $dangerousService.Name }
            
            if ($service -and $service.State -eq "Running") {
                Add-Finding -TestResult $servicesInfo -FindingName "Dangerous Service: $($service.DisplayName)" -Status "Warning" `
                    -Description "Dangerous service is running" -RiskLevel "High" `
                    -AdditionalInfo @{
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        Status = $service.State
                        StartMode = $service.StartMode
                        LogOnAccount = $service.LogOnAccount
                        Description = $dangerousService.Description
                    }
            }
        }
    }
    catch {
        Write-Error "Error analyzing Windows services: $_"
        Add-Finding -TestResult $servicesInfo -FindingName "Windows Services" -Status "Error" `
            -Description "Failed to analyze Windows services: $($_.Exception.Message)" -RiskLevel "High" `
            -AdditionalInfo @{
                Error = $_.Exception.Message
                StackTrace = $_.ScriptStackTrace
            }
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $servicesInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $servicesInfo
}

# Export the function
Export-ModuleMember -Function Test-WindowsServices 