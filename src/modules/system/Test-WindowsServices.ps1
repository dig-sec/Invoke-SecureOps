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
                $serviceStatus = @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Description = $criticalService.Description
                    StartMode = $service.StartMode
                    State = $service.State
                    LogOnAccount = $service.LogOnAccount
                    PathName = $service.PathName
                }
                
                $servicesInfo.CriticalServices += $serviceStatus
                
                # Add findings based on service status
                if ($service.State -ne "Running") {
                    Add-Finding -CheckName "Critical Service: $($service.DisplayName)" -Status "Warning" `
                        -Details "Critical service $($service.DisplayName) is not running" -Category "WindowsServices" `
                        -AdditionalInfo @{
                            Component = "Services"
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            CurrentState = $service.State
                            ExpectedState = "Running"
                            Recommendation = "Start the $($service.DisplayName) service"
                        }
                }
                elseif ($service.StartMode -ne "Automatic") {
                    Add-Finding -CheckName "Critical Service: $($service.DisplayName)" -Status "Warning" `
                        -Details "Critical service $($service.DisplayName) is not set to start automatically" -Category "WindowsServices" `
                        -AdditionalInfo @{
                            Component = "Services"
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            CurrentStartMode = $service.StartMode
                            ExpectedStartMode = "Automatic"
                            Recommendation = "Set $($service.DisplayName) to start automatically"
                        }
                }
                else {
                    Add-Finding -CheckName "Critical Service: $($service.DisplayName)" -Status "Pass" `
                        -Details "Critical service $($service.DisplayName) is running and set to start automatically" -Category "WindowsServices" `
                        -AdditionalInfo @{
                            Component = "Services"
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            State = $service.State
                            StartMode = $service.StartMode
                        }
                }
            }
            else {
                Add-Finding -CheckName "Critical Service: $($criticalService.DisplayName)" -Status "Warning" `
                    -Details "Critical service $($criticalService.DisplayName) is not installed" -Category "WindowsServices" `
                    -AdditionalInfo @{
                        Component = "Services"
                        ServiceName = $criticalService.Name
                        DisplayName = $criticalService.DisplayName
                        Status = "Not Installed"
                        Recommendation = "Consider installing $($criticalService.DisplayName) for better security"
                    }
            }
        }
        
        # Check for services running with high privileges
        $highPrivilegeAccounts = @("LocalSystem", "NT AUTHORITY\SYSTEM", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService")
        $highPrivilegeServices = $serviceDetails | Where-Object { $_.LogOnAccount -in $highPrivilegeAccounts }
        
        $servicesInfo.HighPrivilegeServices = $highPrivilegeServices | ForEach-Object {
            @{
                DisplayName = $_.DisplayName
                Name = $_.Name
                StartMode = $_.StartMode
                State = $_.State
                LogOnAccount = $_.LogOnAccount
                PathName = $_.PathName
            }
        }
        
        if ($highPrivilegeServices.Count -gt 0) {
            Add-Finding -CheckName "High Privilege Services" -Status "Info" `
                -Details "Found $($highPrivilegeServices.Count) services running with high privileges" -Category "WindowsServices" `
                -AdditionalInfo @{
                    Component = "Services"
                    Count = $highPrivilegeServices.Count
                    Services = $highPrivilegeServices | ForEach-Object {
                        @{
                            DisplayName = $_.DisplayName
                            Name = $_.Name
                            LogOnAccount = $_.LogOnAccount
                        }
                    }
                    Recommendation = "Review these services to ensure they require high privileges"
                }
        }
        
        # Check for potentially dangerous services
        $dangerousServices = @(
            @{Name="TlntSvr"; DisplayName="Telnet"; Description="Provides unencrypted remote access"},
            @{Name="FTPSVC"; DisplayName="FTP Publishing Service"; Description="Provides unencrypted file transfer"},
            @{Name="RemoteRegistry"; DisplayName="Remote Registry"; Description="Allows remote registry access"}
        )
        
        $servicesInfo.DangerousServices = @()
        foreach ($dangerousService in $dangerousServices) {
            $service = $serviceDetails | Where-Object { $_.Name -eq $dangerousService.Name }
            
            if ($service -and $service.State -eq "Running") {
                $serviceStatus = @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Description = $dangerousService.Description
                    StartMode = $service.StartMode
                    State = $service.State
                    LogOnAccount = $service.LogOnAccount
                    PathName = $service.PathName
                }
                
                $servicesInfo.DangerousServices += $serviceStatus
                
                Add-Finding -CheckName "Dangerous Service: $($service.DisplayName)" -Status "Warning" `
                    -Details "Potentially dangerous service $($service.DisplayName) is running" -Category "WindowsServices" `
                    -AdditionalInfo @{
                        Component = "Services"
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        Description = $dangerousService.Description
                        CurrentState = $service.State
                        Recommendation = "Consider disabling $($service.DisplayName) if not needed"
                    }
            }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Windows Services Analysis"
        Add-Finding -CheckName "Windows Services" -Status "Error" `
            -Details "Failed to check Windows services: $($_.Exception.Message)" -Category "WindowsServices" `
            -AdditionalInfo $errorInfo
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