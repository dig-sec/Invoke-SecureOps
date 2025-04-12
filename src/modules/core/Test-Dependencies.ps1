# -----------------------------------------------------------------------------
# Dependency Management Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests and manages dependencies required by the security assessment toolkit.

.DESCRIPTION
    This function checks for required PowerShell modules, Windows features, and
    system requirements. It can optionally install missing dependencies.

.PARAMETER AutoInstall
    Switch parameter to automatically install missing dependencies.

.PARAMETER WhatIf
    Switch parameter to simulate dependency installation without making changes.

.OUTPUTS
    [hashtable] A hashtable containing dependency check results and installation status.

.EXAMPLE
    Test-Dependencies -AutoInstall -Verbose

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-Dependencies {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$AutoInstall,
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf,
        
        [Parameter(Mandatory = $false)]
        [switch]$Verbose
    )

    try {
        Write-SectionHeader "Dependency Management"
        Write-Output "Checking required dependencies..."

        # Initialize results object
        $dependencyInfo = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            WindowsVersion = [System.Environment]::OSVersion.Version.ToString()
            RequiredModules = @()
            RequiredFeatures = @()
            MissingDependencies = @()
            InstalledDependencies = @()
            FailedInstallations = @()
            RequiresReboot = $false
            StartTime = Get-Date
            EndTime = $null
            Duration = 0
        }

        # Define required PowerShell modules
        $requiredModules = @(
            @{
                Name = "Microsoft.PowerShell.Security"
                MinimumVersion = "3.0.0.0"
                Required = $true
            },
            @{
                Name = "NetSecurity"
                MinimumVersion = "2.0.0.0"
                Required = $true
            },
            @{
                Name = "Defender"
                MinimumVersion = "1.0.0.0"
                Required = $false
            },
            @{
                Name = "Hyper-V"
                MinimumVersion = "2.0.0.0"
                Required = $false
            }
        )

        # Define required Windows features
        $requiredFeatures = @(
            @{
                Name = "Microsoft-Hyper-V-Management-PowerShell"
                DisplayName = "Hyper-V Management Tools"
                Required = $false
            },
            @{
                Name = "Windows-Defender"
                DisplayName = "Windows Defender"
                Required = $true
            }
        )

        # Check PowerShell version
        $minimumPSVersion = [Version]"5.1"
        $currentPSVersion = [Version]$PSVersionTable.PSVersion
        if ($currentPSVersion -lt $minimumPSVersion) {
            $dependencyInfo.MissingDependencies += @{
                Type = "PowerShell"
                Name = "PowerShell Version"
                Required = "$minimumPSVersion"
                Current = "$currentPSVersion"
                Status = "Upgrade Required"
            }
        }

        # Check Windows version
        $minimumWindowsVersion = [Version]"10.0"
        $currentWindowsVersion = [Version][System.Environment]::OSVersion.Version
        if ($currentWindowsVersion -lt $minimumWindowsVersion) {
            $dependencyInfo.MissingDependencies += @{
                Type = "Windows"
                Name = "Windows Version"
                Required = "$minimumWindowsVersion"
                Current = "$currentWindowsVersion"
                Status = "Upgrade Required"
            }
        }

        # Check PowerShell modules
        foreach ($module in $requiredModules) {
            $dependencyInfo.RequiredModules += $module

            $installedModule = Get-Module -Name $module.Name -ListAvailable | 
                Sort-Object Version -Descending | 
                Select-Object -First 1

            if (-not $installedModule) {
                if ($module.Required) {
                    $dependencyInfo.MissingDependencies += @{
                        Type = "Module"
                        Name = $module.Name
                        MinimumVersion = $module.MinimumVersion
                        Status = "Not Installed"
                    }

                    if ($AutoInstall) {
                        try {
                            if ($PSCmdlet.ShouldProcess($module.Name, "Install PowerShell Module")) {
                                Install-Module -Name $module.Name -MinimumVersion $module.MinimumVersion -Force
                                $dependencyInfo.InstalledDependencies += @{
                                    Type = "Module"
                                    Name = $module.Name
                                    Version = $module.MinimumVersion
                                    Status = "Installed"
                                }
                            }
                            else {
                                Write-Output "Would install module: $($module.Name) (WhatIf)"
                            }
                        }
                        catch {
                            $dependencyInfo.FailedInstallations += @{
                                Type = "Module"
                                Name = $module.Name
                                Error = $_.Exception.Message
                            }
                        }
                    }
                }
                else {
                    Write-Output "Optional module not installed: $($module.Name)"
                }
            }
            elseif ([Version]$installedModule.Version -lt [Version]$module.MinimumVersion) {
                if ($module.Required) {
                    $dependencyInfo.MissingDependencies += @{
                        Type = "Module"
                        Name = $module.Name
                        MinimumVersion = $module.MinimumVersion
                        CurrentVersion = $installedModule.Version
                        Status = "Upgrade Required"
                    }

                    if ($AutoInstall) {
                        try {
                            if ($PSCmdlet.ShouldProcess($module.Name, "Update PowerShell Module")) {
                                Update-Module -Name $module.Name -Force
                                $dependencyInfo.InstalledDependencies += @{
                                    Type = "Module"
                                    Name = $module.Name
                                    Version = $module.MinimumVersion
                                    Status = "Updated"
                                }
                            }
                            else {
                                Write-Output "Would update module: $($module.Name) (WhatIf)"
                            }
                        }
                        catch {
                            $dependencyInfo.FailedInstallations += @{
                                Type = "Module"
                                Name = $module.Name
                                Error = $_.Exception.Message
                            }
                        }
                    }
                }
                else {
                    Write-Output "Optional module needs update: $($module.Name)"
                }
            }
        }

        # Check Windows features
        foreach ($feature in $requiredFeatures) {
            $dependencyInfo.RequiredFeatures += $feature

            $installedFeature = Get-WindowsFeature -Name $feature.Name -ErrorAction SilentlyContinue
            if (-not $installedFeature -or -not $installedFeature.Installed) {
                if ($feature.Required) {
                    $dependencyInfo.MissingDependencies += @{
                        Type = "Feature"
                        Name = $feature.Name
                        DisplayName = $feature.DisplayName
                        Status = "Not Installed"
                    }

                    if ($AutoInstall) {
                        try {
                            if ($PSCmdlet.ShouldProcess($feature.DisplayName, "Install Windows Feature")) {
                                Install-WindowsFeature -Name $feature.Name -IncludeManagementTools
                                $dependencyInfo.InstalledDependencies += @{
                                    Type = "Feature"
                                    Name = $feature.Name
                                    DisplayName = $feature.DisplayName
                                    Status = "Installed"
                                }
                                $dependencyInfo.RequiresReboot = $true
                            }
                            else {
                                Write-Output "Would install feature: $($feature.DisplayName) (WhatIf)"
                            }
                        }
                        catch {
                            $dependencyInfo.FailedInstallations += @{
                                Type = "Feature"
                                Name = $feature.Name
                                DisplayName = $feature.DisplayName
                                Error = $_.Exception.Message
                            }
                        }
                    }
                }
                else {
                    Write-Output "Optional feature not installed: $($feature.DisplayName)"
                }
            }
        }

        # Calculate duration
        $dependencyInfo.EndTime = Get-Date
        $dependencyInfo.Duration = ($dependencyInfo.EndTime - $dependencyInfo.StartTime).TotalSeconds

        # Output summary
        Write-Output "`nDependency Check Summary:"
        Write-Output "- PowerShell Version: $($dependencyInfo.PowerShellVersion)"
        Write-Output "- Windows Version: $($dependencyInfo.WindowsVersion)"
        Write-Output "- Missing Dependencies: $($dependencyInfo.MissingDependencies.Count)"
        Write-Output "- Installed Dependencies: $($dependencyInfo.InstalledDependencies.Count)"
        Write-Output "- Failed Installations: $($dependencyInfo.FailedInstallations.Count)"
        
        if ($dependencyInfo.RequiresReboot) {
            Write-Output "`nWARNING: A system reboot is required to complete some installations."
        }

        if ($dependencyInfo.MissingDependencies.Count -gt 0 -and -not $AutoInstall) {
            Write-Output "`nTo install missing dependencies, run with -AutoInstall parameter."
        }

        return $dependencyInfo
    }
    catch {
        Write-Error "Error checking dependencies: $_"
        throw
    }
}

# Export the function
Export-ModuleMember -Function Test-Dependencies 