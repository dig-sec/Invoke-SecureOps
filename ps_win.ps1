# Work in progress PABI 2025
#Requires -RunAsAdministrator

param (
    [string]$OutputDir = ".\output",
    [switch]$Verbose,
    [switch]$Pretty
)

# Import helper functions
. .\functions\helpers.ps1
. .\functions\common.ps1
. .\functions\log_analysis.ps1
. .\functions\process_analysis.ps1
. .\functions\threat_hunting.ps1
. .\functions\wifi_check.ps1

# Initialize findings
Initialize-Findings

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Initialize assessment info
$assessmentInfo = Initialize-JsonOutput -Category "SystemAssessment" -RiskLevel "Medium" -ActionLevel "Review"
$assessmentInfo.StartTime = Get-FormattedTimestamp
$assessmentInfo.OutputDirectory = $OutputDir

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

if ($Verbose) {
    Write-Output "Starting assessment on $env:COMPUTERNAME at $($assessmentInfo.StartTime)"
}

# System Enumeration
Get-SystemInformation

# Log Analysis
Test-SystemLogs -Days 7 -OutputPath "$OutputDir\system_logs.json" -Pretty:$Pretty
Test-SecurityEvents -Days 7 -OutputPath "$OutputDir\security_events.json" -Pretty:$Pretty

# Process Analysis
Test-SystemProcesses -OutputPath "$OutputDir\system_processes.json" -Pretty:$Pretty
Test-ProcessConnections -OutputPath "$OutputDir\process_connections.json" -Pretty:$Pretty

# Security Checks
Test-OS_EOL
Test-AntivirusStatus
Test-BitLockerStatus
Test-WindowsFeatures
Test-InstalledRoles
Test-InstalledHotfixes
Test-InstalledPatches
Test-InstalledUpdates
Test-InstalledDrivers
Test-InstalledDevices
Test-InstalledPrinters
Test-InstalledScanners
Test-InstalledCameras
Test-InstalledMicrophones
Test-InstalledSpeakers
Test-InstalledKeyboards
Test-InstalledMice
Test-InstalledMonitors
Test-InstalledStorage
Test-InstalledMemory
Test-InstalledProcessors
Test-InstalledMotherboards
Test-InstalledBios
Test-InstalledFirmware
Test-InstalledBootConfiguration
Test-InstalledBootFiles
Test-InstalledBootRecords
Test-InstalledBootSectors
Test-InstalledBootPartitions
Test-InstalledBootVolumes
Test-InstalledBootDrives
Test-InstalledBootDevices
Test-InstalledBootControllers
Test-InstalledBootBuses
Test-InstalledBootPorts
Test-InstalledBootSlots
Test-InstalledBootCards
Test-InstalledBootModules
Test-InstalledBootComponents
Test-InstalledBootSystems
Test-InstalledBootPlatforms
Test-InstalledBootArchitectures
Test-InstalledBootProcessors
Test-InstalledBootMemory
Test-InstalledBootStorage
Test-InstalledBootNetwork
Test-InstalledBootVideo
Test-InstalledBootAudio
Test-InstalledBootInput
Test-InstalledBootOutput
Test-InstalledBootPeripheral
Test-InstalledBootExternal

# Threat Hunting
Test-ThreatHunting_EnvVariables
Test-ThreatHunting_ScheduledTasks
Test-WMIEventSubscriptions
Test-SuspiciousServices
Test-UnsignedDrivers
Test-UnusualDLLs
Test-PrefetchFiles

# Network Analysis
Test-NetworkConfiguration
Test-NetworkNeighborCache
Test-NetTCPConnection
Test-LocalRouteTable
Test-WifiProfiles

# Additional Security Checks
Test-CredentialProtection
Test-CachedCredentials
Test-CredentialGuard
Test-RegistrySecurity
Test-DirectoryPermissions
Test-PowerShellSecurity
Test-PowerShellHistory
Test-StorageEncryption
Test-SoftwareInventory
Test-UserAccountSecurity
Test-UnquotedServicePaths
Test-AdvancedNetworkSecurity
Test-WindowsServices
Test-SmbSigningEnabled
Test-SelfSignedCerts
Test-RDCManager
Test-WSUSSettings
Test-ServiceVulnerabilities
Test-PATHHijacking
Test-Credentials
Test-ExtendedDriveScan
Test-DirectorySecurityPermissions
Test-AccessibilityExecutables

# Write JSON report
$JsonOutputPath = Join-Path $OutputDir "$env:COMPUTERNAME`_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
Export-Findings -OutputPath $JsonOutputPath -Pretty:$Pretty

if ($Verbose) {
    Write-Output "Assessment completed. Results exported to: $JsonOutputPath"
    Write-FindingsSummary
}

# -----------------------------------------------------------------------------
# Security Check Functions
# -----------------------------------------------------------------------------

function Test-OS_EOL {
    Write-SectionHeader "OS End-of-Life Check"
    
    # Get detailed OS information
    $osInfo = Get-WmiObject win32_operatingsystem
    $os = $osInfo.Caption
    $version = $osInfo.Version
    $buildNumber = $osInfo.BuildNumber
    $eol = $false
    
    # Create detailed OS info object for JSON output
    $osDetails = @{
        OSName = $os
        OSVersion = $version
        BuildNumber = $buildNumber
        ServicePack = $osInfo.ServicePackMajorVersion
        InstallDate = [Management.ManagementDateTimeConverter]::ToDateTime($osInfo.InstallDate).ToString('yyyy-MM-dd HH:mm:ss')
        LastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($osInfo.LastBootUpTime).ToString('yyyy-MM-dd HH:mm:ss')
        Architecture = $osInfo.OSArchitecture
        SystemDrive = $osInfo.SystemDrive
        WindowsDirectory = $osInfo.WindowsDirectory
        SerialNumber = $osInfo.SerialNumber
        RegisteredUser = $osInfo.RegisteredUser
        Organization = $osInfo.Organization
    }
    
    # Define EOL dates for Windows versions
    $eolDates = @{
        # Client OS
        "Windows XP" = "2014-04-08"
        "Windows Vista" = "2017-04-11"
        "Windows 7" = "2020-01-14"
        "Windows 8" = "2016-01-12"
        "Windows 8.1" = "2023-01-10"
        "Windows 10 1507" = "2017-05-09"
        "Windows 10 1511" = "2017-10-10"
        "Windows 10 1607" = "2019-04-09"
        "Windows 10 1703" = "2018-10-09"
        "Windows 10 1709" = "2019-04-09"
        "Windows 10 1803" = "2019-11-12"
        "Windows 10 1809" = "2020-11-10"
        "Windows 10 1903" = "2020-12-08"
        "Windows 10 1909" = "2022-05-10"
        "Windows 10 2004" = "2021-12-14"
        "Windows 10 20H2" = "2023-05-09"
        "Windows 10 21H1" = "2022-12-13"
        "Windows 10 21H2" = "2024-06-11"
        
        # Server OS
        "Windows Server 2003" = "2015-07-14"
        "Windows Server 2003 R2" = "2015-07-14"
        "Windows Server 2008" = "2020-01-14"
        "Windows Server 2008 R2" = "2020-01-14"
        "Windows Server 2012" = "2023-10-10"
        "Windows Server 2012 R2" = "2023-10-10"
        "Windows Server 2016" = "2027-01-12"
        "Windows Server 2019" = "2029-01-09"
    }
    
    # Detect the exact Windows version with more detail
    $osVersionForEOL = ""
    $osDetails.DetectedWindowsVersion = ""
    
    # More comprehensive EOL detection with improved matching
    if ($os -like "*Windows XP*") {
        $eol = $true
        $osVersionForEOL = "Windows XP"
    } elseif ($os -like "*Windows Vista*") {
        $eol = $true
        $osVersionForEOL = "Windows Vista"
    } elseif ($os -like "*Windows 7*") {
        $eol = $true
        $osVersionForEOL = "Windows 7"
    } elseif ($os -like "*Windows 8*" -and $os -notlike "*Windows 8.1*") {
        $eol = $true
        $osVersionForEOL = "Windows 8"
    } elseif ($os -like "*Windows 8.1*") {
        $eol = $true  # EOL since Jan 10, 2023
        $osVersionForEOL = "Windows 8.1"
    } elseif ($os -like "*Windows Server 2003*") {
        $eol = $true
        $osVersionForEOL = "Windows Server 2003"
        if ($os -like "*R2*") {
            $osVersionForEOL = "Windows Server 2003 R2"
        }
    } elseif ($os -like "*Windows Server 2008*") {
        $eol = $true
        $osVersionForEOL = "Windows Server 2008"
        if ($os -like "*R2*") {
            $osVersionForEOL = "Windows Server 2008 R2"
        }
    } elseif ($os -like "*Windows Server 2012*") {
        if ($os -notlike "*R2*") {
            $eol = $true  # EOL since Oct 10, 2023
            $osVersionForEOL = "Windows Server 2012"
        } else {
            $eol = $true  # EOL since Oct 10, 2023
            $osVersionForEOL = "Windows Server 2012 R2"
        }
    } elseif ($os -like "*Windows Server 2016*") {
        $osVersionForEOL = "Windows Server 2016"
    } elseif ($os -like "*Windows Server 2019*") {
        $osVersionForEOL = "Windows Server 2019"
    } elseif ($os -like "*Windows Server 2022*") {
        $osVersionForEOL = "Windows Server 2022"
    } elseif ($os -like "*Windows 10*") {
        # Handle Windows 10 versions based on build number
        $windows10Builds = @{
            10240 = "Windows 10 1507"
            10586 = "Windows 10 1511"
            14393 = "Windows 10 1607"
            15063 = "Windows 10 1703"
            16299 = "Windows 10 1709"
            17134 = "Windows 10 1803"
            17763 = "Windows 10 1809"
            18362 = "Windows 10 1903"
            18363 = "Windows 10 1909"
            19041 = "Windows 10 2004"
            19042 = "Windows 10 20H2"
            19043 = "Windows 10 21H1"
            19044 = "Windows 10 21H2"
            19045 = "Windows 10 22H2"
        }
        
        $buildKey = [int]$buildNumber
        if ($windows10Builds.ContainsKey($buildKey)) {
            $osVersionForEOL = $windows10Builds[$buildKey]
            $osDetails.DetectedWindowsVersion = $osVersionForEOL
            # Check against EOL dates
            if ($eolDates.ContainsKey($osVersionForEOL)) {
                $eolDate = [DateTime]::Parse($eolDates[$osVersionForEOL])
                if ((Get-Date) -gt $eolDate) {
                    $eol = $true
                }
            }
        }
    } elseif ($os -like "*Windows 11*") {
        $windows11Builds = @{
            22000 = "Windows 11 21H2"
            22621 = "Windows 11 22H2" 
            22631 = "Windows 11 23H2"
        }
        
        $buildKey = [int]$buildNumber
        if ($windows11Builds.ContainsKey($buildKey)) {
            $osVersionForEOL = $windows11Builds[$buildKey]
            $osDetails.DetectedWindowsVersion = $osVersionForEOL
        } else {
            $osVersionForEOL = "Windows 11"
            $osDetails.DetectedWindowsVersion = "Windows 11 (Build $buildNumber)"
        }
    }
    
    # Add EOL information to OS details
    if ($osVersionForEOL -and $eolDates.ContainsKey($osVersionForEOL)) {
        $osDetails.EOLDate = $eolDates[$osVersionForEOL]
        $osDetails.DaysSinceEOL = if ($eol) {
            [math]::Round(((Get-Date) - [DateTime]::Parse($eolDates[$osVersionForEOL])).TotalDays)
        } else {
            $null
        }
    }
    
    $osDetails.IsEOL = $eol
    $osDetails.ExactWindowsVersion = $osVersionForEOL
    $osDetails.CurrentDate = (Get-Date).ToString('yyyy-MM-dd')
    
    if ($eol) {
        Write-Output "FAIL: Operating system is end-of-life."
        Write-Output "OS: $os ($osVersionForEOL)"
        Write-Output "Version: $version"
        Write-Output "Build: $buildNumber"
        
        if ($osVersionForEOL -and $eolDates.ContainsKey($osVersionForEOL)) {
            Write-Output "End of Support Date: $($eolDates[$osVersionForEOL])"
        }
        
        Add-Finding -CheckName "OS End-of-Life" -Status "Fail" `
            -Details "OS: $os ($osVersionForEOL) is no longer supported." -Category "SystemInfo" `
            -AdditionalInfo @{
                OSInfo = $osDetails
                Vulnerabilities = @(
                    "No longer receiving security updates",
                    "Increased risk of malware and other security threats",
                    "Potential compliance issues with regulatory standards",
                    "May not support modern security features"
                )
                RecommendedActions = @(
                    "Upgrade to a supported OS version as soon as possible",
                    "Implement additional network isolation controls if upgrade is not immediately possible",
                    "Consider extended support options if available from Microsoft"
                )
            }
    }
    else {
        Write-Output "PASS: Operating system is supported."
        Write-Output "OS: $os ($osVersionForEOL)"
        Write-Output "Version: $version"
        Write-Output "Build: $buildNumber"
        
        if ($osVersionForEOL -and $eolDates.ContainsKey($osVersionForEOL)) {
            Write-Output "End of Support Date: $($eolDates[$osVersionForEOL])"
        }
        
        Add-Finding -CheckName "OS End-of-Life" -Status "Pass" `
            -Details "OS: $os ($osVersionForEOL) is currently supported." -Category "SystemInfo" `
            -AdditionalInfo @{
                OSInfo = $osDetails
            }
    }
}

function Test-AntivirusStatus {
    Write-SectionHeader "Antivirus Status"
    
    # Create detailed object for JSON output
    $avInfo = @{
        AntivirusProducts = @()
        SecurityCenterAvailable = $false
        AntivirusDetected = $false
        LastScanTime = $null
        OperatingSystem = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        ScanMethod = "SecurityCenter2 WMI Query"
        ScanTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        $avInfo.SecurityCenterAvailable = $true
        
        if ($avProducts) {
            $avInfo.AntivirusDetected = $true
            Write-Output "PASS: Antivirus is installed."
            
            foreach ($av in $avProducts) {
                # Decode the product state from hex
                $hexString = [Convert]::ToString($av.productState, 16).PadLeft(6, '0')
                
                # Extract status information from hex string
                # Bits 0-1: Product status (0=Not installed, 1=Disabled, 2=Enabled)
                # Bits 2-3: Definition status (0=Up-to-date, 1=Out-of-date)
                # Bits 4-5: Real-time protection (0=On, 1=Off, 2=Snoozed, 3=Expired)
                $enabled = $hexString.Substring(2, 2) -eq "10" -or $hexString.Substring(2, 2) -eq "11"
                $upToDate = $hexString.Substring(4, 2) -eq "00"
                $realtimeEnabled = $hexString.Substring(0, 2) -eq "00" -or $hexString.Substring(0, 2) -eq "10"
                
                # Attempt to get additional details about the AV product
                $additionalDetails = @{}
                try {
                    $avProcess = if ($av.pathToSignedProductExe) {
                        $exeName = [System.IO.Path]::GetFileName($av.pathToSignedProductExe)
                        Get-Process -Name $exeName.Replace(".exe", "") -ErrorAction SilentlyContinue
                    } else { $null }
                    
                    if ($avProcess) {
                        $additionalDetails.ProcessId = $avProcess.Id
                        $additionalDetails.WorkingSet = $avProcess.WorkingSet64
                        $additionalDetails.CPUTime = $avProcess.TotalProcessorTime
                    }
                }
                catch {
                    # Process details unavailable
                }
                
                # Create detailed product information
                $productInfo = @{
                    DisplayName = $av.displayName
                    InstanceGuid = $av.instanceGuid
                    ProductState = $av.productState
                    ProductStateHex = "0x$hexString"
                    ProductStateDecoded = @{
                        Enabled = $enabled
                        UpToDate = $upToDate
                        RealtimeProtectionEnabled = $realtimeEnabled
                    }
                    PathToSignedProductExe = $av.pathToSignedProductExe
                    ProductVersion = $av.versionNumber
                    Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    ProcessDetails = $additionalDetails
                }
                
                # Add to collection
                $avInfo.AntivirusProducts += $productInfo
                
                # Add individual finding for each AV product
                $findingStatus = if ($enabled -and $upToDate) { "Pass" } elseif ($enabled) { "Warning" } else { "Fail" }
                $findingDetails = "$($av.displayName) - " + 
                                  "Status: " + $(if ($enabled) { "Enabled" } else { "Disabled" }) + ", " +
                                  "Definitions: " + $(if ($upToDate) { "Up-to-date" } else { "Out-of-date" })
                
                Add-Finding -CheckName "Antivirus: $($av.displayName)" -Status $findingStatus `
                    -Details $findingDetails -Category "Endpoint" `
                    -AdditionalInfo $productInfo
            }
        }
        else {
            Write-Output "FAIL: No antivirus detected."
            Add-Finding -CheckName "Antivirus" -Status "Fail" `
                -Details "No antivirus found." -Category "Endpoint" `
                -AdditionalInfo $avInfo
        }
    }
    catch {
        $avInfo.SecurityCenterAvailable = $false
        $avInfo.ErrorMessage = $_.Exception.Message
        
        # Fallback method - check for common AV services
        $commonAVServices = @(
            "MsMpSvc", "WinDefend", "McShield", "McAfeeFramework", "vsservppl",
            "ekrn", "avast! Antivirus", "avguard", "AVP", "NortonSecurity"
        )
        
        $runningAVServices = Get-Service | Where-Object { 
            $_.Name -in $commonAVServices -or 
            $_.DisplayName -match "antivirus|security|endpoint|protection" 
        }
        
        if ($runningAVServices) {
            $avInfo.AntivirusDetected = $true
            $avInfo.DetectionMethod = "Service Enumeration (Fallback)"
            
            foreach ($svc in $runningAVServices) {
                $avInfo.AntivirusProducts += @{
                    DisplayName = $svc.DisplayName
                    ServiceName = $svc.Name
                    Status = $svc.Status.ToString()
                    StartType = $svc.StartType.ToString()
                    DetectionMethod = "Service Enumeration"
                    Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
            
            Write-Output "PASS: Antivirus services detected (using fallback method)."
            Add-Finding -CheckName "Antivirus (Fallback Detection)" -Status "Pass" `
                -Details "Detected $($runningAVServices.Count) antivirus-related services." -Category "Endpoint" `
                -AdditionalInfo $avInfo
        }
        else {
            Write-Output "FAIL: No antivirus detected (SecurityCenter2 unavailable and no AV services found)."
            Add-Finding -CheckName "Antivirus" -Status "Fail" `
                -Details "No antivirus found. SecurityCenter2 WMI access failed and no AV services detected." -Category "Endpoint" `
                -AdditionalInfo $avInfo
        }
    }
    
    # Add overall antivirus status finding with comprehensive details
    Add-Finding -CheckName "Antivirus Status Summary" -Status "Info" `
        -Details "AV products detected: $($avInfo.AntivirusProducts.Count)" -Category "Endpoint" `
        -AdditionalInfo $avInfo
}

function Test-CredentialGuard {
    Write-SectionHeader "Credential Guard Status"
    
    # Create comprehensive object for JSON output
    $credGuardInfo = @{
        RegistrySettings = @{
            LsaCfgFlagsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
            LsaCfgFlagsValue = $null
            LsaCfgFlagsExists = $false
            LsaCfgFlagsMeaning = @{
                0 = "Credential Guard disabled"
                1 = "Credential Guard enabled with UEFI lock"
                2 = "Credential Guard enabled without UEFI lock"
            }
        }
        DeviceGuard = @{
            Available = $false
            VirtualizationBasedSecurityStatus = $null
            VirtualizationBasedSecurityStatusMeaning = @{
                0 = "VBS not enabled"
                1 = "VBS enabled but not running"
                2 = "VBS enabled and running"
            }
            SecurityServicesConfigured = @()
            SecurityServicesRunning = @()
            RequiredSecurityProperties = @()
            AvailableSecurityProperties = @()
            SecurityServicesMapping = @{
                1 = "Credential Guard"
                2 = "Hypervisor enforced Code Integrity"
                3 = "System Guard Secure Launch"
                4 = "SMM Protection"
                5 = "APIC Virtualization"
                6 = "vTPM"
            }
        }
        HardwareCapability = @{
            ProcessorVirtualizationSupport = $false
            TPMPresent = $false
            TPMVersion = $null
            SecureBootEnabled = $false
            UEFIPresent = $false
        }
        OverallStatus = @{
            IsEnabled = $false
            IsRunning = $false
            StatusMessage = "Credential Guard status could not be determined"
            ConfigurationMethod = "Not configured"
        }
        RecommendedActions = @()
    }
    
    # Check registry configuration
    try {
        $lsaCfgFlags = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
        if ($null -ne $lsaCfgFlags) {
            $credGuardInfo.RegistrySettings.LsaCfgFlagsExists = $true
            $credGuardInfo.RegistrySettings.LsaCfgFlagsValue = $lsaCfgFlags
            
            if ($lsaCfgFlags -in @(1,2)) {
                $credGuardInfo.OverallStatus.ConfigurationMethod = "Registry"
                $credGuardInfo.OverallStatus.IsEnabled = $true
            }
        }
    }
    catch {
        $credGuardInfo.RegistrySettings.Error = $_.Exception.Message
    }
    
    # Check via WMI/CIM
    try {
        $deviceGuardStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($deviceGuardStatus) {
            $credGuardInfo.DeviceGuard.Available = $true
            $credGuardInfo.DeviceGuard.VirtualizationBasedSecurityStatus = $deviceGuardStatus.VirtualizationBasedSecurityStatus
            
            # Add raw values from DeviceGuard
            $securityServices = @()
            foreach ($service in $deviceGuardStatus.SecurityServicesConfigured) {
                if ($credGuardInfo.DeviceGuard.SecurityServicesMapping.ContainsKey($service)) {
                    $securityServices += $credGuardInfo.DeviceGuard.SecurityServicesMapping[$service]
                } else {
                    $securityServices += "Unknown service ($service)"
                }
            }
            $credGuardInfo.DeviceGuard.SecurityServicesConfigured = $securityServices
            
            $runningServices = @()
            foreach ($service in $deviceGuardStatus.SecurityServicesRunning) {
                if ($credGuardInfo.DeviceGuard.SecurityServicesMapping.ContainsKey($service)) {
                    $runningServices += $credGuardInfo.DeviceGuard.SecurityServicesMapping[$service]
                } else {
                    $runningServices += "Unknown service ($service)"
                }
            }
            $credGuardInfo.DeviceGuard.SecurityServicesRunning = $runningServices
            
            # Process required security properties
            $credGuardInfo.DeviceGuard.RequiredSecurityProperties = $deviceGuardStatus.RequiredSecurityProperties
            $credGuardInfo.DeviceGuard.AvailableSecurityProperties = $deviceGuardStatus.AvailableSecurityProperties
            
            # Update overall status based on actual running services
            if ($deviceGuardStatus.SecurityServicesRunning -contains 1) {
                $credGuardInfo.OverallStatus.IsRunning = $true
                if (-not $credGuardInfo.OverallStatus.IsEnabled) {
                    $credGuardInfo.OverallStatus.IsEnabled = $true
                    $credGuardInfo.OverallStatus.ConfigurationMethod = "Group Policy or Other"
                }
            }
        }
    }
    catch {
        $credGuardInfo.DeviceGuard.Error = $_.Exception.Message
    }
    
    # Check hardware capabilities
    try {
        $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        $credGuardInfo.HardwareCapability.SecureBootEnabled = $secureBootStatus
        $credGuardInfo.HardwareCapability.UEFIPresent = $true
    }
    catch {
        # If this fails, likely not UEFI
        $credGuardInfo.HardwareCapability.UEFIPresent = $false
    }
    
    # Check for TPM
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $credGuardInfo.HardwareCapability.TPMPresent = $tpm.TpmPresent
            $credGuardInfo.HardwareCapability.TPMVersion = $tpm.ManufacturerVersionInfo
        }
    }
    catch {
        # TPM check failed
    }
    
    # Check processor virtualization support
    try {
        $processorInfo = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($processorInfo) {
            # VT-x/AMD-V is needed for virtualization
            $credGuardInfo.HardwareCapability.ProcessorVirtualizationSupport = $processorInfo.VirtualizationFirmwareEnabled
        }
    }
    catch {
        # Processor check failed
    }
    
    # Generate recommended actions based on findings
    if (-not $credGuardInfo.OverallStatus.IsEnabled) {
        $credGuardInfo.RecommendedActions += "Enable Credential Guard using Group Policy or registry settings"
        
        if (-not $credGuardInfo.HardwareCapability.UEFIPresent) {
            $credGuardInfo.RecommendedActions += "Upgrade to UEFI BIOS to support Credential Guard"
        }
        
        if (-not $credGuardInfo.HardwareCapability.SecureBootEnabled) {
            $credGuardInfo.RecommendedActions += "Enable Secure Boot in UEFI settings"
        }
        
        if (-not $credGuardInfo.HardwareCapability.TPMPresent) {
            $credGuardInfo.RecommendedActions += "Install and enable TPM"
        }
        
        if (-not $credGuardInfo.HardwareCapability.ProcessorVirtualizationSupport) {
            $credGuardInfo.RecommendedActions += "Enable virtualization support in BIOS/UEFI settings"
        }
    }
    elseif (-not $credGuardInfo.OverallStatus.IsRunning) {
        $credGuardInfo.RecommendedActions += "Credential Guard is configured but not running. Verify hardware requirements and restart the system."
    }
    
    # Set final status message
    if ($credGuardInfo.OverallStatus.IsRunning) {
        $credGuardInfo.OverallStatus.StatusMessage = "Credential Guard is enabled and running"
    }
    elseif ($credGuardInfo.OverallStatus.IsEnabled) {
        $credGuardInfo.OverallStatus.StatusMessage = "Credential Guard is configured but not running"
    }
    else {
        $credGuardInfo.OverallStatus.StatusMessage = "Credential Guard is not enabled"
    }
    
    # Output to console
    if ($credGuardInfo.OverallStatus.IsRunning) {
        Write-Output "PASS: Credential Guard is enabled and running."
        if ($credGuardInfo.RegistrySettings.LsaCfgFlagsValue -eq 1) {
            Write-Output "Registry configuration: Enabled with UEFI lock (LsaCfgFlags = 1)"
        } elseif ($credGuardInfo.RegistrySettings.LsaCfgFlagsValue -eq 2) {
            Write-Output "Registry configuration: Enabled without UEFI lock (LsaCfgFlags = 2)"
        } else {
            Write-Output "Enabled via Group Policy or other mechanism"
        }
        
        # Show detailed information
        Write-Output "Security Services Running: $($credGuardInfo.DeviceGuard.SecurityServicesRunning -join ', ')"
        Write-Output "Virtualization-based Security Status: $($credGuardInfo.DeviceGuard.VirtualizationBasedSecurityStatus) (${$credGuardInfo.DeviceGuard.VirtualizationBasedSecurityStatusMeaning[$credGuardInfo.DeviceGuard.VirtualizationBasedSecurityStatus]})"
        
        Add-Finding -CheckName "Credential Guard" -Status "Pass" `
            -Details "Credential Guard is enabled and running." -Category "CredProtection" `
            -AdditionalInfo $credGuardInfo
    }
    elseif ($credGuardInfo.OverallStatus.IsEnabled) {
        Write-Output "FAIL: Credential Guard is configured but not running."
        Write-Output "Configuration method: $($credGuardInfo.OverallStatus.ConfigurationMethod)"
        Write-Output "Recommended actions:"
        foreach ($action in $credGuardInfo.RecommendedActions) {
            Write-Output "- $action"
        }
        
        Add-Finding -CheckName "Credential Guard" -Status "Fail" `
            -Details "Credential Guard is configured but not running." -Category "CredProtection" `
            -AdditionalInfo $credGuardInfo
    }
    else {
        Write-Output "FAIL: Credential Guard is not enabled."
        Write-Output "Recommended actions:"
        foreach ($action in $credGuardInfo.RecommendedActions) {
            Write-Output "- $action"
        }
        
        Add-Finding -CheckName "Credential Guard" -Status "Fail" `
            -Details "Credential Guard is not enabled." -Category "CredProtection" `
            -AdditionalInfo $credGuardInfo
    }
    
    # Add a detailed technical summary for security professionals
    Add-Finding -CheckName "Credential Guard Technical Details" -Status "Info" `
        -Details "Detailed Credential Guard configuration and capability assessment." -Category "CredProtection" `
        -AdditionalInfo $credGuardInfo
}

function Test-RegisteredAntivirus {
    Write-SectionHeader "Registered Antivirus Products"
    Write-Host " [+] Registered Antivirus" -ForegroundColor Yellow

    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
    $avDetails = @()

    if ($avProducts) {
        $avProducts | Select-Object displayName | Format-Table -AutoSize

        # Process each antivirus product
        foreach ($av in $avProducts) {
            # Decode the productState bit field
            $state = $av.productState
            $hexString = [Convert]::ToString($state, 16).PadLeft(6, '0')
            $enabled = $hexString.Substring(2, 2) -eq "10" -or $hexString.Substring(2, 2) -eq "11"
            $upToDate = $hexString.Substring(4, 2) -eq "00"

            # Create detailed antivirus information
            $avInfo = @{
                Name = $av.displayName
                Enabled = $enabled
                UpToDate = $upToDate
                ProductState = $state
                ProductStateHex = "0x$hexString"
                Path = $av.pathToSignedProductExe
                Version = $av.versionNumber
                Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            }
            $avDetails += $avInfo

            # Add findings for each antivirus product
            if ($enabled) {
                Add-Finding -CheckName "Antivirus Status: $($av.displayName)" -Status "Pass" `
                    -Details "Antivirus product is enabled." -Category "Endpoint" `
                    -AdditionalInfo $avInfo
            } else {
                Add-Finding -CheckName "Antivirus Status: $($av.displayName)" -Status "Fail" `
                    -Details "Antivirus product is not enabled." -Category "Endpoint" `
                    -AdditionalInfo $avInfo
            }

            if ($upToDate) {
                Add-Finding -CheckName "Antivirus Updates: $($av.displayName)" -Status "Pass" `
                    -Details "Antivirus definitions are up-to-date." -Category "Endpoint" `
                    -AdditionalInfo $avInfo
            } else {
                Add-Finding -CheckName "Antivirus Updates: $($av.displayName)" -Status "Warning" `
                    -Details "Antivirus definitions may not be up-to-date." -Category "Endpoint" `
                    -AdditionalInfo $avInfo
            }
        }
    } else {
        Write-Host "   No AV products detected."
        Add-Finding -CheckName "Antivirus Products" -Status "Fail" `
            -Details "No antivirus products detected." -Category "Endpoint"
    }

    # Check for Windows Defender exclusions
    $defenderExclusions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ErrorAction SilentlyContinue
    $exclusionDetails = @()

    if ($defenderExclusions) {
        Write-Host "   Defender Exclusions:"
        $defenderExclusions | Format-List

        # Process exclusion paths
        $excludedPaths = $defenderExclusions.PSObject.Properties | Where-Object {
            $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
        }

        foreach ($path in $excludedPaths) {
            $exclusionDetails += @{
                Path = $path.Name
                Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            }
        }

        if ($excludedPaths.Count -gt 0) {
            Add-Finding -CheckName "Defender Exclusions" -Status "Warning" `
                -Details "$($excludedPaths.Count) path exclusions found." -Category "Endpoint" `
                -AdditionalInfo @{
                    ExclusionCount = $excludedPaths.Count
                    ExclusionPaths = $exclusionDetails
                }
        } else {
            Add-Finding -CheckName "Defender Exclusions" -Status "Pass" `
                -Details "No path exclusions configured." -Category "Endpoint"
        }
    } else {
        Add-Finding -CheckName "Defender Exclusions" -Status "Info" `
            -Details "No exclusion information available." -Category "Endpoint"
    }
}

function Test-PatchManagement {
    Write-SectionHeader "Patch Management"
    
    try {
        # Retrieve hotfixes with full details
        $hotfixes = Get-HotFix -ErrorAction Stop
        
        # Display installed hotfixes
        $hotfixes | Select-Object HotFixID, Description, InstalledOn | Format-Table -AutoSize
        
        # Check for patches installed in the last 90 days
        $recentPatchDate = (Get-Date).AddDays(-90)
        $recentPatches = $hotfixes | Where-Object { $_.InstalledOn -gt $recentPatchDate }
        
        # Create detailed patch info for JSON with comprehensive patch details
        $patchDetails = @{
            PatchCount = $hotfixes.Count
            RecentPatchCount = $recentPatches.Count
            OldestPatch = ($hotfixes | Sort-Object InstalledOn | Select-Object -First 1).InstalledOn
            NewestPatch = ($hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
            AssessmentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                OSName = (Get-WmiObject -Class Win32_OperatingSystem).Caption
                OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
                OSBuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
            }
            # Detailed granular data for each patch
            AllPatches = $hotfixes | ForEach-Object {
                @{
                    HotFixID = $_.HotFixID
                    Description = $_.Description
                    InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { "Unknown" }
                    InstalledBy = $_.InstalledBy
                    Caption = $_.Caption
                    FixComments = $_.FixComments
                    ServicePackInEffect = $_.ServicePackInEffect
                    Status = $_.Status
                    CSName = $_.CSName
                    InstallationSource = $null # Not available in standard Get-HotFix but added for future expansion
                    IsRecent = if ($_.InstalledOn -gt $recentPatchDate) { $true } else { $false }
                    DaysSinceInstallation = if ($_.InstalledOn) { 
                        [math]::Round(((Get-Date) - $_.InstalledOn).TotalDays, 2) 
                    } else { 
                        $null 
                    }
                }
            }
            RecentPatchesDetailed = $recentPatches | ForEach-Object {
                @{
                    HotFixID = $_.HotFixID
                    Description = $_.Description
                    InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { "Unknown" }
                    InstalledBy = $_.InstalledBy
                    DaysSinceInstallation = if ($_.InstalledOn) { 
                        [math]::Round(((Get-Date) - $_.InstalledOn).TotalDays, 2) 
                    } else { 
                        $null 
                    }
                }
            }
            # Statistics about patches categorized by type
            PatchCategories = @{
                SecurityUpdates = ($hotfixes | Where-Object { $_.Description -match "Security Update" }).Count
                CriticalUpdates = ($hotfixes | Where-Object { $_.Description -match "Critical Update" }).Count
                UpdateRollups = ($hotfixes | Where-Object { $_.Description -match "Update Rollup" }).Count
                ServicePacks = ($hotfixes | Where-Object { $_.Description -match "Service Pack" }).Count
                Hotfixes = ($hotfixes | Where-Object { $_.Description -match "Hotfix" }).Count
                Updates = ($hotfixes | Where-Object { $_.Description -match "Update" -and $_.Description -notmatch "Security|Critical" }).Count
                OtherPatches = ($hotfixes | Where-Object { 
                    $_.Description -notmatch "Security|Critical|Update|Service Pack|Hotfix" 
                }).Count
            }
            # Timeline analysis
            PatchTimeline = @{
                Last30Days = ($hotfixes | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-30) }).Count
                Last60Days = ($hotfixes | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-60) }).Count
                Last90Days = $recentPatches.Count
                Last180Days = ($hotfixes | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-180) }).Count
                Last365Days = ($hotfixes | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-365) }).Count
            }
        }
        
        if ($recentPatches.Count -gt 0) {
            Write-Output "PASS: Recent security patches installed."
            Add-Finding -CheckName "Recent Security Patches" -Status "Pass" `
                -Details "$($recentPatches.Count) patches within last 90 days." -Category "PatchManagement" `
                -AdditionalInfo $patchDetails
        }
        else {
            Write-Output "FAIL: No recent security patches found."
            Add-Finding -CheckName "Recent Security Patches" -Status "Fail" `
                -Details "No patches installed in the last 90 days." -Category "PatchManagement" `
                -AdditionalInfo $patchDetails
        }
    }
    catch {
        Write-Output "FAIL: Unable to retrieve hotfix information: $_"
        Add-Finding -CheckName "Hotfix Retrieval" -Status "Fail" `
            -Details "Hotfix information not available: $($_.Exception.Message)" -Category "PatchManagement" `
            -AdditionalInfo @{
                Error = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
                StackTrace = $_.ScriptStackTrace
                HotfixQueryAttempted = $true
                SystemInfo = @{
                    ComputerName = $env:COMPUTERNAME
                    OSName = $(try { (Get-WmiObject -Class Win32_OperatingSystem).Caption } catch { "Unknown" })
                    OSVersion = $(try { (Get-WmiObject -Class Win32_OperatingSystem).Version } catch { "Unknown" })
                }
            }
    }
    
    # Retrieve OS name and check for EOL versions that might need specific patches
    try {
        $osInfo = Get-WmiObject win32_operatingsystem -ErrorAction Stop
        $osName = $osInfo.Caption
        $osVersion = $osInfo.Version
        $buildNumber = $osInfo.BuildNumber
        
        # Detailed OS information for JSON output
        $osDetailedInfo = @{
            Caption = $osName
            Version = $osVersion
            BuildNumber = $buildNumber
            ServicePackMajorVersion = $osInfo.ServicePackMajorVersion
            ServicePackMinorVersion = $osInfo.ServicePackMinorVersion
            InstallDate = [Management.ManagementDateTimeConverter]::ToDateTime($osInfo.InstallDate).ToString('yyyy-MM-dd HH:mm:ss')
            LastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($osInfo.LastBootUpTime).ToString('yyyy-MM-dd HH:mm:ss')
            LocalDateTime = $osInfo.LocalDateTime
            OSArchitecture = $osInfo.OSArchitecture
            MUILanguages = $osInfo.MUILanguages
            Manufacturer = $osInfo.Manufacturer
        }
        
        if ($osName -match "Windows (7|Vista|XP|2008|2003)") {
            Write-Output "Checking for missing critical patches..."
            
            # List of critical patches for older OS versions - enhanced with CVE information where available
            $criticalPatches = @(
                @{HotFixID = "KB2592799"; Description = "MS11-080: XP/SP3, 2003/SP3 (afd.sys)"; CVE = "CVE-2011-2005"; Severity = "Critical"}
                @{HotFixID = "KB3143141"; Description = "MS16-032: 2008/SP1/2, Vista/SP2, 7/SP1 (secondary logon)"; CVE = "CVE-2016-0099"; Severity = "Critical"}
                @{HotFixID = "KB2393802"; Description = "MS11-011: XP/SP2/3, 2003/SP2, 2008/SP2, Vista/SP1/2, 7/SP0 (WmiTraceMessageVa)"; CVE = "CVE-2011-0045"; Severity = "Critical"}
                @{HotFixID = "KB982799"; Description = "MS10-059: 2008, Vista, 7/SP0 (Chimichurri)"; CVE = "CVE-2010-2555"; Severity = "Important"}
                @{HotFixID = "KB979683"; Description = "MS10-021: 2000/SP4, XP/SP2/3, 2003/SP2, 2008/SP2, Vista/SP0/1/2, 7/SP0 (Win Kernel)"; CVE = "CVE-2010-0232"; Severity = "Critical"}
                @{HotFixID = "KB2305420"; Description = "MS10-092: 2008/SP0/1/2, Vista/SP1/2, 7/SP0 (Task Scheduler)"; CVE = "CVE-2010-3338"; Severity = "Important"}
                @{HotFixID = "KB981957"; Description = "MS10-073: XP/SP2/3, 2003/SP2, 2008/SP2, Vista/SP1/2, 7/SP0 (Keyboard Layout)"; CVE = "CVE-2010-2743"; Severity = "Important"}
                @{HotFixID = "KB4013081"; Description = "MS17-017: 2008/SP2, Vista/SP2, 7/SP1 (Registry Hive Loading)"; CVE = "CVE-2017-0103"; Severity = "Important"}
                @{HotFixID = "KB977165"; Description = "MS10-015: 2000, XP, 2003, 2008, Vista, 7 (User Mode to Ring)"; CVE = "CVE-2010-0232"; Severity = "Critical"}
                @{HotFixID = "KB941693"; Description = "MS08-025: 2000/SP4, XP/SP2, 2003/SP1/2, 2008/SP0, Vista/SP0/1 (win32k.sys)"; CVE = "CVE-2008-1084"; Severity = "Important"}
                @{HotFixID = "KB920958"; Description = "MS06-049: 2000/SP4 (ZwQuerySysInfo)"; CVE = "CVE-2006-3442"; Severity = "Important"}
                @{HotFixID = "KB914389"; Description = "MS06-030: 2000, XP/SP2 (Mrxsmb.sys)"; CVE = "CVE-2006-2373"; Severity = "Critical"}
                @{HotFixID = "KB908523"; Description = "MS05-055: 2000/SP4 (APC Data-Free)"; CVE = "CVE-2005-2119"; Severity = "Critical"}
                @{HotFixID = "KB890859"; Description = "MS05-018: 2000/SP3/4, XP/SP1/2 (CSRSS)"; CVE = "CVE-2005-0071"; Severity = "Critical"}
                @{HotFixID = "KB842526"; Description = "MS04-019: 2000/SP2/3/4 (Utility Manager)"; CVE = "CAN-2004-0213"; Severity = "Important"}
                @{HotFixID = "KB835732"; Description = "MS04-011: 2000/SP2/3/4, XP/SP0/1 (LSASS BoF)"; CVE = "CAN-2003-0533"; Severity = "Critical"}
                @{HotFixID = "KB841872"; Description = "MS04-020: 2000/SP4 (POSIX)"; CVE = "CAN-2004-0210"; Severity = "Important"}
                @{HotFixID = "KB2975684"; Description = "MS14-040: 2003/SP2, 2008/SP2, Vista/SP2, 7/SP1 (afd.sys Dangling Pointer)"; CVE = "CVE-2014-1767"; Severity = "Important"}
                @{HotFixID = "KB3136041"; Description = "MS16-016: 2008/SP1/2, Vista/SP2, 7/SP1 (WebDAV)"; CVE = "CVE-2016-0051"; Severity = "Important"}
                @{HotFixID = "KB3057191"; Description = "MS15-051: 2003/SP2, 2008/SP2, Vista/SP2, 7/SP1 (win32k.sys)"; CVE = "CVE-2015-1701"; Severity = "Important"}
                @{HotFixID = "KB2989935"; Description = "MS14-070: 2003/SP2 (TCP/IP)"; CVE = "CVE-2014-4076"; Severity = "Important"}
                @{HotFixID = "KB2778930"; Description = "MS13-005: Vista, 7, 8, 2008, 2008R2, 2012, RT (hwnd_broadcast)"; CVE = "CVE-2013-0002"; Severity = "Important"}
                @{HotFixID = "KB2850851"; Description = "MS13-053: 7/SP0/SP1_x86 (schlamperei)"; CVE = "CVE-2013-3129"; Severity = "Important"}
                @{HotFixID = "KB2870008"; Description = "MS13-081: 7/SP0/SP1_x86 (track_popup_menu)"; CVE = "CVE-2013-3881"; Severity = "Important"}
                @{HotFixID = "KB982666"; Description = "MS10-061: 2008/SP2, Vista/SP1/2, 7/SP0 (Print Spooler)"; CVE = "CVE-2010-2729"; Severity = "Critical"}
                @{HotFixID = "KB3139914"; Description = "MS16-024: 2008/SP1/2, Vista/SP2, 7/SP1 (PDF Library)"; CVE = "CVE-2016-0046"; Severity = "Critical"}
                @{HotFixID = "KB2503665"; Description = "MS11-046: 2003/SP2, 2008/SP2, Vista/SP1/2, 7/SP0 (AFD.sys)"; CVE = "CVE-2011-1249"; Severity = "Important"}
                @{HotFixID = "KB2724197"; Description = "MS13-018: XP/SP3 (Kernel Win32k.sys)"; CVE = "CVE-2013-1251"; Severity = "Important"}
                @{HotFixID = "KB3000061"; Description = "MS14-058: 2003/SP2, 2008/SP2, Vista/SP2, 7/SP1 (Win32k.sys)"; CVE = "CVE-2014-4113"; Severity = "Critical"}
                @{HotFixID = "KB2829361"; Description = "MS13-046: 2003/SP2, 2008/SP2, Vista/SP2, 7/SP0/SP1 (dxgkrnl.sys)"; CVE = "CVE-2013-1300"; Severity = "Important"}
                @{HotFixID = "KB2868626"; Description = "MS13-097: Internet Explorer Memory Corruption"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB3011780"; Description = "MS14-064: Internet Explorer vulnerabilities"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB3045171"; Description = "MS15-027: NETLOGON triggering vulnerability"; CVE = "CVE-2015-0005"; Severity = "Important"}
                @{HotFixID = "KB3077657"; Description = "MS15-078: Remote Code Execution in Font Driver"; CVE = "CVE-2015-2426"; Severity = "Critical"}
                @{HotFixID = "KB3124280"; Description = "MS16-007: Remote Code Execution in Microsoft DLL"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4012213"; Description = "MS17-010: SMB RCE (EternalBlue/WannaCry)"; CVE = "CVE-2017-0143,CVE-2017-0144,CVE-2017-0145,CVE-2017-0146,CVE-2017-0147,CVE-2017-0148"; Severity = "Critical"; ExploitInTheWild = $true}
                @{HotFixID = "KB4022747"; Description = "June 2017 Critical Update"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4012606"; Description = "MS17-012: Windows SMB/Win32k Elevation of Privilege"; CVE = "Multiple"; Severity = "Important"}
                @{HotFixID = "KB4041693"; Description = "Windows 7 Security Update (2017-10)"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4012212"; Description = "MS17-010: SMB Security Update"; CVE = "CVE-2017-0143,CVE-2017-0144,CVE-2017-0145,CVE-2017-0146,CVE-2017-0147,CVE-2017-0148"; Severity = "Critical"; ExploitInTheWild = $true}
                @{HotFixID = "KB2839229"; Description = "MS13-081: Win32k.sys Elevation of Privilege"; CVE = "Multiple"; Severity = "Important"}
                @{HotFixID = "KB3124624"; Description = "Security Update for Windows (Remote Font Driver vulnerability)"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB3033889"; Description = "MS15-010: Vulnerability in Windows Kernel Mode Driver"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB3046269"; Description = "MS15-023: Security Update for Windows Kernel"; CVE = "Multiple"; Severity = "Important"}
                @{HotFixID = "KB3004361"; Description = "MS14-064: Critical OLE Vulnerability"; CVE = "CVE-2014-6332"; Severity = "Critical"; ExploitInTheWild = $true}
                @{HotFixID = "KB4525235"; Description = "November 2019 Security Update for Windows"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4041681"; Description = "Windows 7 Security Update (2017-09)"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB2984972"; Description = "MS14-060: Vulnerability in Windows OLE"; CVE = "CVE-2014-4114"; Severity = "Important"; ExploitInTheWild = $true}
                @{HotFixID = "KB3000483"; Description = "MS14-066: SSL/TLS Vulnerability (POODLE)"; CVE = "CVE-2014-3566"; Severity = "Important"}
                @{HotFixID = "KB2991963"; Description = "MS14-058: Kernel-Mode Driver Vulnerabilities"; CVE = "CVE-2014-4113,CVE-2014-4148"; Severity = "Critical"}
                @{HotFixID = "KB3088195"; Description = "MS15-102: Windows Task Management Vulnerability"; CVE = "CVE-2015-2524"; Severity = "Important"}
                @{HotFixID = "KB2862152"; Description = "MS13-098: WinVerifyTrust Signature Validation"; CVE = "CVE-2013-3900"; Severity = "Important"}
                @{HotFixID = "KB2823324"; Description = "MS13-031: Kernel Elevation of Privilege"; CVE = "CVE-2013-1284,CVE-2013-1285"; Severity = "Important"}
                @{HotFixID = "KB3197835"; Description = "MS16-135: Windows Kernel Vulnerability"; CVE = "CVE-2016-7255"; Severity = "Important"; ExploitInTheWild = $true}
                @{HotFixID = "KB3206632"; Description = "December 2016 Security Update"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4034879"; Description = "August 2017 Security Update"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4056897"; Description = "January 2018 Security Update (Meltdown/Spectre)"; CVE = "CVE-2017-5753,CVE-2017-5754,CVE-2017-5715"; Severity = "Critical"; ExploitInTheWild = $true}
                @{HotFixID = "KB4039653"; Description = "September 2017 Security Update"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4021903"; Description = "May 2017 Security Update"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4019264"; Description = "May 2017 Windows 7 Security Update"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4038777"; Description = "September 2017 Security Monthly Quality Rollup"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4012598"; Description = "March 2017 Security Monthly Quality Rollup"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4018466"; Description = "April 2017 Security Monthly Quality Rollup"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4015549"; Description = "April 2017 Security Update"; CVE = "Multiple"; Severity = "Critical"}
                @{HotFixID = "KB4015546"; Description = "April 2017 Security Only Quality Update"; CVE = "Multiple"; Severity = "Critical"}
            )
            
            # Create comprehensive OS details for JSON
            $legacyOSInfo = @{
                OSName = $osName
                OSVersion = $osVersion
                BuildNumber = $buildNumber
                IsEOLVersion = $true
                EOLStatus = "End-of-Life/End-of-Support"
                VulnerabilityLevel = "High"
                RecommendedAction = "Upgrade to a supported OS version"
                DetailedOSInfo = $osDetailedInfo
            }
            
            # Check each critical patch
            $missingPatches = @()
            $installedCriticalPatches = @()
            $missingCount = 0
            
            foreach ($patch in $criticalPatches) {
                $installedPatch = $hotfixes | Where-Object { $_.HotFixID -eq $patch.HotFixID }
                if (-not $installedPatch) {
                    Write-Output "Missing patch: $($patch.HotFixID) - $($patch.Description)"
                    $missingCount++
                    
                    # Enhanced missing patch details
                    $missingPatchDetails = $patch.Clone() # Clone to avoid modifying the original
                    $missingPatchDetails.Status = "Missing"
                    $missingPatchDetails.AffectedOS = $osName
                    $missingPatchDetails.CheckDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    
                    $missingPatches += $missingPatchDetails
                    
                    # Add individual findings for important missing patches
                    Add-Finding -CheckName "Missing Patch $($patch.HotFixID)" -Status "Fail" `
                        -Details "Missing $($patch.Description)" -Category "PatchManagement" `
                        -AdditionalInfo @{
                            PatchID = $patch.HotFixID
                            Description = $patch.Description
                            CVE = $patch.CVE
                            Severity = $patch.Severity
                            ExploitInTheWild = if ($patch.ExploitInTheWild) { $patch.ExploitInTheWild } else { $false }
                            OSVersion = $osVersion
                            OSName = $osName
                            BuildNumber = $buildNumber
                            RecommendedAction = "Install missing security patch immediately"
                        }
                } else {
                    # Capture details of installed critical patches
                    $installedPatchDetails = $patch.Clone() # Clone to avoid modifying the original
                    $installedPatchDetails.Status = "Installed"
                    $installedPatchDetails.InstalledOn = $installedPatch.InstalledOn
                    $installedPatchDetails.InstalledBy = $installedPatch.InstalledBy
                    $installedCriticalPatches += $installedPatchDetails
                }
            }
            
            # Create a summary finding with comprehensive JSON
            $criticalInfo = @{
                OSVersion = $osVersion
                OSName = $osName
                BuildNumber = $buildNumber
                CheckedPatchCount = $criticalPatches.Count
                MissingPatchCount = $missingCount
                InstalledCriticalPatchCount = $installedCriticalPatches.Count
                MissingPatches = $missingPatches
                InstalledCriticalPatches = $installedCriticalPatches
                VulnerabilityAssessment = @{
                    MissingCriticalSeverityCount = ($missingPatches | Where-Object {$_.Severity -eq "Critical"}).Count
                    MissingImportantSeverityCount = ($missingPatches | Where-Object {$_.Severity -eq "Important"}).Count
                    MissingWithKnownExploitsCount = ($missingPatches | Where-Object {$_.ExploitInTheWild -eq $true}).Count
                    HighestRiskMissingPatches = $missingPatches | Where-Object {$_.ExploitInTheWild -eq $true} | Select-Object HotFixID, Description, CVE
                    VulnerabilityScore = if ($missingCount -gt 0) {
                        if (($missingPatches | Where-Object {$_.ExploitInTheWild -eq $true}).Count -gt 0) { "Critical" }
                        elseif (($missingPatches | Where-Object {$_.Severity -eq "Critical"}).Count -gt 0) { "High" }
                        else { "Medium" }
                    } else { "Low" }
                }
                DetailedOSInfo = $legacyOSInfo
            }
            
            if ($missingCount -eq 0) {
                Write-Output "PASS: All critical patches are installed."
                Add-Finding -CheckName "Critical Patches" -Status "Pass" `
                    -Details "No missing critical patches." -Category "PatchManagement" `
                    -AdditionalInfo $criticalInfo
            }
            else {
                Write-Output "FAIL: $missingCount critical patches missing."
                Add-Finding -CheckName "Critical Patches" -Status "Fail" `
                    -Details "$missingCount critical patches missing." -Category "PatchManagement" `
                    -AdditionalInfo $criticalInfo
            }
        }
        else {
            # For modern OS versions, we'll just log the general patch status from above
            Write-Output "Modern OS detected, no specific patch list to check."
            
            # Still add OS information to findings
            Add-Finding -CheckName "OS Patch Status" -Status "Info" `
                -Details "Modern OS detected: $osName" -Category "PatchManagement" `
                -AdditionalInfo @{
                    OSInfo = $osDetailedInfo
                    OSAssessment = @{
                        IsLegacyOS = $false
                        IsFullyPatched = if ($recentPatches.Count -gt 0) { $true } else { $false }
                        LastPatchDate = ($hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
                        DaysSinceLastPatch = if (($hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn) {
                            [math]::Round(((Get-Date) - ($hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn).TotalDays, 2)
                        } else { $null }
                    }
                }
        }
    }
    catch {
        Write-Output "WARNING: Unable to check for specific OS patches: $_" 
        Add-Finding -CheckName "OS-Specific Patch Check" -Status "Warning" `
            -Details "Unable to check OS-specific patches: $($_.Exception.Message)" -Category "PatchManagement" `
            -AdditionalInfo @{
                Error = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
                StackTrace = $_.ScriptStackTrace
                OSCheckAttempted = $true
                PartialOSInfo = @{
                    ComputerName = $env:COMPUTERNAME
                    OSName = $(try { (Get-WmiObject -Class Win32_OperatingSystem).Caption } catch { "Unknown" })
                    OSVersion = $(try { (Get-WmiObject -Class Win32_OperatingSystem).Version } catch { "Unknown" })
                }
            }
    }
}
function Test-TimeConfiguration {
    Write-SectionHeader "Time Configuration"
    $currentDate = Get-Date
    Write-Output "Current Date: $($currentDate.ToString('yyyy-MM-dd'))"
    Write-Output "Current Time: $($currentDate.ToString('HH:mm:ss'))"
    
    $timeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
    $timeConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue
    if ($timeService -and $timeConfig) {
        $ntpServer = $timeConfig.NtpServer
        
        # Create additional info for JSON output
        $additionalInfo = @{
            CurrentDateTime = $currentDate.ToString('yyyy-MM-dd HH:mm:ss')
            TimeZone = [System.TimeZoneInfo]::Local.DisplayName
            TimeServiceStatus = $timeService.Status
            NtpServer = $ntpServer
            Type = $timeConfig.Type
        }
        
        # Try to get time sync status
        try {
            $syncInfo = w32tm /query /status | Out-String
            $additionalInfo.SyncInfo = $syncInfo
            
            # Extract last sync time if available
            if ($syncInfo -match "Last Successful Sync Time: (.+)") {
                $additionalInfo.LastSyncTime = $matches[1]
            }
        }
        catch {
            $additionalInfo.SyncInfo = "Failed to retrieve sync status"
        }
        
        if ($timeService.Status -eq "Running") {
            Write-Output "PASS: Windows Time service is running."
            Add-Finding -CheckName "Time Synchronization" -Status "Pass" `
                -Details "Time service running; NTP: $ntpServer" -Category "TimeConfig" `
                -AdditionalInfo $additionalInfo
        }
        else {
            Write-Output "FAIL: Windows Time service is not running."
            Add-Finding -CheckName "Time Synchronization" -Status "Fail" `
                -Details "Time service not running." -Category "TimeConfig" `
                -AdditionalInfo $additionalInfo
        }
        if (-not $ntpServer) {
            Write-Output "FAIL: NTP server not configured."
            Add-Finding -CheckName "NTP Configuration" -Status "Fail" `
                -Details "NTP server is missing." -Category "TimeConfig" `
                -AdditionalInfo $additionalInfo
        }
    }
}

function Test-AuditAndLogging {
    Write-SectionHeader "Audit & Logging Configuration"
    
    # Check registry-based audit settings
    Write-Output "Checking registry-based audit settings..."
    $auditSettings = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue
    
    # Initialize JSON-friendly audit details
    $auditDetails = @{
        RegistrySettingsFound = ($null -ne $auditSettings)
        AdvancedPolicyConfigured = $false
        CriticalCategoriesAudited = @{}
    }
    
    if ($auditSettings) {
        Write-Output "Audit settings found:"
        $auditSettings | Format-List | Out-String | Write-Output
        
        # Add registry settings to audit details
        $auditSettings.PSObject.Properties | Where-Object { 
            $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') 
        } | ForEach-Object {
            $auditDetails[$_.Name] = $_.Value
        }
    }
    else {
        Write-Output "FAIL: No audit settings configured."
        Add-Finding -CheckName "Audit Policy" -Status "Fail" `
            -Details "Audit policy not configured." -Category "AuditLogging" `
            -AdditionalInfo $auditDetails
    }
    
    Write-Output ""
    Write-Output "Retrieving advanced audit policy summary..."
    $advancedAuditPolicy = auditpol /get /category:* 2>$null
    
    # Parse audit policy output into structured data
    $parsedAuditPolicy = @{}
    
    if ($advancedAuditPolicy) {
        Write-Output "Advanced Audit Policy Summary:"
        $advancedAuditPolicy | Out-String | Write-Output
        $auditDetails.AdvancedPolicyConfigured = $true
        
        # Extract policy settings from output
        $currentCategory = ""
        $advancedAuditPolicy | ForEach-Object {
            $line = $_.Trim()
            if ($line -match "^[A-Za-z]") {
                # This looks like a category header
                if ($line -notmatch "^\s*Subcategory|^\s*Category|^\s*System|^Policy") {
                    $currentCategory = $line
                    $parsedAuditPolicy[$currentCategory] = @{}
                }
            }
            elseif ($line -match "^\s+(.+?)\s+(Success|Failure|Success and Failure|No Auditing)") {
                # This is a subcategory setting
                $subCategory = $matches[1].Trim()
                $setting = $matches[2].Trim()
                if ($currentCategory -and $subCategory) {
                    $parsedAuditPolicy[$currentCategory][$subCategory] = $setting
                }
            }
        }
        
        # Add parsed policy to audit details
        $auditDetails.ParsedAuditPolicy = $parsedAuditPolicy
    }
    else {
        Write-Output "No advanced audit policy settings found."
    }
    
    Write-Output ""
    Write-Output "Evaluating critical audit categories..."
    $criticalCategories = @("Account Logon", "Logon/Logoff", "Object Access")
    foreach ($cat in $criticalCategories) {
        $config = $advancedAuditPolicy | Select-String $cat
        $isConfigured = $config -match "Success|Failure"
        $auditDetails.CriticalCategoriesAudited[$cat] = $isConfigured
        
        if (-not $isConfigured) {
            Write-Output "FAIL: Audit policy for '$cat' not configured properly."
            Add-Finding -CheckName "Audit Policy: $cat" -Status "Fail" `
                -Details "$cat not audited." -Category "AuditLogging" `
                -AdditionalInfo @{
                    Category = $cat
                    AuditSetting = "Not Configured"
                    RecommendedSetting = "Success and Failure"
                }
        }
        else {
            Write-Output "PASS: '$cat' auditing is configured."
            
            # Extract the actual setting for this category
            $setting = "Unknown"
            if ($config -match "$cat.*(Success and Failure|Success|Failure|No Auditing)") {
                $setting = $matches[1]
            }
            
            Add-Finding -CheckName "Audit Policy: $cat" -Status "Pass" `
                -Details "$cat audited." -Category "AuditLogging" `
                -AdditionalInfo @{
                    Category = $cat
                    AuditSetting = $setting
                }
        }
    }
    
    # Add a summary finding with all audit details
    Add-Finding -CheckName "Audit Policy Summary" -Status "Info" `
        -Details "Overall audit policy assessment." -Category "AuditLogging" `
        -AdditionalInfo $auditDetails
}

function Test-EventLogForwarding {
    Write-SectionHeader "Event Log Forwarding"
    
    # Capture detailed WEF information for JSON output
    $wefDetails = @{
        Configured = $false
        SubscriptionManagerEntries = @()
        WinRMServiceStatus = $null
        CollectorServiceStatus = $null
    }
    
    # Check WEF subscription manager configuration
    $wefSettings = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -ErrorAction SilentlyContinue
    
    # Check service statuses related to WEF
    $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    $wecService = Get-Service -Name "Wecsvc" -ErrorAction SilentlyContinue
    
    $wefDetails.WinRMServiceStatus = $winrmService.Status
    $wefDetails.CollectorServiceStatus = $wecService.Status
    
    if ($wefSettings) {
        Write-Output "PASS: Windows Event Forwarding is configured."
        $wefSettings | Format-List
        
        # Extract subscription manager entries for JSON
        $wefDetails.Configured = $true
        
        # Process all properties that aren't PowerShell metadata
        $wefSettings.PSObject.Properties | Where-Object { 
            $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') 
        } | ForEach-Object {
            $wefDetails.SubscriptionManagerEntries += [PSCustomObject]@{
                Name = $_.Name
                Value = $_.Value
            }
        }
        
        Add-Finding -CheckName "WEF Configuration" -Status "Pass" `
            -Details "WEF is configured." -Category "AuditLogging" `
            -AdditionalInfo $wefDetails
    }
    else {
        Write-Output "FAIL: Windows Event Forwarding is not configured."
        Add-Finding -CheckName "WEF Configuration" -Status "Fail" `
            -Details "WEF not configured." -Category "AuditLogging" `
            -AdditionalInfo $wefDetails
    }
}

function Test-LAPS {
    Write-SectionHeader "Local Administrator Password Solution (LAPS)"
    
    # Initialize additional info for JSON
    $additionalInfo = @{
        LegacyLAPSInstalled = $false
        LegacyLAPSEnabled = $false
        ModernLAPSInstalled = $false
        LAPSSettings = @{}
    }
    
    # Check Legacy LAPS
    $lapsLegacy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
    if ($lapsLegacy) {
        Write-Output "Legacy LAPS configuration found."
        $lapsLegacy | Format-List
        
        # Add legacy LAPS settings to JSON
        $additionalInfo.LegacyLAPSInstalled = $true
        $additionalInfo.LegacyLAPSEnabled = ($lapsLegacy.AdmPwdEnabled -eq 1)
        
        # Add all legacy LAPS properties
        foreach ($property in $lapsLegacy.PSObject.Properties) {
            if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                $additionalInfo.LAPSSettings[$property.Name] = $property.Value
            }
        }
        
        if ($lapsLegacy.AdmPwdEnabled -eq 1) {
            Write-Output "PASS: Legacy LAPS is enabled."
        }
        else {
            Write-Output "FAIL: Legacy LAPS is installed but disabled."
        }
    }
    else {
        Write-Output "Legacy LAPS not installed."
    }
    
    # Check Modern LAPS
    $lapsPaths = @("HKLM:\Software\Microsoft\Policies\LAPS", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS")
    $lapsInstalled = $false
    $lapsConfig = $null
    
    foreach ($path in $lapsPaths) {
        $laps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($laps) { 
            $lapsInstalled = $true
            $lapsConfig = $laps
            $additionalInfo.ModernLAPSInstalled = $true
            
            # Add modern LAPS settings
            foreach ($property in $laps.PSObject.Properties) {
                if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    $additionalInfo.LAPSSettings["Modern_" + $property.Name] = $property.Value
                }
            }
            
            break
        }
    }
    
    # Add LAPS status to findings
    if ($lapsInstalled) {
        Write-Output "Modern LAPS configuration found."
        $lapsConfig | Format-List
    }
    elseif (-not $lapsLegacy) {
        Write-Output "FAIL: No version of LAPS installed."
    }
}

function Test-CredentialProtection {
    Write-SectionHeader "Credential Protection"
    
    # Initialize additional info for JSON
    $lsaProtectionInfo = @{
        Registry = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
        SettingName = "RunAsPPL"
        RecommendedValue = 1
        Description = "Protects LSA process from code injection and credential theft"
    }
    
    $credGuardInfo = @{
        Registry = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
        SettingName = "LsaCfgFlags"
        RecommendedValues = @(1, 2)
        Description = "Isolates and hardens credential storage"
    }
    
    $wdigestInfo = @{
        Registry = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        SettingName = "UseLogonCredential"
        RecommendedValue = 0
        Description = "Controls storage of plaintext credentials in memory"
    }
    
    # Check LSA Protection
    $lsaProtection = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    $lsaProtectionInfo.ActualValue = $lsaProtection
    
    if ($lsaProtection -eq 1) {
        Write-Output "PASS: LSA Protection enabled."
        Add-Finding -CheckName "LSA Protection" -Status "Pass" `
            -Details "LSA Protection is enabled." -Category "CredProtection" `
            -AdditionalInfo $lsaProtectionInfo
    }
    else {
        Write-Output "FAIL: LSA Protection not enabled."
        Add-Finding -CheckName "LSA Protection" -Status "Fail" `
            -Details "LSA Protection is disabled." -Category "CredProtection" `
            -AdditionalInfo $lsaProtectionInfo
    }
    
    # Check Credential Guard
    $credGuard = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
    $credGuardInfo.ActualValue = $credGuard
    
    if ($credGuard -eq 1 -or $credGuard -eq 2) {
        Write-Output "PASS: Credential Guard is enabled."
        Add-Finding -CheckName "Credential Guard" -Status "Pass" `
            -Details "Credential Guard is enabled." -Category "CredProtection" `
            -AdditionalInfo $credGuardInfo
    }
    else {
        Write-Output "FAIL: Credential Guard not enabled."
        Add-Finding -CheckName "Credential Guard" -Status "Fail" `
            -Details "Credential Guard is disabled." -Category "CredProtection" `
            -AdditionalInfo $credGuardInfo
    }
    
    # Check WDigest
    $wdigest = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    $wdigestInfo.ActualValue = $wdigest
    
    if ($wdigest -eq 1) {
        Write-Output "FAIL: WDigest enabled (plain-text credentials)."
        Add-Finding -CheckName "WDigest" -Status "Fail" `
            -Details "WDigest authentication is enabled." -Category "CredProtection" `
            -AdditionalInfo $wdigestInfo
    }
    else {
        Write-Output "PASS: WDigest disabled."
        Add-Finding -CheckName "WDigest" -Status "Pass" `
            -Details "WDigest is disabled." -Category "CredProtection" `
            -AdditionalInfo $wdigestInfo
    }
}

function Test-CachedCredentials {
    Write-SectionHeader "Cached Credentials"
    
    # Get cached credential count
    $cachedCreds = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT" -ErrorAction SilentlyContinue).CACHEDLOGONSCOUNT
    $cachedCount = [int]$cachedCreds
    
    # Create additional info for JSON output
    $additionalInfo = @{
        RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        SettingName = "CACHEDLOGONSCOUNT"
        ActualValue = $cachedCount
        RecommendedValue = 0
        Description = "Controls how many previous logons are cached locally for offline use"
        SecurityRisk = "Higher values increase the risk of credential theft via tools like Mimikatz"
    }
    
    # Check for domain cached credentials (MSCACHE v2 hashes)
    $securelySavedMsg = "Note: Cached credentials are securely saved as MSCACHE v2 hashes in the registry."
    $howToViewMsg = "These cannot be directly viewed but can be extracted with admin privileges using specialized tools."

    Write-Output "Cached domain logon count: $cachedCount"
    Write-Output $securelySavedMsg
    Write-Output $howToViewMsg
    
    # Add security assessment
    if ($cachedCount -gt 4) {
        Write-Output "FAIL: Excessive cached credentials ($cachedCount). Recommended maximum: 4"
        Write-Output "      This increases credential theft risk in case of system compromise."
        Add-Finding -CheckName "Cached Credentials" -Status "Fail" `
            -Details "Excessive cached credentials: $cachedCount" -Category "AuthControls" `
            -AdditionalInfo $additionalInfo
    }
    elseif ($cachedCount -gt 0) {
        Write-Output "WARNING: Cached credentials present: $cachedCount"
        Write-Output "         Consider reducing to 0 for high-security systems."
        Add-Finding -CheckName "Cached Credentials" -Status "Warning" `
            -Details "Cached credentials present: $cachedCount" -Category "AuthControls" `
            -AdditionalInfo $additionalInfo
    }
    else {
        Write-Output "PASS: No cached credentials."
        Add-Finding -CheckName "Cached Credentials" -Status "Pass" `
            -Details "No cached credentials." -Category "AuthControls" `
            -AdditionalInfo $additionalInfo
    }
    
    # Additional information about security implications
    Write-Output "Security Note: Cached credentials help users log in when domain controllers are unavailable,"
    Write-Output "               but they increase the risk of credential theft in case of system compromise."
    Write-Output "Recommendation: Set to 0-2 based on your organization's security requirements and user needs."
}

function Test-UserAccountSecurity {
    Write-SectionHeader "User Account Security"

    # Retrieve all local user accounts with relevant details
    Write-Output "All User Accounts:"
    $allAccounts = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, Description
    $allAccounts | Format-Table -AutoSize

    # Build detailed account JSON records
    $accountInfo = $allAccounts | ForEach-Object {
        @{
            Name = $_.Name
            Enabled = $_.Enabled
            LastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            PasswordRequired = $_.PasswordRequired
            PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
            Description = $_.Description
        }
    }

    Add-Finding -CheckName "User Accounts" -Status "Info" `
        -Details "$($allAccounts.Count) local user accounts found." -Category "UserSecurity" `
        -AdditionalInfo @{
            AccountCount = $allAccounts.Count
            Accounts     = $accountInfo
        }

    # Identify accounts with blank passwords (PasswordRequired = $false)
    $blankPasswordAccounts = $allAccounts | Where-Object { $_.PasswordRequired -eq $false }
    if ($blankPasswordAccounts.Count -gt 0) {
        Write-Output "FAIL: Accounts with blank passwords found:"
        $blankPasswordAccounts | Format-Table Name, Enabled -AutoSize

        $blankPasswordDetails = $blankPasswordAccounts | ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                Description = $_.Description
            }
        }

        Add-Finding -CheckName "Blank Passwords" -Status "Fail" `
            -Details "$($blankPasswordAccounts.Count) accounts have blank passwords." -Category "UserSecurity" `
            -AdditionalInfo @{
                AccountCount = $blankPasswordAccounts.Count
                Accounts     = $blankPasswordDetails
            }
    } else {
        Write-Output "PASS: No accounts with blank passwords."
        Add-Finding -CheckName "Blank Passwords" -Status "Pass" `
            -Details "No blank passwords found." -Category "UserSecurity"
    }

    # Password complexity check from registry
    $passwordPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue
    $complexityEnabled = $passwordPolicy.RequireComplexPasswords -eq 1

    if ($passwordPolicy -and $complexityEnabled) {
        Write-Output "PASS: Password complexity requirements enabled."
        Add-Finding -CheckName "Password Complexity" -Status "Pass" `
            -Details "Password complexity requirements are enabled." -Category "UserSecurity" `
            -AdditionalInfo @{
                RequireComplexPasswords = $passwordPolicy.RequireComplexPasswords
                RegistryPath            = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            }
    } else {
        Write-Output "FAIL: Password complexity requirements not enabled."
        Add-Finding -CheckName "Password Complexity" -Status "Fail" `
            -Details "Password complexity requirements are not enabled." -Category "UserSecurity" `
            -AdditionalInfo @{
                RequireComplexPasswords = if ($passwordPolicy) { $passwordPolicy.RequireComplexPasswords } else { $null }
                RegistryPath            = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            }
    }

    # Report login information for all accounts
    Write-Output "Account Login Information:"
    $accountLoginInfo = $allAccounts | Sort-Object LastLogon
    $accountLoginInfo | Format-Table Name, Enabled, LastLogon -AutoSize

    # Accounts that have never logged in
    $neverLoggedIn = $accountLoginInfo | Where-Object { -not $_.LastLogon }
    if ($neverLoggedIn.Count -gt 0) {
        Write-Output "INFO: Accounts that have never logged in:"
        $neverLoggedIn | Format-Table Name, Enabled -AutoSize

        $neverLoggedInDetails = $neverLoggedIn | ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                Description = $_.Description
            }
        }

        Add-Finding -CheckName "Account Login History" -Status "Info" `
            -Details "$($neverLoggedIn.Count) accounts have never logged in." -Category "UserSecurity" `
            -AdditionalInfo @{
                AccountCount = $neverLoggedIn.Count
                Accounts     = $neverLoggedInDetails
            }
    }

    # Check administrator accounts
    $adminAccounts = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($adminAccounts) {
        Write-Output "Found $($adminAccounts.Count) administrator accounts:"
        $adminAccounts | Format-Table Name, ObjectClass -AutoSize

        $adminAccountDetails = $adminAccounts | ForEach-Object {
            @{
                Name = $_.Name.ToString()
                ObjectClass = $_.ObjectClass
                PrincipalSource = if ($_.PrincipalSource) { $_.PrincipalSource.ToString() } else { "Unknown" }
            }
        }

        Add-Finding -CheckName "Admin Accounts" -Status "Info" `
            -Details "$($adminAccounts.Count) administrator accounts found." -Category "UserSecurity" `
            -AdditionalInfo @{
                AdminCount = $adminAccounts.Count
                Accounts   = $adminAccountDetails
            }
    } else {
        Write-Output "Unable to retrieve administrator accounts."
        Add-Finding -CheckName "Admin Accounts" -Status "Warning" `
            -Details "Unable to retrieve administrator accounts." -Category "UserSecurity"
    }
}

function Test-AuthenticationControls {
    Write-SectionHeader "Authentication & User Controls"
    $cachedCreds = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT" -ErrorAction SilentlyContinue).CACHEDLOGONSCOUNT
    $cachedCount = [int]$cachedCreds
    Write-Output "Cached Credentials: $cachedCount"
    
    # Create additional info for JSON output
    $cachedCredsInfo = @{
        RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        SettingName = "CACHEDLOGONSCOUNT"
        ActualValue = $cachedCount
        RecommendedValue = 1
        Description = "Controls how many previous logons are cached locally for offline use"
    }
    
    if ($cachedCount -le 1) {
        Add-Finding -CheckName "Cached Credentials" -Status "Pass" `
            -Details "Cached credentials count: $cachedCount" -Category "AuthControls" `
            -AdditionalInfo $cachedCredsInfo
    }
    else {
        Add-Finding -CheckName "Cached Credentials" -Status "Fail" `
            -Details "Too many cached credentials ($cachedCount)." -Category "AuthControls" `
            -AdditionalInfo $cachedCredsInfo
    }
    
    # UAC Enabled check
    $uac = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    
    $uacInfo = @{
        RegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        SettingName = "EnableLUA"
        ActualValue = $uac
        RecommendedValue = 1
        Description = "Controls whether User Account Control is enabled"
    }
    
    if ($uac -eq 1) {
        Write-Output "PASS: UAC enabled."
        Add-Finding -CheckName "User Account Control" -Status "Pass" `
            -Details "UAC is enabled." -Category "AuthControls" `
            -AdditionalInfo $uacInfo
    }
    else {
        Write-Output "FAIL: UAC disabled."
        Add-Finding -CheckName "User Account Control" -Status "Fail" `
            -Details "UAC is disabled." -Category "AuthControls" `
            -AdditionalInfo $uacInfo
    }
    
    # UAC Prompt Behavior check
    $uacPrompt = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    
    $uacPromptInfo = @{
        RegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        SettingName = "ConsentPromptBehaviorAdmin"
        ActualValue = $uacPrompt
        RecommendedValue = "2 (Prompt for consent on the secure desktop)"
        Description = "Controls UAC elevation prompt behavior for administrators"
        ValueMeaning = @{
            0 = "Elevate without prompting (not recommended)"
            1 = "Prompt for credentials on the secure desktop"
            2 = "Prompt for consent on the secure desktop"
            3 = "Prompt for credentials"
            4 = "Prompt for consent"
            5 = "Prompt for consent for non-Windows binaries"
        }
    }
    
    if ($uacPrompt -ne 0) {
        Write-Output "PASS: UAC prompt configured properly."
        Add-Finding -CheckName "UAC Prompt Behavior" -Status "Pass" `
            -Details "UAC prompt behavior: $uacPrompt" -Category "AuthControls" `
            -AdditionalInfo $uacPromptInfo
    }
    else {
        Write-Output "FAIL: UAC elevates without prompting."
        Add-Finding -CheckName "UAC Prompt Behavior" -Status "Fail" `
            -Details "UAC is configured to elevate without prompting." -Category "AuthControls" `
            -AdditionalInfo $uacPromptInfo
    }
}

function Test-UnquotedServicePaths {
    Write-SectionHeader "File System Security: Unquoted Service Paths"

    $vulnerableServices = @()

    # Retrieve all services that have a defined PathName containing a space
    $services = Get-WmiObject -Class Win32_Service | Where-Object { 
        $_.PathName -and $_.PathName -match " "
    }

    foreach ($svc in $services) {
        $path = $svc.PathName.Trim()
        
        # Skip if the path is already quoted
        if ($path.StartsWith('"')) {
            continue
        }

        # Extract the executable part (first token up to the first space)
        $exePath = $path.Split(" ")[0].Trim('"')

        # Check if the executable file exists
        if (-not (Test-Path $exePath)) {
            continue
        }

        # Exclude services with executables in trusted directories (adjust whitelist as needed)
        if ($exePath -match "^(C:\\Windows\\|C:\\Program Files\\)") {
            continue
        }

        # If we reach here, consider the service potentially vulnerable
        $vulnerableServices += $svc
    }

    # Create detailed service information for JSON output
    $vulnerableServiceDetails = $vulnerableServices | ForEach-Object {
        @{
            Name = $_.Name
            DisplayName = $_.DisplayName
            PathName = $_.PathName
            StartMode = $_.StartMode
            State = $_.State
            StartName = $_.StartName
            Description = $_.Description
        }
    }

    if ($vulnerableServices.Count -gt 0) {
        Write-Output "FAIL: Services with potentially vulnerable unquoted paths found:"
        $vulnerableServices | Select-Object Name, DisplayName, PathName | Format-Table -AutoSize
        Add-Finding -CheckName "Unquoted Service Paths" -Status "Fail" `
            -Details "$($vulnerableServices.Count) services have potentially vulnerable unquoted paths." -Category "FileSystemSecurity" `
            -AdditionalInfo @{
                VulnerableServiceCount = $vulnerableServices.Count
                VulnerableServices = $vulnerableServiceDetails
                Explanation = "Unquoted service paths could allow privilege escalation if spaces exist in the path and an attacker has write access to directories in that path."
                Remediation = "Modify service path by enclosing the entire path within double quotes."
            }
    }
    else {
        Write-Output "PASS: No vulnerable services with unquoted paths found."
        Add-Finding -CheckName "Unquoted Service Paths" -Status "Pass" `
            -Details "No vulnerable unquoted service paths found." -Category "FileSystemSecurity" `
            -AdditionalInfo @{
                ServicesChecked = $services.Count
                Explanation = "Services with spaces in their execution paths have been properly quoted, preventing potential path hijacking attacks."
            }
    }
}

function Test-DirectoryPermissions {
    Write-SectionHeader "File System Security: Directory Permissions"
    
    # Initialize comprehensive object for JSON output
    $directorySecurityInfo = @{
        ProgramDirectories = @()
        SystemDirectories = @()
        VulnerableDirectoryCount = 0
        TotalDirectoriesChecked = 0
        SecurityRisks = @()
    }
    
    # Check permissions on Program Files directories
    $programPaths = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}")
    foreach ($path in $programPaths) {
        if (Test-Path $path) {
            $directorySecurityInfo.TotalDirectoriesChecked++
            
            # Create detailed directory info object
            $dirInfo = @{
                Path = $path
                DirectoryExists = $true
                LastWriteTime = (Get-Item -Path $path).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                CreationTime = (Get-Item -Path $path).CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                HasExcessivePermissions = $false
                ProblematicAccounts = @()
                AllPermissions = @()
                DirectoryType = "ProgramFiles"
            }
            
            try {
                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                
                if ($acl) {
                    # Get detailed information about each ACE (Access Control Entry)
                    foreach ($ace in $acl.Access) {
                        $aceDetails = @{
                            IdentityReference = $ace.IdentityReference.ToString()
                            FileSystemRights = $ace.FileSystemRights.ToString()
                            AccessControlType = $ace.AccessControlType.ToString()
                            IsInherited = $ace.IsInherited
                            InheritanceFlags = $ace.InheritanceFlags.ToString()
                            PropagationFlags = $ace.PropagationFlags.ToString()
                        }
                        
                        # Add to all permissions collection
                        $dirInfo.AllPermissions += $aceDetails
                        
                        # Check if this is a problematic permission
                        if (($ace.IdentityReference -match "Everyone|EVERYONE|Authenticated Users|Users|USERS") -and 
                            ($ace.FileSystemRights -match "Write|Modify|FullControl|TakeOwnership|ChangePermissions")) {
                            $dirInfo.HasExcessivePermissions = $true
                            $dirInfo.ProblematicAccounts += @{
                                Account = $ace.IdentityReference.ToString()
                                Rights = $ace.FileSystemRights.ToString()
                                AccessType = $ace.AccessControlType.ToString()
                            }
                        }
                    }
                    
                    # Add owner information
                    $dirInfo.Owner = $acl.Owner
                    
                    # Check if directory is writable by current user as an additional test
                    $dirInfo.IsWritableByCurrentUser = Test-WritablePermission -Path $path -Type "File"
                }
            } catch {
                $dirInfo.Error = $_.Exception.Message
                $dirInfo.ErrorType = $_.Exception.GetType().Name
                $dirInfo.AllPermissions = @()
            }
            
            # Add directory info to the collection
            $directorySecurityInfo.ProgramDirectories += $dirInfo
            
            # Output results and create findings
            if ($dirInfo.HasExcessivePermissions) {
                $directorySecurityInfo.VulnerableDirectoryCount++
                
                # Add to security risks if not already present
                $riskMessage = "Program Files directory with excessive permissions allows non-administrators to modify application files"
                if ($riskMessage -notin $directorySecurityInfo.SecurityRisks) {
                    $directorySecurityInfo.SecurityRisks += $riskMessage
                }
                
                Write-Output "FAIL: $path has excessive permissions for Everyone or Authenticated Users."
                Add-Finding -CheckName "Program Files Permissions" -Status "Fail" `
                    -Details "$path has write access for non-administrative users." -Category "FileSystemSecurity" `
                    -AdditionalInfo @{
                        Path = $path
                        DirectoryType = "ProgramFiles"
                        ExcessivePermissions = $true
                        ProblematicAccounts = ($dirInfo.ProblematicAccounts | ForEach-Object { $_.Account }) -join ", "
                        Owner = $dirInfo.Owner
                        AllPermissions = $dirInfo.AllPermissions
                        IsWritableByCurrentUser = $dirInfo.IsWritableByCurrentUser
                        LastModified = $dirInfo.LastWriteTime
                        SecurityRisk = "Allows non-administrative users to potentially modify application files, enabling privilege escalation or malware persistence"
                        Recommendation = "Remove write/modify permissions for non-administrative users and groups"
                    }
            } else {
                Write-Output "PASS: $path has appropriate permissions."
                Add-Finding -CheckName "Program Files Permissions" -Status "Pass" `
                    -Details "$path has appropriate permissions." -Category "FileSystemSecurity" `
                    -AdditionalInfo @{
                        Path = $path
                        DirectoryType = "ProgramFiles"
                        ExcessivePermissions = $false
                        Owner = $dirInfo.Owner
                        AllPermissions = $dirInfo.AllPermissions
                        IsWritableByCurrentUser = $dirInfo.IsWritableByCurrentUser
                        LastModified = $dirInfo.LastWriteTime
                    }
            }
        } else {
            Write-Output "WARNING: $path does not exist."
            $directorySecurityInfo.TotalDirectoriesChecked++
            $directorySecurityInfo.ProgramDirectories += @{
                Path = $path
                DirectoryExists = $false
                DirectoryType = "ProgramFiles"
                Error = "Directory does not exist"
            }
            
            Add-Finding -CheckName "Program Files Path" -Status "Warning" `
                -Details "$path directory not found." -Category "FileSystemSecurity" `
                -AdditionalInfo @{
                    Path = $path
                    DirectoryExists = $false
                    DirectoryType = "ProgramFiles"
                    PossibleCauses = @(
                        "Custom Windows installation",
                        "Environment variable misconfiguration",
                        "Directory deletion or corruption"
                    )
                }
        }
    }
    
    # Check for world-writable folders in system paths with enhanced details
    $systemPaths = @($env:windir, "$env:windir\System32", "$env:windir\System32\drivers")
    foreach ($path in $systemPaths) {
        if (Test-Path $path) {
            $directorySecurityInfo.TotalDirectoriesChecked++
            
            # Create detailed directory info object
            $dirInfo = @{
                Path = $path
                DirectoryExists = $true
                LastWriteTime = (Get-Item -Path $path).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                CreationTime = (Get-Item -Path $path).CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                HasExcessivePermissions = $false
                ProblematicAccounts = @()
                AllPermissions = @()
                DirectoryType = "SystemDirectory"
                Criticality = "High"
            }
            
            try {
                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                
                if ($acl) {
                    # Get detailed information about each ACE
                    foreach ($ace in $acl.Access) {
                        $aceDetails = @{
                            IdentityReference = $ace.IdentityReference.ToString()
                            FileSystemRights = $ace.FileSystemRights.ToString()
                            AccessControlType = $ace.AccessControlType.ToString()
                            IsInherited = $ace.IsInherited
                            InheritanceFlags = $ace.InheritanceFlags.ToString()
                            PropagationFlags = $ace.PropagationFlags.ToString()
                        }
                        
                        # Add to all permissions collection
                        $dirInfo.AllPermissions += $aceDetails
                        
                        # Check if this is a problematic permission
                        if (($ace.IdentityReference -match "Everyone|EVERYONE|Authenticated Users|Users|USERS") -and 
                            ($ace.FileSystemRights -match "Write|Modify|FullControl|TakeOwnership|ChangePermissions")) {
                            $dirInfo.HasExcessivePermissions = $true
                            $dirInfo.ProblematicAccounts += @{
                                Account = $ace.IdentityReference.ToString()
                                Rights = $ace.FileSystemRights.ToString()
                                AccessType = $ace.AccessControlType.ToString()
                            }
                        }
                    }
                    
                    # Add owner information
                    $dirInfo.Owner = $acl.Owner
                    
                    # Check if directory is writable by current user as an additional test
                    $dirInfo.IsWritableByCurrentUser = Test-WritablePermission -Path $path -Type "File"
                }
            } catch {
                $dirInfo.Error = $_.Exception.Message
                $dirInfo.ErrorType = $_.Exception.GetType().Name
                $dirInfo.AllPermissions = @()
            }
            
            # Add directory info to the collection
            $directorySecurityInfo.SystemDirectories += $dirInfo
            
            # Output results and create findings
            if ($dirInfo.HasExcessivePermissions) {
                $directorySecurityInfo.VulnerableDirectoryCount++
                
                # Add to security risks if not already present
                $riskMessage = "System directory with excessive permissions allows potential system compromise"
                if ($riskMessage -notin $directorySecurityInfo.SecurityRisks) {
                    $directorySecurityInfo.SecurityRisks += $riskMessage
                }
                
                Write-Output "FAIL: $path has excessive permissions."
                Add-Finding -CheckName "System Directory Permissions" -Status "Fail" `
                    -Details "$path has write access for non-administrative users." -Category "FileSystemSecurity" `
                    -AdditionalInfo @{
                        Path = $path
                        DirectoryType = "SystemDirectory"
                        ExcessivePermissions = $true
                        ProblematicAccounts = ($dirInfo.ProblematicAccounts | ForEach-Object { $_.Account }) -join ", "
                        Owner = $dirInfo.Owner
                        AllPermissions = $dirInfo.AllPermissions
                        IsWritableByCurrentUser = $dirInfo.IsWritableByCurrentUser
                        LastModified = $dirInfo.LastWriteTime
                        Criticality = "High"
                        SecurityRisk = "Allows non-administrative users to modify system files, enabling privilege escalation, malware persistence, or system compromise"
                        Recommendation = "Remove all write/modify permissions for non-administrative users and groups from system directories"
                        RemediationSteps = @(
                            "Reset permissions with icacls $path /reset",
                            "Apply proper permissions with icacls $path /inheritance:r",
                            "Grant appropriate permissions with icacls $path /grant SYSTEM:(OI)(CI)F Administrators:(OI)(CI)F"
                        )
                    }
            } else {
                Write-Output "PASS: $path has appropriate permissions."
                Add-Finding -CheckName "System Directory Permissions" -Status "Pass" `
                    -Details "$path has appropriate permissions." -Category "FileSystemSecurity" `
                    -AdditionalInfo @{
                        Path = $path
                        DirectoryType = "SystemDirectory"
                        ExcessivePermissions = $false
                        Owner = $dirInfo.Owner
                        AllPermissions = $dirInfo.AllPermissions
                        IsWritableByCurrentUser = $dirInfo.IsWritableByCurrentUser
                        LastModified = $dirInfo.LastWriteTime
                        Criticality = "High"
                        NormalConfiguration = "System directories should only be modifiable by SYSTEM and Administrators"
                    }
            }
        } else {
            Write-Output "CRITICAL: $path does not exist."
            $directorySecurityInfo.TotalDirectoriesChecked++
            $directorySecurityInfo.SystemDirectories += @{
                Path = $path
                DirectoryExists = $false
                DirectoryType = "SystemDirectory"
                Error = "Critical system directory does not exist"
                Criticality = "High"
                LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                AssessmentHost = $env:COMPUTERNAME
                CheckPerformedBy = $env:USERNAME
            }
            
            Add-Finding -CheckName "System Directory Existence" -Status "Fail" `
                -Details "Critical system directory not found: $path" -Category "FileSystemSecurity" `
                -AdditionalInfo @{
                    Path = $path
                    DirectoryExists = $false
                    DirectoryType = "SystemDirectory"
                    Criticality = "High"
                    SecurityImplication = "Missing system directories indicate system corruption or tampering"
                    RecommendedAction = "Verify system integrity and consider system recovery or reinstallation"
                    PossibleCauses = @(
                        "System corruption",
                        "Malware activity",
                        "Unauthorized system modification",
                        "Failed update or installation"
                    )
                    DetectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    OperatingSystem = (Get-WmiObject Win32_OperatingSystem).Caption
                    OperatingSystemVersion = (Get-WmiObject Win32_OperatingSystem).Version
                }
        }
    }
    
    # Add comprehensive directory security summary finding
    Add-Finding -CheckName "Directory Permissions Summary" -Status "Info" `
        -Details "Checked $($directorySecurityInfo.TotalDirectoriesChecked) directories, found $($directorySecurityInfo.VulnerableDirectoryCount) with excessive permissions" `
        -Category "FileSystemSecurity" `
        -AdditionalInfo @{
            DirectorySecurity = $directorySecurityInfo
            AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            AssessmentHostname = $env:COMPUTERNAME
            CheckedDirectories = $directorySecurityInfo.TotalDirectoriesChecked
            VulnerableDirectories = $directorySecurityInfo.VulnerableDirectoryCount
            ProgramDirectoriesDetails = $directorySecurityInfo.ProgramDirectories
            SystemDirectoriesDetails = $directorySecurityInfo.SystemDirectories
            SecurityRisks = $directorySecurityInfo.SecurityRisks
            RecommendedRemediation = @{
                Actions = @(
                    "Reset permissions on vulnerable directories",
                    "Apply principle of least privilege",
                    "Configure proper group policies for directory permissions"
                )
                CommandExamples = @{
                    ResetPermissions = "icacls [path] /reset"
                    RemoveInheritance = "icacls [path] /inheritance:r"
                    SetAdminPermissions = "icacls [path] /grant Administrators:(OI)(CI)F"
                }
            }
        }
}

function Test-PowerShellSecurity {
    Write-SectionHeader "PowerShell Security"
    
    # Initialize comprehensive object for JSON output
    $psSecurityInfo = @{
        PowerShellVersions = @{}
        PowerShellV2Status = $false
        CurrentSessionDetails = @{
            PSVersion = $PSVersionTable.PSVersion.ToString()
            PSEdition = $PSVersionTable.PSEdition
            PSCompatibleVersions = ($PSVersionTable.PSCompatibleVersions | ForEach-Object { $_.ToString() })
            BuildVersion = $PSVersionTable.BuildVersion.ToString()
            PSRemotingProtocolVersion = $PSVersionTable.PSRemotingProtocolVersion.ToString()
            SerializationVersion = $PSVersionTable.SerializationVersion.ToString()
            WSManStackVersion = if ($PSVersionTable.WSManStackVersion) { $PSVersionTable.WSManStackVersion.ToString() } else { $null }
            PSHost = @{
                Name = $Host.Name
                Version = $Host.Version.ToString()
                InstanceId = $Host.InstanceId.ToString()
                CurrentCulture = $Host.CurrentCulture.Name
                CurrentUICulture = $Host.CurrentUICulture.Name
            }
            ExecutionContextDetails = @{
                LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
                InitialSessionState = if ($ExecutionContext.InitialSessionState) { $true } else { $false }
                RunspaceId = $ExecutionContext.Host.Runspace.Id.ToString()
                EngineVersion = $ExecutionContext.EngineVersion.ToString()
            }
        }
        LoggingConfiguration = @{
            TranscriptionEnabled = $false
            ModuleLoggingEnabled = $false
            ScriptBlockLoggingEnabled = $false
            TranscriptionSettings = @{}
            ModuleLoggingSettings = @{}
            ScriptBlockLoggingSettings = @{}
            EventLogConfiguration = @{}
        }
        ExecutionPolicy = @{}
        LanguageMode = $null
        AMSIIntegration = @{
            Available = $false
            DllDetails = $null
            AMSIProviders = @()
        }
        SecurityMitigations = @{
            ConstrainedLanguageModeEnabled = $false
            ExecutionPolicyEnforcement = $false
            ScriptBlockLoggingEnabled = $false
            PowerShellVersionRestrictions = $false
            JEAImplemented = $false
        }
        SecurityRecommendations = @()
        RawRegistrySettings = @{
            Transcription = $null
            ModuleLogging = $null
            ScriptBlockLogging = $null
        }
    }
    
    # Check PowerShell versions
    $psVersions = @(
        [PSCustomObject]@{ Path = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine"; Label = "v2"; ExpectedVersion = "2.0" },
        [PSCustomObject]@{ Path = "HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine"; Label = "v5"; ExpectedVersion = "5.0" }
    )
    
    foreach ($ver in $psVersions) {
        try {
            $versionInfo = Get-ItemProperty -Path $ver.Path -ErrorAction SilentlyContinue
            if ($versionInfo) {
                $version = $versionInfo.PowerShellVersion
                Write-Output "PowerShell $($ver.Label): $version"
                $psSecurityInfo.PowerShellVersions[$ver.Label] = @{
                    Version = $version
                    RuntimeVersion = $versionInfo.RuntimeVersion
                    ConsoleHostAssemblyName = $versionInfo.ConsoleHostAssemblyName
                    PSCompatibleVersion = $versionInfo.PSCompatibleVersion
                    BuildVersion = $versionInfo.BuildVersion
                    InstallDate = if (Test-Path (Join-Path (Split-Path $ver.Path) "Install-Date")) {
                        (Get-ItemProperty -Path (Join-Path (Split-Path $ver.Path) "Install-Date") -ErrorAction SilentlyContinue).Date
                    } else { $null }
                    RegistryPath = $ver.Path
                    RegistryProperties = ($versionInfo.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } | ForEach-Object { $_.Name })
                }
            } else {
                $psSecurityInfo.PowerShellVersions[$ver.Label] = @{
                    Version = "Not installed or accessible"
                    RegistryPath = $ver.Path
                    Exists = $false
                }
            }
        }
        catch {
            $psSecurityInfo.PowerShellVersions[$ver.Label] = @{
                Version = "Error retrieving version"
                Error = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
                StackTrace = $_.ScriptStackTrace
                RegistryPath = $ver.Path
                Exists = $false
            }
        }
    }
    
    # Add current PowerShell version information
    $currentVersion = $PSVersionTable
    if ($currentVersion) {
        $psSecurityInfo.PowerShellVersions["Current"] = @{
            PSVersion = $currentVersion.PSVersion.ToString()
            PSEdition = $currentVersion.PSEdition
            CLRVersion = if ($currentVersion.CLRVersion) { $currentVersion.CLRVersion.ToString() } else { $null }
            BuildVersion = $currentVersion.BuildVersion.ToString()
            WSManStackVersion = if ($currentVersion.WSManStackVersion) { $currentVersion.WSManStackVersion.ToString() } else { $null }
            PSRemotingProtocolVersion = if ($currentVersion.PSRemotingProtocolVersion) { $currentVersion.PSRemotingProtocolVersion.ToString() } else { $null }
            SerializationVersion = if ($currentVersion.SerializationVersion) { $currentVersion.SerializationVersion.ToString() } else { $null }
            GitCommitId = if ($currentVersion.GitCommitId) { $currentVersion.GitCommitId } else { $null }
            PSCompatibleVersions = if ($currentVersion.PSCompatibleVersions) { 
                $currentVersion.PSCompatibleVersions | ForEach-Object { $_.ToString() } 
            } else { $null }
        }
    }
    
    # Check if PowerShell v2 is enabled
    try {
        $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
        $psv2Root = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
        
        if ($psv2Feature -or $psv2Root) {
            $psv2Enabled = $null -ne ($psv2Feature | Where-Object { $_.State -eq "Enabled" }) -or
                         $null -ne ($psv2Root | Where-Object { $_.State -eq "Enabled" })
            
            $psSecurityInfo.PowerShellV2Status = $psv2Enabled
            $psSecurityInfo.PowerShellV2Feature = @{
                FeatureName = if ($psv2Feature) { $psv2Feature.FeatureName } else { $psv2Root.FeatureName }
                DisplayName = if ($psv2Feature) { $psv2Feature.DisplayName } else { $psv2Root.DisplayName }
                State = if ($psv2Feature) { $psv2Feature.State.ToString() } else { $psv2Root.State.ToString() }
                CustomProperties = if ($psv2Feature) {
                    ($psv2Feature.PSObject.Properties | Where-Object { $_.Name -notin @('FeatureName', 'State', 'DisplayName') } | ForEach-Object { 
                        @{ $_.Name = $_.Value } 
                    })
                } else {
                    ($psv2Root.PSObject.Properties | Where-Object { $_.Name -notin @('FeatureName', 'State', 'DisplayName') } | ForEach-Object { 
                        @{ $_.Name = $_.Value } 
                    })
                }
                V2FeaturePresent = $null -ne $psv2Feature
                V2RootFeaturePresent = $null -ne $psv2Root
            }
        } else {
            # Could not retrieve feature information
            $psSecurityInfo.PowerShellV2Status = "Unknown"
            $psSecurityInfo.PowerShellV2Feature = @{
                Error = "Could not retrieve Windows feature information"
                FeaturesQueried = @("MicrosoftWindowsPowerShellV2", "MicrosoftWindowsPowerShellV2Root")
            }
        }
    }
    catch {
        $psv2Enabled = $null
        $psSecurityInfo.PowerShellV2Status = "Unknown"
        $psSecurityInfo.PowerShellV2Error = @{
            Message = $_.Exception.Message
            Type = $_.Exception.GetType().Name
            StackTrace = $_.ScriptStackTrace
            FullException = $_.Exception.ToString()
            InnerException = if ($_.Exception.InnerException) {
                @{
                    Message = $_.Exception.InnerException.Message
                    Type = $_.Exception.InnerException.GetType().Name
                }
            } else { $null }
            PSCommandPath = $PSCommandPath
            CommandInvocation = if ($_.InvocationInfo) {
                @{
                    Line = $_.InvocationInfo.Line
                    ScriptLineNumber = $_.InvocationInfo.ScriptLineNumber
                    OffsetInLine = $_.InvocationInfo.OffsetInLine
                    ScriptName = $_.InvocationInfo.ScriptName
                }
            } else { $null }
        }
    }
    
    if ($psv2Enabled) {
        Write-Output "FAIL: PowerShell v2 is enabled."
        $psSecurityInfo.SecurityRecommendations += "Disable PowerShell v2 using 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'"
        
        Add-Finding -CheckName "PowerShell v2" -Status "Fail" `
            -Details "PowerShell v2 is enabled." -Category "PSecurity" `
            -AdditionalInfo @{
                PowerShellV2Status = $psv2Enabled
                PowerShellV2Feature = $psSecurityInfo.PowerShellV2Feature
                SecurityRisk = "PowerShell v2 lacks advanced security features like ScriptBlock logging and AMSI integration"
                SecurityImpact = "Attackers can downgrade to PowerShell v2 to bypass security controls"
                Recommendation = "Disable PowerShell v2 using 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'"
                ApplicationImpact = "Disabling v2 may affect legacy scripts that rely on PowerShell v2 features"
                MitigationSteps = @(
                    "Identify any scripts requiring PowerShell v2",
                    "Update scripts to be compatible with newer PowerShell versions",
                    "Disable PowerShell v2 feature",
                    "Implement application control to prevent powershell.exe -Version 2 execution"
                )
                DowngradeTestCommand = "powershell.exe -Version 2 -Command `"Write-Host `$PSVersionTable.PSVersion`""
                References = @(
                    "https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/",
                    "https://attack.mitre.org/techniques/T1562/009/"
                )
            }
    }
    else {
        Write-Output "PASS: PowerShell v2 is disabled."
        Add-Finding -CheckName "PowerShell v2" -Status "Pass" `
            -Details "PowerShell v2 is disabled." -Category "PSecurity" `
            -AdditionalInfo @{
                PowerShellV2Status = $psv2Enabled
                PowerShellV2Feature = $psSecurityInfo.PowerShellV2Feature
                SecurityBenefit = "Prevents attackers from downgrading to PowerShell v2 to bypass security controls"
                ComplianceImpact = "Satisfies security hardening requirements for PowerShell environments"
                DetectionMethod = "Checked Windows Optional Feature status for MicrosoftWindowsPowerShellV2Root"
                VerificationTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                References = @(
                    "https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/install/windows-powershell-system-requirements"
                )
            }
    }
    
    # Check PowerShell logging policies - Enhanced with raw registry data
    $psPolicies = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "Transcription" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "ModuleLogging" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "ScriptBlockLogging" }
    )
    
    foreach ($policy in $psPolicies) {
        if (Test-Path -Path $policy.Path -ErrorAction SilentlyContinue) {
            $settings = Get-ItemProperty -Path $policy.Path -ErrorAction SilentlyContinue
            
            if ($settings) {
                Write-Output "Policy $($policy.Name):"
                $settings | Format-List
                
                # Extract all non-PowerShell metadata properties for JSON
                $properties = $settings.PSObject.Properties | Where-Object { 
                    $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSProvider", "PSDrive") 
                }
                
                # Create raw registry entry data for complete transparency
                $rawSettings = @{}
                foreach ($prop in $properties) {
                    $rawSettings[$prop.Name] = $prop.Value
                }
                
                # Store raw registry values
                if ($policy.Name -eq "Transcription") {
                    $psSecurityInfo.RawRegistrySettings.Transcription = $rawSettings
                }
                elseif ($policy.Name -eq "ModuleLogging") {
                    $psSecurityInfo.RawRegistrySettings.ModuleLogging = $rawSettings
                }
                elseif ($policy.Name -eq "ScriptBlockLogging") {
                    $psSecurityInfo.RawRegistrySettings.ScriptBlockLogging = $rawSettings
                }
                
                # Add settings to their respective policy sections
                foreach ($prop in $properties) {
                    if ($policy.Name -eq "Transcription") {
                        $psSecurityInfo.LoggingConfiguration.TranscriptionSettings[$prop.Name] = $prop.Value
                        if ($prop.Name -eq "EnableTranscripting" -and $prop.Value -eq 1) {
                            $psSecurityInfo.LoggingConfiguration.TranscriptionEnabled = $true
                        }
                    }
                    elseif ($policy.Name -eq "ModuleLogging") {
                        $psSecurityInfo.LoggingConfiguration.ModuleLoggingSettings[$prop.Name] = $prop.Value
                        if ($prop.Name -eq "EnableModuleLogging" -and $prop.Value -eq 1) {
                            $psSecurityInfo.LoggingConfiguration.ModuleLoggingEnabled = $true
                        }
                    }
                    elseif ($policy.Name -eq "ScriptBlockLogging") {
                        $psSecurityInfo.LoggingConfiguration.ScriptBlockLoggingSettings[$prop.Name] = $prop.Value
                        if ($prop.Name -eq "EnableScriptBlockLogging" -and $prop.Value -eq 1) {
                            $psSecurityInfo.LoggingConfiguration.ScriptBlockLoggingEnabled = $true
                        }
                    }
                }
            }
        }
        else {
            # If registry path doesn't exist, record that in the JSON
            if ($policy.Name -eq "Transcription") {
                $psSecurityInfo.LoggingConfiguration.TranscriptionSettings["RegistryPathExists"] = $false
                $psSecurityInfo.RawRegistrySettings.Transcription = @{ "RegistryPathExists" = $false }
            }
            elseif ($policy.Name -eq "ModuleLogging") {
                $psSecurityInfo.LoggingConfiguration.ModuleLoggingSettings["RegistryPathExists"] = $false
                $psSecurityInfo.RawRegistrySettings.ModuleLogging = @{ "RegistryPathExists" = $false }
            }
            elseif ($policy.Name -eq "ScriptBlockLogging") {
                $psSecurityInfo.LoggingConfiguration.ScriptBlockLoggingSettings["RegistryPathExists"] = $false
                $psSecurityInfo.RawRegistrySettings.ScriptBlockLogging = @{ "RegistryPathExists" = $false }
            }
        }
    }
    
    # Check EventLog configuration for PowerShell logs
    try {
        $psEventLogConfig = Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue
        if ($psEventLogConfig) {
            $psSecurityInfo.LoggingConfiguration.EventLogConfiguration = @{
                IsEnabled = $psEventLogConfig.IsEnabled
                LogName = $psEventLogConfig.LogName
                LogMode = $psEventLogConfig.LogMode.ToString()
                MaximumSizeInBytes = $psEventLogConfig.MaximumSizeInBytes
                RecordCount = $psEventLogConfig.RecordCount
                LogFilePath = $psEventLogConfig.LogFilePath
                OldestRecordNumber = $psEventLogConfig.OldestRecordNumber
                ProviderNames = $psEventLogConfig.ProviderNames
                ProviderLevel = $psEventLogConfig.ProviderLevel
                ProviderKeywords = $psEventLogConfig.ProviderKeywords
            }
        } else {
            $psSecurityInfo.LoggingConfiguration.EventLogConfiguration = @{ Error = "PowerShell event log not found" }
        }
    }
    catch {
        $psSecurityInfo.LoggingConfiguration.EventLogConfiguration = @{
            Error = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
        }
    }
    
    # Check Execution Policy settings with full detail
    try {
        $executionPolicies = Get-ExecutionPolicy -List -ErrorAction SilentlyContinue
        $psSecurityInfo.ExecutionPolicy = @{
            ScopedPolicies = @{}
            EffectivePolicy = $null
            PolicyDefinitions = @{
                Restricted = "No scripts can be run. Windows PowerShell can be used only in interactive mode"
                AllSigned = "Only scripts signed by a trusted publisher can be run"
                RemoteSigned = "Downloaded scripts must be signed by a trusted publisher before they can be run"
                Unrestricted = "No restrictions; all scripts can be run"
                Bypass = "Nothing is blocked and there are no warnings or prompts"
            }
        }
        
        foreach ($scope in $executionPolicies) {
            $psSecurityInfo.ExecutionPolicy.ScopedPolicies[$scope.Scope.ToString()] = @{
                ExecutionPolicy = $scope.ExecutionPolicy.ToString()
                ScopeDescription = switch ($scope.Scope.ToString()) {
                    "MachinePolicy" { "Set by Group Policy for all users of the computer" }
                    "UserPolicy" { "Set by Group Policy for the current user" }
                    "Process" { "Affects only the current PowerShell session" }
                    "CurrentUser" { "Affects only the current user" }
                    "LocalMachine" { "Default scope that affects all users of the computer" }
                    default { "Unknown scope" }
                }
                Precedence = switch ($scope.Scope.ToString()) {
                    "MachinePolicy" { 1 }
                    "UserPolicy" { 2 }
                    "Process" { 3 }
                    "CurrentUser" { 4 }
                    "LocalMachine" { 5 }
                    default { 99 }
                }
            }
        }
        
        # Check current effective policy
        $effectivePolicy = Get-ExecutionPolicy
        $psSecurityInfo.ExecutionPolicy.EffectivePolicy = @{
            Policy = $effectivePolicy.ToString()
            Description = $psSecurityInfo.ExecutionPolicy.PolicyDefinitions[$effectivePolicy.ToString()]
            DeterminedBy = "Dynamic evaluation of execution policy scopes"
            SecurityImpact = switch ($effectivePolicy.ToString()) {
                "Restricted" { "High security - Scripts cannot be run" }
                "AllSigned" { "High security - Only signed scripts allowed" }
                "RemoteSigned" { "Medium security - Local scripts unrestricted, downloaded scripts must be signed" }
                "Unrestricted" { "Low security - All scripts can run, warnings for downloaded scripts" }
                "Bypass" { "No security - No restrictions or warnings" }
                default { "Unknown impact" }
            }
        }
        
        Write-Output "Execution Policy:"
        $executionPolicies | Format-Table -AutoSize
        Write-Output "Effective Policy: $effectivePolicy"
    }
    catch {
        $psSecurityInfo.ExecutionPolicyError = @{
            Message = $_.Exception.Message
            Type = $_.Exception.GetType().Name
            StackTrace = $_.ScriptStackTrace
            FullExceptionDetails = $_.ToString()
        }
    }
    
    # Check Language Mode with detailed information
    try {
        $languageMode = $ExecutionContext.SessionState.LanguageMode
        $psSecurityInfo.LanguageMode = @{
            Mode = $languageMode
            Description = switch ($languageMode) {
                "FullLanguage" { "No restrictions on language elements that can be used" }
                "ConstrainedLanguage" { "Restricts types and prevents access to COM objects, most .NET methods" }
                "RestrictedLanguage" { "Can only use cmdlets, cannot use variables except certain ones" }
                "NoLanguage" { "Cannot use any language elements" }
                default { "Unknown language mode" }
            }
            SecurityLevel = switch ($languageMode) {
                "FullLanguage" { "Low" }
                "ConstrainedLanguage" { "Medium" }
                "RestrictedLanguage" { "High" }
                "NoLanguage" { "Maximum" }
                default { "Unknown" }
            }
            LSATrustedPolicyExists = $false
        }
        
        # Check for WDAC/AppLocker policies that might enforce language mode
        try {
            $lsaRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (Test-Path $lsaRegistryPath) {
                $lsaTrustPolicy = Get-ItemProperty -Path $lsaRegistryPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
                if ($lsaTrustPolicy -and $lsaTrustPolicy.RunAsPPL -eq 1) {
                    $psSecurityInfo.LanguageMode.LSATrustedPolicyExists = $true
                    $psSecurityInfo.LanguageMode.LSAProtection = "Enabled"
                }
            }
            
            # Check AppLocker
            $appLockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
            if ($appLockerService) {
                $psSecurityInfo.LanguageMode.AppLockerService = @{
                    Name = $appLockerService.Name
                    DisplayName = $appLockerService.DisplayName
                    Status = $appLockerService.Status.ToString()
                    StartType = $appLockerService.StartType.ToString()
                }
            }
            
            # Check WDAC/Device Guard
            try {
                $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
                if ($deviceGuard) {
                    $psSecurityInfo.LanguageMode.DeviceGuard = @{
                        SecurityServicesConfigured = $deviceGuard.SecurityServicesConfigured
                        SecurityServicesRunning = $deviceGuard.SecurityServicesRunning
                        VirtualizationBasedSecurityStatus = $deviceGuard.VirtualizationBasedSecurityStatus
                        CodeIntegrityPolicyEnforcementStatus = $deviceGuard.CodeIntegrityPolicyEnforcementStatus
                    }
                }
            }
            catch {
                $psSecurityInfo.LanguageMode.DeviceGuardError = $_.Exception.Message
            }
        }
        catch {
            $psSecurityInfo.LanguageMode.LSACheckError = $_.Exception.Message
        }
        
        Write-Output "PowerShell Language Mode: $languageMode"
        
        if ($languageMode -ne "ConstrainedLanguage" -and $languageMode -ne "RestrictedLanguage") {
            $psSecurityInfo.SecurityRecommendations += "Consider implementing Constrained Language Mode for enhanced security"
        }
    }
    catch {
        $psSecurityInfo.LanguageModeError = @{
            Message = $_.Exception.Message
            Type = $_.Exception.GetType().Name
            StackTrace = $_.ScriptStackTrace
        }
    }
    
    # Check AMSI Integration with detailed information
    try {
        $amsiDll = Get-Item "$env:SystemRoot\System32\amsi.dll" -ErrorAction SilentlyContinue
        $psSecurityInfo.AMSIIntegration = @{
            DllExists = ($null -ne $amsiDll)
            DllDetails = if ($amsiDll) {
                @{
                    Path = $amsiDll.FullName
                    LastModified = $amsiDll.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    Version = $amsiDll.VersionInfo.FileVersion
                    ProductVersion = $amsiDll.VersionInfo.ProductVersion
                    FileSize = $amsiDll.Length
                    CreationTime = $amsiDll.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                    FileHash = (Get-FileHash -Path $amsiDll.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                }
            } else { $null }
            ImplementationInfo = @{
                Description = "AMSI allows real-time scanning of PowerShell scripts by antivirus software"
                IntroducedInVersion = "5.0"
                RequiredForDetection = "Antivirus software with AMSI support"
                BypassProtection = "Script block logging can help detect AMSI bypass attempts"
            }
        }
        
        # Check for AMSI providers installed on the system
        try {
            $amsiProviders = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
            if ($amsiProviders) {
                $psSecurityInfo.AMSIIntegration.AMSIProviders = $amsiProviders | ForEach-Object {
                    $providerName = $_.PSChildName
                    $provider = $_
                    @{
                        ProviderGuid = $providerName
                        Path = $provider.Name
                        Properties = ($provider | Get-ItemProperty) | ForEach-Object {
                            $props = @{}
                            $_.PSObject.Properties | Where-Object {
                                $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive')
                            } | ForEach-Object {
                                $props[$_.Name] = $_.Value
                            }
                            $props
                        }
                    }
                }
                
                $psSecurityInfo.AMSIIntegration.ProvidersFound = $amsiProviders.Count
                $psSecurityInfo.AMSIIntegration.Available = ($amsiProviders.Count -gt 0) -and $psSecurityInfo.AMSIIntegration.DllExists
            }
        }
        catch {
            $psSecurityInfo.AMSIIntegration.ProviderError = $_.Exception.Message
        }
    }
    catch {
        $psSecurityInfo.AMSIIntegrationError = @{
            Message = $_.Exception.Message
            Type = $_.Exception.GetType().Name
            StackTrace = $_.ScriptStackTrace
        }
    }
    
    # Set variables for readability
    $transcriptionEnabled = $psSecurityInfo.LoggingConfiguration.TranscriptionEnabled
    $moduleLoggingEnabled = $psSecurityInfo.LoggingConfiguration.ModuleLoggingEnabled
    $scriptBlockLoggingEnabled = $psSecurityInfo.LoggingConfiguration.ScriptBlockLoggingEnabled
    
    # Construct detailed Security Risk Assessment
    $securityRisks = @()
    if (-not $transcriptionEnabled) {
        $securityRisks += @{
            Setting = "TranscriptionLogging"
            Status = "Disabled"
            Risk = "Command activities not recorded to text files for forensic analysis"
            RecommendedSetting = "Enable PowerShell Transcription via GPO or registry"
            RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            RegistrySettings = @{
                "EnableTranscripting" = 1
                "EnableInvocationHeader" = 1
                "OutputDirectory" = "Desired output path or blank for default"
            }
            SecurityImpact = "Medium"
            MitigationDifficulty = "Low"
            MitigationPriority = "High"
            RequiresRestart = $false
            AdditionalInfo = "Transcripts provide human-readable records of PowerShell activity"
        }
        $psSecurityInfo.SecurityRecommendations += "Enable PowerShell Transcription logging"
    }
    
    if (-not $moduleLoggingEnabled) {
        $securityRisks += @{
            Setting = "ModuleLogging"
            Status = "Disabled"
            Risk = "PowerShell module activity not recorded for security analysis"
            RecommendedSetting = "Enable PowerShell Module Logging via GPO or registry"
            RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
            RegistrySettings = @{
                "EnableModuleLogging" = 1
                "ModuleNames" = "*"
            }
            SecurityImpact = "Medium"
            MitigationDifficulty = "Low"
            MitigationPriority = "Medium"
            RequiresRestart = $false
            AdditionalInfo = "Module logging records execution of PowerShell cmdlets"
        }
        $psSecurityInfo.SecurityRecommendations += "Enable PowerShell Module logging"
    }
    
    if (-not $scriptBlockLoggingEnabled) {
        $securityRisks += @{
            Setting = "ScriptBlockLogging"
            Status = "Disabled"
            Risk = "Malicious scripts may execute without being logged for detection"
            RecommendedSetting = "Enable PowerShell ScriptBlock Logging via GPO or registry"
            RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            RegistrySettings = @{
                "EnableScriptBlockLogging" = 1
                "EnableScriptBlockInvocationLogging" = 1
            }
            SecurityImpact = "High"
            MitigationDifficulty = "Low"
            MitigationPriority = "High"
            RequiresRestart = $false
            AdditionalInfo = "ScriptBlock logging captures code even when obfuscated or encoded"
            LogLocation = "Microsoft-Windows-PowerShell/Operational event log, event IDs 4104 and 4105"
            PerformanceImpact = "Low to Medium (depending on script complexity and volume)"
        }
        $psSecurityInfo.SecurityRecommendations += "Enable PowerShell ScriptBlock logging"
    }
    
    # Update Security Mitigations based on findings
    $psSecurityInfo.SecurityMitigations.ConstrainedLanguageModeEnabled = ($psSecurityInfo.LanguageMode.Mode -eq "ConstrainedLanguage" -or $psSecurityInfo.LanguageMode.Mode -eq "RestrictedLanguage")
    $psSecurityInfo.SecurityMitigations.ExecutionPolicyEnforcement = ($psSecurityInfo.ExecutionPolicy.EffectivePolicy.Policy -in @("Restricted", "AllSigned", "RemoteSigned"))
    $psSecurityInfo.SecurityMitigations.ScriptBlockLoggingEnabled = $scriptBlockLoggingEnabled
    $psSecurityInfo.SecurityMitigations.PowerShellVersionRestrictions = (-not $psSecurityInfo.PowerShellV2Status)
    
    # Add the security risks to our main JSON object
    $psSecurityInfo.SecurityRisks = $securityRisks
    $psSecurityInfo.AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $psSecurityInfo.OperatingSystem = @{
        Caption = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        Version = (Get-WmiObject -Class Win32_OperatingSystem).Version
        BuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
        OSArchitecture = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
    }
    
    # Add logging findings
    if ($transcriptionEnabled -and $moduleLoggingEnabled -and $scriptBlockLoggingEnabled) {
        Write-Output "PASS: All PowerShell logging settings enabled."
        Add-Finding -CheckName "PowerShell Logging" -Status "Pass" `
            -Details "Transcription, Module, and ScriptBlock logging are enabled." -Category "PSecurity" `
            -AdditionalInfo @{
                LoggingConfiguration = $psSecurityInfo.LoggingConfiguration
                RawRegistrySettings = $psSecurityInfo.RawRegistrySettings
                SecurityBenefits = @(
                    @{
                        Feature = "Transcription"
                        Benefit = "Command activities recorded to text files for forensic analysis"
                        LogLocation = if ($psSecurityInfo.LoggingConfiguration.TranscriptionSettings.OutputDirectory) {
                            $psSecurityInfo.LoggingConfiguration.TranscriptionSettings.OutputDirectory
                        } else {
                            "$env:USERPROFILE\Documents\PowerShell_transcript.<hostname>.<random>.<timestamp>.txt"
                        }
                    },
                    @{
                        Feature = "ModuleLogging"
                        Benefit = "Module activity recorded for security monitoring"
                        LogLocation = "Windows event logs (Microsoft-Windows-PowerShell/Operational)"
                        EventIds = @(4103)
                    },
                    @{
                        Feature = "ScriptBlockLogging"
                        Benefit = "Script content recorded even when obfuscated"
                        LogLocation = "Windows event logs (Microsoft-Windows-PowerShell/Operational)"
                        EventIds = @(4104, 4105, 4106)
                    }
                )
                RecommendedSettings = "Current settings comply with security best practices"
                DetectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                AdditionalRecommendations = @(
                    "Review log retention settings to ensure logs are stored long enough for forensic analysis",
                    "Consider forwarding PowerShell logs to a central SIEM solution"
                )
                ComplianceImpact = @{
                    NIST = "Satisfies AC-2(12), AU-3, AU-12"
                    PCI = "Supports Requirements 10.2, 10.3"
                    MITRE = "Addresses T1059.001 mitigation strategies"
                }
            }
    }
    else {
        Write-Output "FAIL: One or more PowerShell logging settings are not enabled."
        Add-Finding -CheckName "PowerShell Logging" -Status "Fail" `
            -Details "Missing one or more of: Transcription, ModuleLogging, ScriptBlockLogging." -Category "PSecurity" `
            -AdditionalInfo @{
                LoggingConfiguration = $psSecurityInfo.LoggingConfiguration
                RawRegistrySettings = $psSecurityInfo.RawRegistrySettings
                SecurityRisks = $securityRisks
                Recommendations = "Enable all PowerShell logging features through Group Policy or registry settings"
                MitigationSteps = @{
                    Transcription = @{
                        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
                        Settings = @{
                            "EnableTranscripting" = 1
                            "EnableInvocationHeader" = 1
                            "OutputDirectory" = "<desired output path or blank for default>"
                        }
                        GPOLocation = "Computer Configuration\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Transcription"
                        PowerShellCommand = "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1 -Type DWord; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Value 1 -Type DWord"
                    }
                    ModuleLogging = @{
                        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
                        Settings = @{
                            "EnableModuleLogging" = 1
                            "ModuleNames" = "*"
                        }
                        GPOLocation = "Computer Configuration\Administrative Templates\Windows Components\Windows PowerShell\Turn on Module Logging"
                        PowerShellCommand = "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1 -Type DWord; New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -Type String"
                    }
                    ScriptBlockLogging = @{
                        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                        Settings = @{
                            "EnableScriptBlockLogging" = 1
                            "EnableScriptBlockInvocationLogging" = 1
                        }
                        GPOLocation = "Computer Configuration\Administrative Templates\Windows Components\Windows PowerShell\Turn on PowerShell Script Block Logging"
                        PowerShellCommand = "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord"
                    }
                }
                EventLogQueries = @{
                    ScriptBlockLogging = "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}"
                    ModuleLogging = "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103}"
                }
                TranscriptLocation = if ($psSecurityInfo.LoggingConfiguration.TranscriptionSettings.OutputDirectory) {
                    $psSecurityInfo.LoggingConfiguration.TranscriptionSettings.OutputDirectory
                } else {
                    "$env:USERPROFILE\Documents\PowerShell_transcript.<hostname>.<random>.<timestamp>.txt"
                }
                LogCollectionConsiderations = @(
                    "Log rotation and retention",
                    "SIEM integration",
                    "Log volume impacts",
                    "Storage requirements"
                )
                DetectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                ComplianceImpact = @{
                    NIST = "Non-compliance with AC-2(12), AU-3, AU-12"
                    PCI = "May impact compliance with Requirements 10.2, 10.3"
                    MITRE = "Increases exposure to T1059.001 (PowerShell)"
                }
            }
    }
    
    # Add overall PowerShell security assessment with comprehensive details
    Add-Finding -CheckName "PowerShell Security Assessment" -Status "Info" `
        -Details "Overall PowerShell security configuration assessment." -Category "PSecurity" `
        -AdditionalInfo $psSecurityInfo
}

function Test-PowerShellHistory {
    Write-SectionHeader "PowerShell Command History"
    $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    
    # Create fully detailed object for JSON output
    $historyInfo = @{
        HistoryPath = $historyPath
        HistoryExists = $false
        HistoryEntryCount = 0
        SuspiciousCommandPatterns = @(
            "IEX", 
            "Invoke-Expression", 
            "DownloadString", 
            "WebClient", 
            "Start-Process", 
            "reg add", 
            "New-Service", 
            "schtasks", 
            "sc create",
            "Invoke-Obfuscation",
            "Invoke-Mimikatz",
            "Invoke-WebRequest",
            "Set-MpPreference -DisableRealTimeMonitoring",
            "-EncodedCommand",
            "Convert-FromBase64String",
            "[System.Convert]::FromBase64String",
            "-encodedcommand",
            "-enc",
            "-e",
            "-nop",
            "-noprofile",
            "-windowstyle hidden",
            "-w hidden",
            "hidden",
            "bypass",
            "-exec bypass",
            "DownloadFile",
            "FromBase64",
            "Reflection.Assembly",
            "Invoke-ReflectivePE",
            "Import-Module",
            "Add-MpPreference -ExclusionPath",
            "Set-ItemProperty -Path 'HKLM:"
        )
        PatternCategories = @{
            "IEX" = "ObfuscationTechnique";
            "Invoke-Expression" = "ObfuscationTechnique";
            "DownloadString" = "DownloadExecute";
            "WebClient" = "DownloadExecute";
            "Start-Process" = "SystemModification";
            "reg add" = "SystemModification";
            "New-Service" = "SystemModification";
            "schtasks" = "SystemModification";
            "sc create" = "SystemModification";
            "Invoke-Obfuscation" = "ObfuscationTechnique";
            "Invoke-Mimikatz" = "CredentialAccess";
            "Invoke-WebRequest" = "DownloadExecute";
            "Set-MpPreference -DisableRealTimeMonitoring" = "BypassSecurity";
            "-EncodedCommand" = "EncodedCommands";
            "Convert-FromBase64String" = "EncodedCommands";
            "[System.Convert]::FromBase64String" = "EncodedCommands";
            "-enc" = "EncodedCommands";
            "-e" = "EncodedCommands";
            "-nop" = "BypassSecurity";
            "-noprofile" = "BypassSecurity";
            "-windowstyle hidden" = "ObfuscationTechnique";
            "-w hidden" = "ObfuscationTechnique";
            "hidden" = "ObfuscationTechnique";
            "bypass" = "BypassSecurity";
            "-exec bypass" = "BypassSecurity";
            "DownloadFile" = "DownloadExecute";
            "FromBase64" = "EncodedCommands";
            "Reflection.Assembly" = "ReflectionUsage";
            "Invoke-ReflectivePE" = "ReflectionUsage";
            "Import-Module" = "SystemModification";
            "Add-MpPreference -ExclusionPath" = "BypassSecurity";
            "Set-ItemProperty -Path 'HKLM:" = "SystemModification"
        }
        CommandEntries = @()
        HistoryFileDetails = $null
        SystemInfo = @{
            Hostname = $env:COMPUTERNAME
            Username = $env:USERNAME
            Domain = $env:USERDOMAIN
            OSVersion = [System.Environment]::OSVersion.VersionString
            PSVersion = $PSVersionTable.PSVersion.ToString()
        }
        ScanTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (Test-Path $historyPath) {
        $history = Get-Content $historyPath -ErrorAction SilentlyContinue
        $historyInfo.HistoryExists = $true
        $historyInfo.HistoryEntryCount = $history.Count
        
        # Get detailed file metadata
        $historyFile = Get-Item $historyPath -ErrorAction SilentlyContinue
        if ($historyFile) {
            $acl = Get-Acl $historyPath -ErrorAction SilentlyContinue
            $permissions = @()
            
            if ($acl) {
                foreach ($access in $acl.Access) {
                    $permissions += @{
                        IdentityReference = $access.IdentityReference.ToString()
                        AccessControlType = $access.AccessControlType.ToString()
                        FileSystemRights = $access.FileSystemRights.ToString()
                        IsInherited = $access.IsInherited
                        InheritanceFlags = $access.InheritanceFlags.ToString()
                        PropagationFlags = $access.PropagationFlags.ToString()
                    }
                }
            }
            
            # Create detailed file metadata
            $historyInfo.HistoryFileDetails = @{
                CreationTime = $historyFile.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                LastWriteTime = $historyFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                LastAccessTime = $historyFile.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')
                FileSize = $historyFile.Length
                Owner = if ($acl) { $acl.Owner } else { "Unknown" }
                Permissions = $permissions
                Attributes = $historyFile.Attributes.ToString()
                FullPath = $historyFile.FullName
                DirectoryName = $historyFile.DirectoryName
                FileHash = (Get-FileHash -Path $historyPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            }
        }
        
        # Process each history command with detailed analysis
        for ($i = 0; $i -lt $history.Count; $i++) {
            $line = $history[$i]
            $lineNumber = $i + 1
            
            # Analyze the command for patterns
            $detectedPatterns = @()
            foreach ($pattern in $historyInfo.SuspiciousCommandPatterns) {
                if ($line -match $pattern) {
                    $category = $historyInfo.PatternCategories[$pattern]
                    $detectedPatterns += @{
                        Pattern = $pattern
                        Category = $category
                        Index = $line.IndexOf($pattern)
                        Length = $pattern.Length
                    }
                }
            }
            
            # Create detailed command analysis
            $commandEntry = @{
                LineNumber = $lineNumber
                Command = $line
                Length = $line.Length
                DetectedPatterns = $detectedPatterns
                PatternCount = $detectedPatterns.Count
                IsSuspicious = $detectedPatterns.Count -gt 0
                Structure = @{
                    StartsWithVerb = if ($line -match '^\s*([A-Za-z]+)-') { $true } else { $false }
                    VerbIdentified = if ($line -match '^\s*([A-Za-z]+)-') { $matches[1] } else { $null }
                    ContainsPipe = $line.Contains('|')
                    PipeCount = ($line -split '\|').Count - 1
                    ContainsRedirection = ($line.Contains('>') -or $line.Contains('>>') -or $line.Contains('2>') -or $line.Contains('2>>'))
                    HasFlags = $line.Contains('-')
                    FlagCount = ($line -split '-').Count - 1
                    WordCount = ($line -split '\s+').Count
                    HasSemicolon = $line.Contains(';')
                    HasBacktick = $line.Contains('`')
                    ContainsEnvironmentVariables = $line -match '\$env:'
                    ContainsSingleQuotes = $line.Contains("'")
                    ContainsDoubleQuotes = $line.Contains('"')
                    EndsWithSemicolon = $line.TrimEnd() -match ';$'
                }
                Analysis = @{
                    ContainsBase64Like = $line -match '[A-Za-z0-9+/]{20,}={0,2}'
                    ContainsIP = $line -match '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                    ContainsURL = $line -match 'https?://[^\s"]+'
                    ContainsFilePath = $line -match '[A-Za-z]:\\[^"]+'
                    ContainsRegistry = $line -match 'HKLM:|HKCU:|HKCR:|HKU:|HKCC:|Registry::'
                    ContainsCredentials = $line -match 'password|credential|secret|key|pwd'
                    ContainsCipher = $line -match 'aes|encrypt|decrypt|cipher|cryptography'
                    ContainsScriptExecution = $line -match '\.ps1|\.bat|\.cmd|\.exe|\.vbs|\.js'
                    ContainsNetworkingCommand = $line -match 'nslookup|ping|tracert|netstat|route|curl|wget'
                    ContainsUserCreation = $line -match 'New-LocalUser|Add-LocalGroupMember|net user add'
                }
                PreviousCommand = if ($i -gt 0) { $history[$i-1] } else { $null }
                NextCommand = if ($i -lt $history.Count-1) { $history[$i+1] } else { $null }
                RelativePosition = @{
                    Index = $i
                    IsFirst = $i -eq 0
                    IsLast = $i -eq ($history.Count - 1)
                    PercentilePosition = [math]::Round(($i / $history.Count) * 100, 2)
                }
                ExecutionContext = if ($historyFile) {
                    $commandTime = $null
                    # Estimate command time based on file timestamp and position
                    if ($history.Count -gt 1) {
                        $timespan = New-TimeSpan -Start $historyFile.CreationTime -End $historyFile.LastWriteTime
                        $secondsPerCommand = $timespan.TotalSeconds / $history.Count
                        $estimatedOffset = $secondsPerCommand * $i
                        $commandTime = $historyFile.CreationTime.AddSeconds($estimatedOffset)
                        $commandTime.ToString('yyyy-MM-dd HH:mm:ss')
                    } else {
                        $historyFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    }
                } else { $null }
            }
            
            # Add to collection
            $historyInfo.CommandEntries += $commandEntry
            
            # Display in console if suspicious
            if ($commandEntry.IsSuspicious) {
                Write-Output "Suspicious command [$lineNumber]: $line"
                foreach ($pattern in $commandEntry.DetectedPatterns) {
                    Write-Output "  - Pattern: $($pattern.Pattern) (Category: $($pattern.Category))"
                }
            }
        }
        
        # Create findings based on detected patterns
        if ($historyInfo.CommandEntries | Where-Object { $_.IsSuspicious }) {
            $suspiciousCount = ($historyInfo.CommandEntries | Where-Object { $_.IsSuspicious }).Count
            Write-Output "ALERT: Found $suspiciousCount suspicious commands in PowerShell history."
            
            # Add finding with full details
            Add-Finding -CheckName "PowerShell Command History" -Status "Warning" `
                -Details "Found $suspiciousCount suspicious commands in PowerShell history." -Category "PSHistory" `
                -AdditionalInfo $historyInfo
        }
        else {
            Write-Output "PASS: No suspicious commands detected in PowerShell history."
            
            # Add finding with full details
            Add-Finding -CheckName "PowerShell Command History" -Status "Pass" `
                -Details "No suspicious commands detected in PowerShell history." -Category "PSHistory" `
                -AdditionalInfo $historyInfo
        }
    }
    else {
        Write-Output "INFO: PowerShell history file not found at $historyPath"
        
        # Create detailed file system check info
        $historyDirPath = Split-Path -Parent $historyPath
        $dirExists = Test-Path -Path $historyDirPath -ErrorAction SilentlyContinue
        $dirDetails = @{
            DirectoryExists = $dirExists
            DirectoryPath = $historyDirPath
        }
        
        if ($dirExists) {
            $dirItem = Get-Item -Path $historyDirPath -ErrorAction SilentlyContinue
            $dirDetails.CreationTime = $dirItem.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
            $dirDetails.LastWriteTime = $dirItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            $dirDetails.LastAccessTime = $dirItem.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')
            
            # List other files in directory
            $otherFiles = Get-ChildItem -Path $historyDirPath -ErrorAction SilentlyContinue | 
                Select-Object -Property Name, Length, CreationTime, LastWriteTime
            
            $dirDetails.OtherFiles = $otherFiles | ForEach-Object {
                @{
                    Name = $_.Name
                    Size = $_.Length
                    CreationTime = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                    LastWriteTime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }
        
        # Check for alternative history locations
        $alternativeHistoryPaths = @(
            "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
            "$env:USERPROFILE\.PowerShell\PSReadLine\ConsoleHost_history.txt",
            "$env:USERPROFILE\Documents\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )
        
        $alternativeHistories = @()
        foreach ($altPath in $alternativeHistoryPaths) {
            if ($altPath -eq $historyPath) { continue }
            
            $exists = Test-Path -Path $altPath -ErrorAction SilentlyContinue
            $altInfo = @{
                Path = $altPath
                Exists = $exists
            }
            
            if ($exists) {
                $altFile = Get-Item -Path $altPath -ErrorAction SilentlyContinue
                $altInfo.CreationTime = $altFile.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                $altInfo.LastWriteTime = $altFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                $altInfo.Size = $altFile.Length
                $altInfo.LineCount = (Get-Content -Path $altPath -ErrorAction SilentlyContinue).Count
            }
            
            $alternativeHistories += $altInfo
        }
        
        # Create PSReadline configuration check
        $psReadlineConfig = @{
            ModuleInstalled = $null
            MaximumHistoryCount = $null
            HistorySavePath = $null
            HistorySaveStyle = $null
        }
        
        try {
            $psReadlineModule = Get-Module -Name PSReadLine -ListAvailable -ErrorAction SilentlyContinue
            $psReadlineConfig.ModuleInstalled = ($null -ne $psReadlineModule)
            
            if ($psReadlineConfig.ModuleInstalled) {
                # Only attempt to get options if module is installed
                try {
                    $options = Get-PSReadLineOption -ErrorAction SilentlyContinue
                    $psReadlineConfig.MaximumHistoryCount = $options.MaximumHistoryCount
                    $psReadlineConfig.HistorySavePath = $options.HistorySavePath
                    $psReadlineConfig.HistorySaveStyle = $options.HistorySaveStyle
                }
                catch {
                    $psReadlineConfig.OptionsError = $_.Exception.Message
                }
            }
        }
        catch {
            $psReadlineConfig.Error = $_.Exception.Message
        }
        
        # Add to history info
        $historyInfo.HistoryFileDetails = @{
            DirectoryInfo = $dirDetails
            AlternativeHistories = $alternativeHistories
            PSReadLineConfiguration = $psReadlineConfig
            HistoryFileExists = $false
            PossibleCauses = @(
                "User has not executed PowerShell commands in this profile",
                "PSReadLine module not used or not configured to save history",
                "History has been intentionally deleted",
                "PowerShell profile configured to disable history",
                "User executing PowerShell with the -NoProfile parameter"
            )
        }
        
        # Add finding with detailed info
        Add-Finding -CheckName "PowerShell Command History" -Status "Info" `
            -Details "PowerShell history file not found at: $historyPath" -Category "PSHistory" `
            -AdditionalInfo $historyInfo
    }
}

function Test-StorageEncryption {
    Write-SectionHeader "Storage & Encryption"
    
    # Get detailed volume information and preserve all properties
    $volumes = Get-Volume | Where-Object { $_.DriveLetter } 
    
    # Display basic information in console
    $volumes | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining, DriveType, HealthStatus, OperationalStatus | Format-Table -AutoSize

    # Create comprehensive volume information for JSON output with all available properties
    $volumeDetails = $volumes | ForEach-Object {
        @{
            DriveLetter = $_.DriveLetter
            FileSystemLabel = $_.FileSystemLabel
            FileSystem = $_.FileSystem
            SizeBytes = $_.Size
            SizeGB = [math]::Round($_.Size / 1GB, 2)
            FreeSpaceBytes = $_.SizeRemaining
            FreeSpaceGB = [math]::Round($_.SizeRemaining / 1GB, 2)
            UsedSpaceGB = [math]::Round(($_.Size - $_.SizeRemaining) / 1GB, 2)
            PercentFree = if($_.Size -gt 0) { [math]::Round(($_.SizeRemaining / $_.Size) * 100, 2) } else { 0 }
            DriveType = $_.DriveType.ToString()
            HealthStatus = $_.HealthStatus.ToString()
            OperationalStatus = $_.OperationalStatus.ToString()
            UniqueId = $_.UniqueId
            Path = $_.Path
            AllocationUnitSize = $_.AllocationUnitSize
            DedupMode = $_.DedupMode
            FileSystemType = $_.FileSystemType
            ObjectId = $_.ObjectId
            IsSystem = ($_.DriveLetter -eq ($env:SystemDrive).TrimEnd(':'))
        }
    }

    # Add detailed volumes info to findings with full granular data
    Add-Finding -CheckName "Volume Information" -Status "Info" `
        -Details "System has $($volumes.Count) volumes with detailed information." -Category "Storage" `
        -AdditionalInfo @{
            VolumeCount = $volumes.Count
            Volumes = $volumeDetails
            SystemDriveLetter = ($env:SystemDrive).TrimEnd(':')
            SystemRoot = $env:SystemRoot
            CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            HostName = $env:COMPUTERNAME
            OSVersion = [System.Environment]::OSVersion.VersionString
        }

    Write-Output "Checking BitLocker status..."
    $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue

    if ($bitlocker) {
        # Display basic BitLocker information in console
        $bitlocker | Select-Object MountPoint, VolumeStatus, EncryptionMethod, EncryptionPercentage, KeyProtector | Format-Table -AutoSize

        # Create detailed BitLocker information for JSON output with all data preserved
        $bitlockerDetails = $bitlocker | ForEach-Object {
            # Create detailed key protector information preserving all properties
            $keyProtectorsDetail = $_.KeyProtector | ForEach-Object {
                @{
                    KeyProtectorId = $_.KeyProtectorId
                    KeyProtectorType = $_.KeyProtectorType.ToString()
                    AutoUnlockKey = $null -ne $_.AutoUnlockKey
                    KeyFileName = $_.KeyFileName
                    RecoveryPassword = $_.RecoveryPassword
                    RecoveryPasswordId = $_.RecoveryPasswordId
                    RecoveryKeyAvailable = $null -ne $_.RecoveryPassword
                    CreationTime = if ($_.CreationTime) { $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
                    VolumeUniqueId = $_.VolumeUniqueId
                }
            }

            # Create comprehensive BitLocker volume object
            @{
                MountPoint = $_.MountPoint
                VolumeStatus = $_.VolumeStatus.ToString()
                EncryptionMethod = if ($_.EncryptionMethod) { $_.EncryptionMethod.ToString() } else { "N/A" }
                EncryptionPercentage = $_.EncryptionPercentage
                ProtectionStatus = $_.ProtectionStatus.ToString()
                LockStatus = $_.LockStatus.ToString()
                AutoUnlockEnabled = $_.AutoUnlockEnabled
                VolumeType = $_.VolumeType.ToString()
                CapacityGB = [math]::Round($_.CapacityGB, 2)
                KeyProtectors = $keyProtectorsDetail
                KeyProtectorTypes = ($_.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
                KeyProtectorCount = $_.KeyProtector.Count
                MetadataVersion = $_.MetadataVersion
                VolumeUniqueId = $_.VolumeUniqueId
                IsSystemDrive = $_.MountPoint -eq "$env:SystemDrive\"
                WipePercentage = $_.WipePercentage
                EncryptionFlags = $_.EncryptionFlags
                IsVolumeInitializedForProtection = $_.IsVolumeInitializedForProtection
            }
        }

        # Determine system drive BitLocker status with precise details
        $systemDrive = $env:SystemDrive.TrimEnd(":\")
        $systemBitlocker = $bitlocker | Where-Object { $_.MountPoint -eq "$systemDrive`:" }

        if ($systemBitlocker -and $systemBitlocker.VolumeStatus -eq "FullyEncrypted") {
            Write-Output "PASS: System drive is encrypted."
            
            # Get detailed system BitLocker information
            $systemBitlockerDetails = $bitlockerDetails | Where-Object { $_["IsSystemDrive"] -eq $true }
            
            Add-Finding -CheckName "BitLocker Encryption" -Status "Pass" `
                -Details "System drive is fully encrypted." -Category "Storage" `
                -AdditionalInfo @{
                    SystemDrive = "$systemDrive`:"
                    VolumeStatus = $systemBitlocker.VolumeStatus.ToString()
                    EncryptionMethod = if ($systemBitlocker.EncryptionMethod) { $systemBitlocker.EncryptionMethod.ToString() } else { "N/A" }
                    ProtectionStatus = $systemBitlocker.ProtectionStatus.ToString()
                    LockStatus = $systemBitlocker.LockStatus.ToString()
                    KeyProtectorTypes = ($systemBitlocker.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
                    KeyProtectorCount = $systemBitlocker.KeyProtector.Count
                    EncryptionPercentage = $systemBitlocker.EncryptionPercentage
                    AutoUnlockEnabled = $systemBitlocker.AutoUnlockEnabled
                    SystemBitLockerDetails = $systemBitlockerDetails
                    ComplianceImpact = "Meets data-at-rest encryption requirements"
                    LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
        }
        else {
            Write-Output "FAIL: System drive is not encrypted."
            
            # Provide detailed information about the unencrypted system drive
            $systemDriveStatus = if ($systemBitlocker) { 
                @{
                    VolumeStatus = $systemBitlocker.VolumeStatus.ToString()
                    EncryptionPercentage = $systemBitlocker.EncryptionPercentage
                    ProtectionStatus = $systemBitlocker.ProtectionStatus.ToString()
                    LockStatus = $systemBitlocker.LockStatus.ToString()
                }
            } else { 
                @{
                    VolumeStatus = "Not Protected"
                    EncryptionPercentage = 0
                    ProtectionStatus = "Unprotected"
                    LockStatus = "Unlocked"
                }
            }
            
            Add-Finding -CheckName "BitLocker Encryption" -Status "Fail" `
                -Details "System drive not fully encrypted." -Category "Storage" `
                -AdditionalInfo @{
                    SystemDrive = "$systemDrive`:"
                    SystemDriveStatus = $systemDriveStatus
                    TPMAvailable = if (Get-WmiObject -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm -ErrorAction SilentlyContinue) { $true } else { $false }
                    BitLockerFeatureInstalled = if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $true } else { $false }
                    RecommendedActions = @(
                        "Enable BitLocker on the system drive",
                        "Ensure TPM is enabled in BIOS/UEFI",
                        "Store recovery keys in a secure location"
                    )
                    ComplianceImpact = "Does not meet data-at-rest encryption requirements"
                    SecurityRisk = "Unencrypted system drive may allow data extraction if physically accessed"
                    LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
        }

        # Add comprehensive summary of all BitLocker volumes with full details
        Add-Finding -CheckName "BitLocker Status Summary" -Status "Info" `
            -Details "$($bitlocker.Count) volumes checked for BitLocker." -Category "Storage" `
            -AdditionalInfo @{
                TotalVolumes = $bitlocker.Count
                EncryptedVolumes = ($bitlocker | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" }).Count
                PartiallyEncryptedVolumes = ($bitlocker | Where-Object { $_.VolumeStatus -eq "EncryptionInProgress" }).Count
                UnencryptedVolumes = ($bitlocker | Where-Object { $_.VolumeStatus -eq "FullyDecrypted" }).Count
                DecryptionInProgress = ($bitlocker | Where-Object { $_.VolumeStatus -eq "DecryptionInProgress" }).Count
                AllBitLockerVolumes = $bitlockerDetails
                SystemVolumeEncrypted = ($systemBitlocker -and $systemBitlocker.VolumeStatus -eq "FullyEncrypted")
                FixedDrivesCount = ($bitlocker | Where-Object { $_.VolumeType -eq "FixedVolume" }).Count
                RemovableDrivesCount = ($bitlocker | Where-Object { $_.VolumeType -eq "RemovableVolume" }).Count
                AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
    }
    else {
        Write-Output "BitLocker not available."
        
        # Check for specific reasons why BitLocker might not be available
        $tpm = Get-WmiObject -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm -ErrorAction SilentlyContinue
        $bitlockerFeature = Get-WindowsFeature -Name BitLocker -ErrorAction SilentlyContinue
        
        Add-Finding -CheckName "BitLocker Availability" -Status "Fail" `
            -Details "BitLocker not available." -Category "Storage" `
            -AdditionalInfo @{
                SystemDrive = $env:SystemDrive
                TPMAvailable = if ($tpm) { $true } else { $false }
                TPMDetails = if ($tpm) {
                    @{
                        IsActivated = $tpm.IsActivated()
                        IsEnabled = $tpm.IsEnabled()
                        IsOwned = $tpm.IsOwned()
                        ManufacturerId = $tpm.ManufacturerId
                        ManufacturerVersion = $tpm.ManufacturerVersion
                        PhysicalPresenceVersionInfo = $tpm.PhysicalPresenceVersionInfo
                        SpecVersion = $tpm.SpecVersion
                    }
                } else { $null }
                BitLockerFeature = if ($bitlockerFeature) { 
                    @{
                        Name = $bitlockerFeature.Name
                        DisplayName = $bitlockerFeature.DisplayName
                        Installed = $bitlockerFeature.Installed
                    } 
                } else { $null }
                BitLockerCommandAvailable = if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $true } else { $false }
                BitLockerDriveEncryptionService = if (Get-Service -Name BDESVC -ErrorAction SilentlyContinue) {
                    (Get-Service -Name BDESVC).Status.ToString()
                } else { "Not Available" }
                RecommendedActions = @(
                    "Verify TPM is enabled in BIOS/UEFI",
                    "Install BitLocker feature if not already installed",
                    "Ensure BitLocker Drive Encryption service is running",
                    "Configure BitLocker policy through Group Policy or directly"
                )
                PossibleReasons = @(
                    "BitLocker feature not installed",
                    "TPM not available or not enabled",
                    "BitLocker not supported on this OS version",
                    "BitLocker Drive Encryption service not running"
                )
                OSVersion = [System.Environment]::OSVersion.VersionString
                AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
    }
}

function Test-NetworkAdapters {
    Write-SectionHeader "Network Adapters"
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    if ($adapters) {
        $adapters | Where-Object { $_.Status -eq "Up" } | 
            Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Format-Table -AutoSize

        foreach ($adapter in $adapters) {
            # Create comprehensive adapter details object preserving all properties
            $adapterDetails = @{
                Name = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                InterfaceIndex = $adapter.InterfaceIndex
                MacAddress = $adapter.MacAddress
                Status = $adapter.Status.ToString()
                MediaType = $adapter.MediaType
                PhysicalMediaType = $adapter.PhysicalMediaType
                InterfaceOperationalStatus = $adapter.InterfaceOperationalStatus.ToString()
                AdminStatus = $adapter.AdminStatus.ToString()
                LinkSpeed = $adapter.LinkSpeed
                MediaConnectionState = $adapter.MediaConnectionState.ToString()
                MtuSize = $adapter.MtuSize
                PromiscuousMode = $adapter.PromiscuousMode
                DeviceWakeUpEnable = $adapter.DeviceWakeUpEnable
                FullDuplex = $adapter.FullDuplex
                Virtual = $adapter.Virtual
                Hidden = $adapter.Hidden
                NotUserRemovable = $adapter.NotUserRemovable
                DriverDate = if ($adapter.DriverDate) { $adapter.DriverDate.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                DriverName = $adapter.DriverName
                DriverDescription = $adapter.DriverDescription
                DriverVersion = $adapter.DriverVersion
                DriverProvider = $adapter.DriverProvider
                DriverFileName = $adapter.DriverFileName
                NdisVersion = $adapter.NdisVersion
                DeviceID = $adapter.DeviceID
                PnPDeviceID = $adapter.PnPDeviceID
                ifOperStatus = $adapter.ifOperStatus.ToString()
                Caption = $adapter.Caption
                ConnectorPresent = $adapter.ConnectorPresent
                ifIndex = $adapter.ifIndex
                NetLuid = $adapter.NetLuid.ToString()
                NetLuidIndex = $adapter.NetLuidIndex
                NetworkAddresses = $adapter.NetworkAddresses
                ReceiveLinkSpeed = $adapter.ReceiveLinkSpeed
                TransmitLinkSpeed = $adapter.TransmitLinkSpeed
                InstanceID = $adapter.InstanceID
            }
            
            # Get detailed interface configuration and routing for this adapter
            try {
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                if ($ipConfig) {
                    $adapterDetails["IPConfiguration"] = @{
                        InterfaceAlias = $ipConfig.InterfaceAlias
                        IPv4Address = @($ipConfig.IPv4Address | ForEach-Object { 
                            @{
                                IPAddress = $_.IPAddress
                                PrefixLength = $_.PrefixLength
                                AddressState = $_.AddressState.ToString()
                                ValidLifetime = $_.ValidLifetime.ToString()
                                PreferredLifetime = $_.PreferredLifetime.ToString()
                                SkipAsSource = $_.SkipAsSource
                                PolicyStore = $_.PolicyStore
                            } 
                        })
                        IPv6Address = @($ipConfig.IPv6Address | ForEach-Object { 
                            @{
                                IPAddress = $_.IPAddress
                                PrefixLength = $_.PrefixLength
                                AddressState = $_.AddressState.ToString()
                                ValidLifetime = $_.ValidLifetime.ToString()
                                PreferredLifetime = $_.PreferredLifetime.ToString()
                                SkipAsSource = $_.SkipAsSource
                                PolicyStore = $_.PolicyStore
                            } 
                        })
                        IPv4DefaultGateway = if ($ipConfig.IPv4DefaultGateway) {
                            @($ipConfig.IPv4DefaultGateway | ForEach-Object {
                                @{
                                    NextHop = $_.NextHop
                                    InterfaceAlias = $_.InterfaceAlias
                                    InterfaceIndex = $_.InterfaceIndex
                                    RouteMetric = $_.RouteMetric
                                    Store = $_.Store
                                }
                            })
                        } else { @() }
                        IPv6DefaultGateway = if ($ipConfig.IPv6DefaultGateway) {
                            @($ipConfig.IPv6DefaultGateway | ForEach-Object {
                                @{
                                    NextHop = $_.NextHop
                                    InterfaceAlias = $_.InterfaceAlias
                                    InterfaceIndex = $_.InterfaceIndex
                                    RouteMetric = $_.RouteMetric
                                    Store = $_.Store
                                }
                            })
                        } else { @() }
                        DNSServer = @($ipConfig.DNSServer | ForEach-Object {
                            @{
                                Address = $_.ServerAddresses
                                AddressFamily = $_.AddressFamily.ToString()
                                InterfaceAlias = $_.InterfaceAlias
                                InterfaceIndex = $_.InterfaceIndex
                            }
                        })
                        NetProfile = if ($ipConfig.NetProfile) {
                            @{
                                Name = $ipConfig.NetProfile.Name
                                NetworkCategory = $ipConfig.NetProfile.NetworkCategory.ToString()
                                IPv4Connectivity = $ipConfig.NetProfile.IPv4Connectivity.ToString()
                                IPv6Connectivity = $ipConfig.NetProfile.IPv6Connectivity.ToString()
                                DomainAuthenticationKind = $ipConfig.NetProfile.DomainAuthenticationKind.ToString()
                            }
                        } else { $null }
                    }
                }
            } catch {
                $adapterDetails["IPConfigurationError"] = $_.Exception.Message
            }

            # Get detailed network adapter statistics
            try {
                $stats = $adapter | Get-NetAdapterStatistics -ErrorAction SilentlyContinue
                if ($stats) {
                    $adapterDetails["Statistics"] = @{
                        ReceivedBytes = $stats.ReceivedBytes
                        ReceivedUnicastPackets = $stats.ReceivedUnicastPackets
                        ReceivedMulticastPackets = $stats.ReceivedMulticastPackets
                        ReceivedBroadcastPackets = $stats.ReceivedBroadcastPackets
                        ReceivedDiscardedPackets = $stats.ReceivedDiscardedPackets
                        ReceivedErrors = $stats.ReceivedErrors
                        ReceivedUnknownProtocolPackets = $stats.ReceivedUnknownProtocolPackets
                        SentBytes = $stats.SentBytes
                        SentUnicastPackets = $stats.SentUnicastPackets
                        SentMulticastPackets = $stats.SentMulticastPackets
                        SentBroadcastPackets = $stats.SentBroadcastPackets
                        SentDiscardedPackets = $stats.SentDiscardedPackets
                        SentErrors = $stats.SentErrors
                        RscStatistics = if ($stats.RscStatistics) {
                            @{
                                CoalescedBytes = $stats.RscStatistics.CoalescedBytes
                                CoalescedPackets = $stats.RscStatistics.CoalescedPackets
                                CoalesceEvents = $stats.RscStatistics.CoalesceEvents
                                RscIPv4 = $stats.RscStatistics.RscIPv4
                                RscIPv6 = $stats.RscStatistics.RscIPv6
                            }
                        } else { $null }
                    }
                }
            } catch {
                $adapterDetails["StatisticsError"] = $_.Exception.Message
            }
            
            # Get detailed advanced properties
            try {
                $advProps = $adapter | Get-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue
                if ($advProps) {
                    $adapterDetails["AdvancedProperties"] = @($advProps | ForEach-Object {
                        @{
                            Name = $_.Name
                            DisplayName = $_.DisplayName
                            DisplayValue = $_.DisplayValue
                            RegistryKeyword = $_.RegistryKeyword
                            RegistryValue = $_.RegistryValue
                            ValidDisplayValues = $_.ValidDisplayValues
                        }
                    })
                }
            } catch {
                $adapterDetails["AdvancedPropertiesError"] = $_.Exception.Message
            }
            
            # Get power management settings
            try {
                $power = $adapter | Get-NetAdapterPowerManagement -ErrorAction SilentlyContinue
                if ($power) {
                    $adapterDetails["PowerManagement"] = @{
                        ArpOffload = $power.ArpOffload.ToString()
                        D0PacketCoalescing = $power.D0PacketCoalescing.ToString()
                        DeviceSleepOnDisconnect = $power.DeviceSleepOnDisconnect.ToString()
                        NSOffload = $power.NSOffload.ToString()
                        SelectiveSuspend = $power.SelectiveSuspend.ToString()
                        WakeOnMagicPacket = $power.WakeOnMagicPacket.ToString()
                        WakeOnPattern = $power.WakeOnPattern.ToString()
                    }
                }
            } catch {
                $adapterDetails["PowerManagementError"] = $_.Exception.Message
            }
            
            # Get VLAN settings
            try {
                $vlan = $adapter | Get-NetAdapterVmq -ErrorAction SilentlyContinue
                if ($vlan) {
                    $adapterDetails["VMQ"] = @{
                        Enabled = $vlan.Enabled
                        BaseProcessorNumber = $vlan.BaseProcessorNumber
                        MaxProcessors = $vlan.MaxProcessors
                        NumaNode = $vlan.NumaNode
                        MaxProcessorNumber = $vlan.MaxProcessorNumber
                    }
                }
            } catch {
                # VMQ not supported on this adapter
            }

            # Add comprehensive adapter details to the global collection
            $global:networkInfo.NetworkAdapters += $adapterDetails
            $global:networkInfo.FullNetworkAdapterProperties += $adapter | ConvertTo-Json -Depth 5 | ConvertFrom-Json
            
            # Add interface metric information
            try {
                $ifMetric = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                if ($ifMetric) {
                    $global:networkInfo.InterfaceMetrics += @($ifMetric | ForEach-Object {
                        @{
                            InterfaceIndex = $_.InterfaceIndex
                            InterfaceAlias = $_.InterfaceAlias
                            AddressFamily = $_.AddressFamily.ToString()
                            InterfaceMetric = $_.InterfaceMetric
                            AutomaticMetric = $_.AutomaticMetric
                            Dhcp = $_.Dhcp.ToString()
                            ConnectionState = $_.ConnectionState.ToString()
                        }
                    })
                }
            } catch {}
            
            # Get binding information
            try {
                $bindings = Get-NetAdapterBinding -InterfaceAlias $adapter.InterfaceAlias -ErrorAction SilentlyContinue
                if ($bindings) {
                    $global:networkInfo.BindingInformation += @($bindings | ForEach-Object {
                        @{
                            Name = $_.Name
                            DisplayName = $_.DisplayName
                            ComponentID = $_.ComponentID
                            Enabled = $_.Enabled
                            InterfaceDescription = $_.InterfaceDescription
                            InterfaceAlias = $_.InterfaceAlias
                        }
                    })
                }
            } catch {}
            
            # Get raw adapter statistics for detailed analysis
            try {
                $rawStats = $adapter | Get-NetAdapterStatistics -ErrorAction SilentlyContinue | 
                    Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties
                if ($rawStats) {
                    $global:networkInfo.RawNetAdapterStatistics += $rawStats
                }
            } catch {}
        }
        
        # Add individual findings for each active adapter
        foreach ($adapter in ($adapters | Where-Object { $_.Status -eq "Up" })) {
            $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            
            $adapterFindingInfo = @{
                Name = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                Status = $adapter.Status.ToString()
                MacAddress = $adapter.MacAddress
                LinkSpeed = $adapter.LinkSpeed
                MediaConnectionState = $adapter.MediaConnectionState.ToString()
                IPAddresses = @($ipInfo | ForEach-Object {
                    @{
                        IPAddress = $_.IPAddress
                        AddressFamily = $_.AddressFamily.ToString()
                        PrefixLength = $_.PrefixLength
                        Type = $_.Type.ToString()
                        AddressState = $_.AddressState.ToString()
                    }
                })
                Virtual = $adapter.Virtual
                DriverVersion = $adapter.DriverVersion
                DriverProvider = $adapter.DriverProvider
                ComponentID = $adapter.ComponentID
                DeviceID = $adapter.DeviceID
            }
            
            Add-Finding -CheckName "Network Adapter: $($adapter.Name)" -Status "Info" `
                -Details "Status: $($adapter.Status), MAC: $($adapter.MacAddress)" -Category "NetworkConfig" `
                -AdditionalInfo $adapterFindingInfo
        }
    } else {
        Write-Output "No network adapters found."
        
        Add-Finding -CheckName "Network Adapters" -Status "Info" `
            -Details "No network adapters found." -Category "NetworkConfig" `
            -AdditionalInfo @{
                Error = "No network adapters could be detected"
                PossibleCauses = @(
                    "Hardware failure",
                    "Missing drivers",
                    "Disabled in BIOS/UEFI",
                    "Disabled in Device Manager"
                )
            }
    }
}
function Test-IPConfiguration {
    Write-SectionHeader "IP Configuration"
    
    # Get detailed IP configuration
    $ipconfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue
    
    if ($ipconfig) {
        # Create detailed array for all network adapters
        $detailedIpConfig = @()
        
        foreach ($adapter in $ipconfig) {
            Write-Output "Interface: $($adapter.InterfaceAlias)"
            
            # Get IPv4 address information
            if ($adapter.IPv4Address) {
                $ipv4Addresses = @($adapter.IPv4Address | ForEach-Object {
                    @{
                        IPAddress = $_.IPAddress
                        PrefixLength = $_.PrefixLength
                        AddressState = $_.AddressState.ToString()
                        ValidLifetime = $_.ValidLifetime.ToString()
                        PreferredLifetime = $_.PreferredLifetime.ToString()
                        SkipAsSource = $_.SkipAsSource
                        PolicyStore = $_.PolicyStore
                        Type = $_.Type.ToString()
                    }
                })
                
                foreach ($ipv4 in $adapter.IPv4Address) {
                    Write-Output "  IPv4: $($ipv4.IPAddress)/$($ipv4.PrefixLength)"
                }
            }
            
            # Get IPv6 address information
            $ipv6Addresses = @()
            if ($adapter.IPv6Address) {
                $ipv6Addresses = @($adapter.IPv6Address | ForEach-Object {
                    @{
                        IPAddress = $_.IPAddress
                        PrefixLength = $_.PrefixLength
                        AddressState = $_.AddressState.ToString()
                        ValidLifetime = $_.ValidLifetime.ToString()
                        PreferredLifetime = $_.PreferredLifetime.ToString()
                        SkipAsSource = $_.SkipAsSource
                        PolicyStore = $_.PolicyStore
                        Type = $_.Type.ToString()
                    }
                })
                
                foreach ($ipv6 in $adapter.IPv6Address) {
                    Write-Output "  IPv6: $($ipv6.IPAddress)/$($ipv6.PrefixLength)"
                }
            }
            
            # Get gateway information
            $ipv4Gateways = @()
            if ($adapter.IPv4DefaultGateway) {
                $ipv4Gateways = @($adapter.IPv4DefaultGateway | ForEach-Object {
                    @{
                        NextHop = $_.NextHop
                        InterfaceAlias = $_.InterfaceAlias
                        InterfaceIndex = $_.InterfaceIndex
                        RouteMetric = $_.RouteMetric
                        Store = $_.Store
                    }
                })
                
                foreach ($gateway in $adapter.IPv4DefaultGateway) {
                    Write-Output "  Gateway: $($gateway.NextHop) (Metric: $($gateway.RouteMetric))"
                }
            }
            
            # Get IPv6 gateway information
            $ipv6Gateways = @()
            if ($adapter.IPv6DefaultGateway) {
                $ipv6Gateways = @($adapter.IPv6DefaultGateway | ForEach-Object {
                    @{
                        NextHop = $_.NextHop
                        InterfaceAlias = $_.InterfaceAlias
                        InterfaceIndex = $_.InterfaceIndex
                        RouteMetric = $_.RouteMetric
                        Store = $_.Store
                    }
                })
                
                foreach ($gateway in $adapter.IPv6DefaultGateway) {
                    Write-Output "  IPv6 Gateway: $($gateway.NextHop) (Metric: $($gateway.RouteMetric))"
                }
            }
            
            # Get DNS server information
            $dnsServers = @()
            if ($adapter.DNSServer) {
                $dnsServers = @($adapter.DNSServer | ForEach-Object {
                    @{
                        ServerAddresses = $_.ServerAddresses
                        AddressFamily = $_.AddressFamily.ToString()
                        InterfaceAlias = $_.InterfaceAlias
                        InterfaceIndex = $_.InterfaceIndex
                    }
                })
                
                foreach ($dns in $adapter.DNSServer) {
                    if ($dns.ServerAddresses) {
                        Write-Output "  DNS Servers: $($dns.ServerAddresses -join ', ')"
                    }
                }
            }
            
            # Get network profile information
            $networkProfile = $null
            if ($adapter.NetProfile) {
                $networkProfile = @{
                    Name = $adapter.NetProfile.Name
                    NetworkCategory = $adapter.NetProfile.NetworkCategory.ToString()
                    IPv4Connectivity = $adapter.NetProfile.IPv4Connectivity.ToString()
                    IPv6Connectivity = $adapter.NetProfile.IPv6Connectivity.ToString()
                    DomainAuthenticationKind = $adapter.NetProfile.DomainAuthenticationKind.ToString()
                }
                
                Write-Output "  Network Profile: $($adapter.NetProfile.Name) ($($adapter.NetProfile.NetworkCategory))"
                Write-Output "  IPv4 Connectivity: $($adapter.NetProfile.IPv4Connectivity)"
                Write-Output "  IPv6 Connectivity: $($adapter.NetProfile.IPv6Connectivity)"
            }
            
            # Combine all information into a detailed object
            $adapterDetails = @{
                InterfaceAlias = $adapter.InterfaceAlias
                InterfaceIndex = $adapter.InterfaceIndex
                InterfaceDescription = $adapter.InterfaceDescription
                NetAdapter = @{
                    Name = $adapter.NetAdapter.Name
                    InterfaceDescription = $adapter.NetAdapter.InterfaceDescription
                    Status = $adapter.NetAdapter.Status.ToString()
                    MacAddress = $adapter.NetAdapter.MacAddress
                    LinkSpeed = $adapter.NetAdapter.LinkSpeed
                }
                IPv4Address = $ipv4Addresses
                IPv6Address = $ipv6Addresses
                IPv4DefaultGateway = $ipv4Gateways
                IPv6DefaultGateway = $ipv6Gateways
                DNSServer = $dnsServers
                NetProfile = $networkProfile
                CompartmentId = $adapter.CompartmentId
                NetworkCards = $adapter.NetworkCards | ForEach-Object { 
                    @{
                        Name = $_.Name 
                        InterfaceIndex = $_.InterfaceIndex
                        Description = $_.Description
                    }
                }
            }
            
            # Add detailed adapter info to our collection
            $detailedIpConfig += $adapterDetails
        }
        
        # Store detailed information in the global variable for JSON output
        $global:networkInfo.DetailedIPConfiguration = $detailedIpConfig
        $global:networkInfo.IPConfiguration += $detailedIpConfig
        
        # Add IP configuration finding for each network adapter
        foreach ($adapter in $detailedIpConfig) {
            $addressInfo = if ($adapter.IPv4Address) {
                "$($adapter.IPv4Address.Count) IPv4 addresses, " +
                "Primary: $($adapter.IPv4Address[0].IPAddress)/$($adapter.IPv4Address[0].PrefixLength)"
            } else {
                "No IPv4 address"
            }
            
            Add-Finding -CheckName "IP Configuration: $($adapter.InterfaceAlias)" -Status "Info" `
                -Details $addressInfo -Category "NetworkConfig" `
                -AdditionalInfo $adapter
        }
    } else {
        Write-Output "No IP configuration found."
        
        Add-Finding -CheckName "IP Configuration" -Status "Warning" `
            -Details "Failed to retrieve IP configuration" -Category "NetworkConfig" `
            -AdditionalInfo @{
                Error = "Unable to retrieve network adapter IP configuration"
                PossibleCauses = @(
                    "Network adapters disabled",
                    "Insufficient permissions",
                    "Network components not functioning properly"
                )
                CommandAttempted = "Get-NetIPConfiguration"
            }
    }
}
function Test-FirewallProfiles {
    Write-SectionHeader "Firewall Status"
    $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    
    if ($firewall) {
        # Display basic information in the console
        $firewall | Select-Object Name, Enabled | Format-Table -AutoSize
        
        # Create comprehensive firewall profile information for JSON output
        $firewallDetails = $firewall | ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction.ToString()
                DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
                AllowInboundRules = $_.AllowInboundRules.ToString()
                AllowLocalFirewallRules = $_.AllowLocalFirewallRules.ToString()
                AllowLocalIPsecRules = $_.AllowLocalIPsecRules.ToString()
                AllowUserApps = $_.AllowUserApps.ToString()
                AllowUserPorts = $_.AllowUserPorts.ToString()
                AllowUnicastResponseToMulticast = $_.AllowUnicastResponseToMulticast.ToString()
                NotifyOnListen = $_.NotifyOnListen.ToString()
                EnableStealthModeForIPsec = $_.EnableStealthModeForIPsec.ToString()
                LogFileName = $_.LogFileName
                LogMaxSizeKilobytes = $_.LogMaxSizeKilobytes
                LogAllowed = $_.LogAllowed.ToString()
                LogBlocked = $_.LogBlocked.ToString()
                LogIgnored = $_.LogIgnored.ToString()
                DisabledInterfaceAliases = $_.DisabledInterfaceAliases
                PolicyStoreSource = $_.PolicyStoreSource
                PolicyStoreSourceType = $_.PolicyStoreSourceType.ToString()
                AssessmentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        # Store in global network info
        if (-not (Get-Variable -Name networkInfo -Scope Global -ErrorAction SilentlyContinue)) {
            $global:networkInfo = @{
                NetworkAdapters = @()
                IPConfiguration = @()
                FirewallProfiles = @()
                RiskyFirewallRules = @()
                SMBConfiguration = $null
                FullNetworkAdapterProperties = @()
                DetailedIPConfiguration = @()
                CompleteFirewallRules = @()
                RawNetAdapterStatistics = @()
                NetworkConnectionDetails = @()
                InterfaceMetrics = @()
                BindingInformation = @()
                AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        $global:networkInfo.FirewallProfiles = $firewallDetails
        
        # Check if all profiles are enabled
        $allEnabled = ($firewall | Where-Object { $_.Enabled -eq $false }).Count -eq 0
        
        if ($allEnabled) {
            Write-Output "PASS: All firewall profiles are enabled."
            Add-Finding -CheckName "Windows Firewall" -Status "Pass" `
                -Details "All firewall profiles are enabled." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    AllProfilesEnabled = $true
                    ProfileDetails = $firewallDetails
                    LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    SecurityBenefits = "Firewall protects against unauthorized network access and helps prevent malware communication"
                }
        } else {
            # Get specific disabled profiles for more detailed information
            $disabledProfiles = $firewall | Where-Object { $_.Enabled -eq $false } | ForEach-Object { $_.Name }
            
            Write-Output "FAIL: One or more firewall profiles are disabled: $($disabledProfiles -join ', ')"
            
            Add-Finding -CheckName "Windows Firewall" -Status "Fail" `
                -Details "One or more firewall profiles are disabled: $($disabledProfiles -join ', ')" -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    AllProfilesEnabled = $false
                    DisabledProfiles = $disabledProfiles
                    EnabledProfiles = ($firewall | Where-Object { $_.Enabled -eq $true } | ForEach-Object { $_.Name })
                    ProfileDetails = $firewallDetails
                    LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    SecurityRisk = "Disabled firewall profiles may allow unauthorized network access or malware communication"
                    Recommendation = "Enable all firewall profiles to protect against network-based attacks"
                }
        }
        
        # Add a comprehensive firewall assessment finding with full details
        Add-Finding -CheckName "Firewall Configuration Assessment" -Status "Info" `
            -Details "Detailed analysis of Windows Firewall configuration." -Category "NetworkSecurity" `
            -AdditionalInfo @{
                FirewallProfiles = $firewallDetails
                ProfileCount = $firewall.Count
                EnabledProfileCount = ($firewall | Where-Object { $_.Enabled -eq $true }).Count
                DisabledProfileCount = ($firewall | Where-Object { $_.Enabled -eq $false }).Count
                LoggingDetails = $firewallDetails | ForEach-Object {
                    @{
                        ProfileName = $_.Name
                        LogFileName = $_.LogFileName
                        LogMaxSizeKilobytes = $_.LogMaxSizeKilobytes
                        LogAllowed = $_.LogAllowed
                        LogBlocked = $_.LogBlocked
                        LogIgnored = $_.LogIgnored
                    }
                }
                DefaultActions = $firewallDetails | ForEach-Object {
                    @{
                        ProfileName = $_.Name
                        DefaultInboundAction = $_.DefaultInboundAction
                        DefaultOutboundAction = $_.DefaultOutboundAction
                    }
                }
                AssessmentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                CheckedBy = $env:USERNAME
                Hostname = $env:COMPUTERNAME
                OSVersion = [System.Environment]::OSVersion.VersionString
            }
    } else {
        Write-Output "Failed to retrieve firewall profiles."
        
        Add-Finding -CheckName "Windows Firewall" -Status "Fail" `
            -Details "Failed to retrieve firewall profile information." -Category "NetworkSecurity" `
            -AdditionalInfo @{
                Error = "Could not access firewall profiles"
                PossibleCauses = @(
                    "Windows Firewall service not running",
                    "Insufficient permissions",
                    "Group Policy restrictions",
                    "Windows Firewall components corrupted"
                )
                LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Hostname = $env:COMPUTERNAME
                Username = $env:USERNAME
                OSVersion = [System.Environment]::OSVersion.VersionString
                RecommendedAction = "Verify Windows Firewall service is running and accessible"
            }
    }
}

function Test-RiskyFirewallRules {
    Write-SectionHeader "Risky Firewall Rules"
    $allRules = Get-NetFirewallRule -ErrorAction SilentlyContinue
    
    # Create comprehensive object for JSON output
    $firewallRuleDetails = @{
        TotalRulesChecked = 0
        RiskyRulesCount = 0
        RiskyRules = @()
        RuleCheckTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AssessmentHost = $env:COMPUTERNAME
    }
    
    if ($allRules) {
        $firewallRuleDetails.TotalRulesChecked = $allRules.Count
        
        # Get fully detailed risky rule information
        $riskyRules = $allRules | Where-Object {
            $_.Enabled -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and 
            ($_.RemoteAddress -eq "Any" -or $_.RemoteAddress -eq "*")
        }
        
        if ($riskyRules) {
            $firewallRuleDetails.RiskyRulesCount = $riskyRules.Count
            
            # Display basic information in console
            Write-Output "Found $($riskyRules.Count) risky firewall rules:"
            $riskyRules | Select-Object DisplayName, Direction, Action, RemoteAddress | Format-Table -AutoSize
            
            # Create detailed rule information for each risky rule
            foreach ($rule in $riskyRules) {
                # Get additional detailed properties for each rule
                $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                $securityFilter = $rule | Get-NetFirewallSecurityFilter -ErrorAction SilentlyContinue
                $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
                $interfaceFilter = $rule | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue
                
                # Create comprehensive rule details
                $ruleDetails = @{
                    Name = $rule.Name
                    DisplayName = $rule.DisplayName
                    Description = $rule.Description
                    DisplayGroup = $rule.DisplayGroup
                    Group = $rule.Group
                    Enabled = $rule.Enabled
                    Profile = $rule.Profile.ToString()
                    Platform = $rule.Platform
                    Direction = $rule.Direction.ToString()
                    Action = $rule.Action.ToString()
                    EdgeTraversalPolicy = $rule.EdgeTraversalPolicy.ToString()
                    LooseSourceMapping = $rule.LooseSourceMapping
                    LocalOnlyMapping = $rule.LocalOnlyMapping
                    Owner = $rule.Owner
                    Status = $rule.Status
                    EnforcementStatus = $rule.EnforcementStatus.ToString()
                    PolicyStoreSource = $rule.PolicyStoreSource
                    PolicyStoreSourceType = $rule.PolicyStoreSourceType.ToString()
                    PrimaryStatus = $rule.PrimaryStatus.ToString()
                    RuleGroup = $rule.RuleGroup
                    SecurityRisk = "Allows inbound connections from any IP address"
                    PortFilter = if ($portFilter) {
                        @{
                            Protocol = $portFilter.Protocol
                            LocalPort = $portFilter.LocalPort
                            RemotePort = $portFilter.RemotePort
                            IcmpType = $portFilter.IcmpType
                            DynamicTarget = $portFilter.DynamicTarget.ToString()
                        }
                    } else { $null }
                    AddressFilter = if ($addressFilter) {
                        @{
                            LocalAddress = $addressFilter.LocalAddress
                            RemoteAddress = $addressFilter.RemoteAddress
                        }
                    } else { $null }
                    SecurityFilter = if ($securityFilter) {
                        @{
                            Authentication = $securityFilter.Authentication.ToString()
                            Encryption = $securityFilter.Encryption.ToString()
                            OverrideBlockRules = $securityFilter.OverrideBlockRules
                            LocalUser = $securityFilter.LocalUser
                            RemoteUser = $securityFilter.RemoteUser
                            RemoteMachine = $securityFilter.RemoteMachine
                        }
                    } else { $null }
                    ApplicationFilter = if ($applicationFilter) {
                        @{
                            Program = $applicationFilter.Program
                            Package = $applicationFilter.Package
                        }
                    } else { $null }
                    ServiceFilter = if ($serviceFilter) {
                        @{
                            Service = $serviceFilter.Service
                        }
                    } else { $null }
                    InterfaceFilter = if ($interfaceFilter) {
                        @{
                            InterfaceAlias = $interfaceFilter.InterfaceAlias
                            InterfaceType = $interfaceFilter.InterfaceType.ToString()
                        }
                    } else { $null }
                    DetectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                # Add to the collection
                $firewallRuleDetails.RiskyRules += $ruleDetails
            }
            
            # Store in global network info
            $global:networkInfo.RiskyFirewallRules = $firewallRuleDetails.RiskyRules
            $global:networkInfo.CompleteFirewallRules += $firewallRuleDetails.RiskyRules
            
            # Add comprehensive finding with full details
            Add-Finding -CheckName "Risky Firewall Rules" -Status "Warning" `
                -Details "Found $($riskyRules.Count) risky inbound firewall rules allowing connections from any IP address." -Category "NetworkSecurity" `
                -AdditionalInfo $firewallRuleDetails
                
            # Add individual detailed findings for each risky rule for better filtering
            foreach ($ruleDetail in $firewallRuleDetails.RiskyRules) {
                $ports = if ($ruleDetail.PortFilter.LocalPort -and $ruleDetail.PortFilter.LocalPort -ne "Any") {
                    " on port(s) $($ruleDetail.PortFilter.LocalPort)"
                } else {
                    " on any port"
                }
                
                $protocol = if ($ruleDetail.PortFilter.Protocol -and $ruleDetail.PortFilter.Protocol -ne "Any") {
                    " ($($ruleDetail.PortFilter.Protocol))"
                } else {
                    " (any protocol)"
                }
                
                Add-Finding -CheckName "Risky Rule: $($ruleDetail.DisplayName)" -Status "Warning" `
                    -Details "Allows inbound connections from any IP$ports$protocol" -Category "NetworkSecurity" `
                    -AdditionalInfo $ruleDetail
            }
        } else {
            Write-Output "No risky firewall rules found."
            $firewallRuleDetails.RiskyRulesCount = 0
            
            Add-Finding -CheckName "Risky Firewall Rules" -Status "Pass" `
                -Details "No risky inbound firewall rules detected." -Category "NetworkSecurity" `
                -AdditionalInfo $firewallRuleDetails
        }
    } else {
        Write-Output "Failed to retrieve firewall rules."
        $firewallRuleDetails.ErrorRetrievingRules = $true
        
        Add-Finding -CheckName "Firewall Rules" -Status "Warning" `
            -Details "Failed to retrieve firewall rules." -Category "NetworkSecurity" `
            -AdditionalInfo @{
                Error = "Could not access Windows Firewall rules"
                PossibleCauses = @(
                    "Windows Firewall service not running",
                    "Insufficient permissions",
                    "Group Policy restrictions",
                    "Windows Firewall components corrupted"
                )
                FirewallServiceStatus = (Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue).Status.ToString()
                TroubleshootingSteps = @(
                    "Ensure Windows Firewall service is running",
                    "Run the script with administrative privileges",
                    "Check Group Policy settings for Windows Firewall"
                )
            }
    }
}

function Test-SMBConfiguration {
    Write-SectionHeader "SMB Configuration"
    
    # Create detailed SMB configuration object for JSON output
    $smbConfigInfo = @{
        ConfigurationRetrieved = $false
        SMBv1Enabled = $null
        SMBv2Enabled = $null
        EncryptData = $null
        RejectUnencryptedAccess = $null
        SigningEnabled = $null
        SigningRequired = $null
        ServerDetails = @{}
        ClientDetails = @{}
        SecurityRisks = @()
        Recommendations = @()
        RawConfiguration = $null
        AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    # Get server configuration
    try {
        $smbServer = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smbServer) {
            $smbConfigInfo.ConfigurationRetrieved = $true
            $smbConfigInfo.SMBv1Enabled = $smbServer.EnableSMB1Protocol
            $smbConfigInfo.SMBv2Enabled = $smbServer.EnableSMB2Protocol
            $smbConfigInfo.EncryptData = $smbServer.EncryptData
            $smbConfigInfo.RejectUnencryptedAccess = $smbServer.RejectUnencryptedAccess
            $smbConfigInfo.SigningEnabled = $smbServer.EnableSecuritySignature
            $smbConfigInfo.SigningRequired = $smbServer.RequireSecuritySignature

            # Store all server properties for complete data preservation
            $smbConfigInfo.ServerDetails = $smbServer | ForEach-Object {
                $properties = @{}
                $_.PSObject.Properties | ForEach-Object {
                    if ($_.Name -notin @('PSComputerName','PSShowComputerName','CimClass','CimInstanceProperties','CimSystemProperties')) {
                        $properties[$_.Name] = $_.Value
                    }
                }
                $properties
            }
            
            # Add security risks and recommendations based on configuration
            if ($smbServer.EnableSMB1Protocol) {
                $smbConfigInfo.SecurityRisks += "SMBv1 is enabled, which is vulnerable to EternalBlue and other exploits"
                $smbConfigInfo.Recommendations += "Disable SMBv1 using 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'"
            }
            
            if (-not $smbServer.RequireSecuritySignature) {
                $smbConfigInfo.SecurityRisks += "SMB signing is not required, which allows potential man-in-the-middle attacks"
                $smbConfigInfo.Recommendations += "Enable required SMB signing using 'Set-SmbServerConfiguration -RequireSecuritySignature $true'"
            }
            
            if (-not $smbServer.EncryptData) {
                $smbConfigInfo.SecurityRisks += "SMB encryption is not enabled by default"
                $smbConfigInfo.Recommendations += "Consider enabling SMB encryption using 'Set-SmbServerConfiguration -EncryptData $true'"
            }
            
            # Store raw configuration for reference
            $smbConfigInfo.RawConfiguration = $smbServer | ConvertTo-Json -Depth 5 | ConvertFrom-Json
            
            Write-Output "SMBv1 Enabled: $($smbServer.EnableSMB1Protocol)"
            Write-Output "SMBv2 Enabled: $($smbServer.EnableSMB2Protocol)"
            Write-Output "Signing Enabled: $($smbServer.EnableSecuritySignature)"
            Write-Output "Signing Required: $($smbServer.RequireSecuritySignature)"
            Write-Output "Encryption Enabled: $($smbServer.EncryptData)"
            
            # Store in global network info
            $global:networkInfo.SMBConfiguration = $smbConfigInfo
            
            # Add detailed finding with full information
            Add-Finding -CheckName "SMB Configuration" -Status $(if ($smbServer.EnableSMB1Protocol) { "Fail" } else { "Pass" }) `
                -Details $(if ($smbServer.EnableSMB1Protocol) { "SMBv1 is enabled, which is a security risk." } else { "SMBv1 is properly disabled." }) `
                -Category "NetworkSecurity" `
                -AdditionalInfo $smbConfigInfo
        }
    }
    catch {
        Write-Output "Failed to retrieve SMB server configuration: $_"
        $smbConfigInfo.ConfigurationRetrieved = $false
        $smbConfigInfo.RetrievalError = $_.Exception.Message
        
        # Store in global network info even with error
        $global:networkInfo.SMBConfiguration = $smbConfigInfo
        
        Add-Finding -CheckName "SMB Configuration" -Status "Warning" `
            -Details "Failed to retrieve SMB configuration: $($_.Exception.Message)" `
            -Category "NetworkSecurity" `
            -AdditionalInfo $smbConfigInfo
    }
    
    # Try to get client configuration as well for more complete information
    try {
        $smbClient = Get-SmbClientConfiguration -ErrorAction Stop
        if ($smbClient) {
            # Store all client properties
            $smbConfigInfo.ClientDetails = $smbClient | ForEach-Object {
                $properties = @{}
                $_.PSObject.Properties | ForEach-Object {
                    if ($_.Name -notin @('PSComputerName','PSShowComputerName','CimClass','CimInstanceProperties','CimSystemProperties')) {
                        $properties[$_.Name] = $_.Value
                    }
                }
                $properties
            }
            
            # Update additional security risks and recommendations based on client config
            if ($smbClient.EnableSMB1Protocol) {
                $smbConfigInfo.SecurityRisks += "SMB Client has SMBv1 enabled, which is vulnerable to attacks"
                $smbConfigInfo.Recommendations += "Disable SMBv1 client using 'Set-SmbClientConfiguration -EnableSMB1Protocol $false'"
            }
            
            if (-not $smbClient.RequireSecuritySignature) {
                $smbConfigInfo.SecurityRisks += "SMB Client does not require signing, which allows potential man-in-the-middle attacks"
                $smbConfigInfo.Recommendations += "Enable required client SMB signing using 'Set-SmbClientConfiguration -RequireSecuritySignature $true'"
            }
        }
    }
    catch {
        # Client configuration optional, so just log the error in the object
        $smbConfigInfo.ClientConfigError = $_.Exception.Message
    }
}

function Get-NetworkConnectionDetails {
    Write-SectionHeader "Network Connection Details"
    
    $connectionsInfo = @{
        ConnectionCount = 0
        Connections = @()
        ProcessDetails = @{}
        CommonPorts = @{
            "80" = "HTTP"
            "443" = "HTTPS"
            "21" = "FTP"
            "22" = "SSH"
            "23" = "Telnet"
            "25" = "SMTP"
            "53" = "DNS"
            "110" = "POP3"
            "143" = "IMAP"
            "389" = "LDAP"
            "445" = "SMB"
            "3389" = "RDP"
            "5985" = "WinRM-HTTP"
            "5986" = "WinRM-HTTPS"
            "1433" = "MSSQL"
            "3306" = "MySQL"
            "5432" = "PostgreSQL"
            "27017" = "MongoDB"
            "8080" = "HTTP-ALT"
            "8443" = "HTTPS-ALT"
            "6379" = "Redis"
        }
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ScanPerformedBy = $env:USERNAME
        HostName = $env:COMPUTERNAME
    }
    
    try {
        # Get all TCP connections
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
        
        if ($connections) {
            $connectionsInfo.ConnectionCount = $connections.Count
            
            # Get process details for all connections in one batch for efficiency
            $uniqueProcessIds = $connections | Select-Object -ExpandProperty OwningProcess -Unique
            $processes = @{}
            foreach ($pid in $uniqueProcessIds) {
                try {
                    $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    if ($process) {
                        $processes[$pid] = @{
                            ProcessName = $process.Name
                            ProcessPath = $process.Path
                            CommandLine = if ($process.CommandLine) { $process.CommandLine } else { $null }
                            StartTime = if ($process.StartTime) { $process.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                            WorkingSet = $process.WorkingSet64
                            HandleCount = $process.HandleCount
                            Responding = $process.Responding
                            PriorityClass = if ($process.PriorityClass) { $process.PriorityClass.ToString() } else { "Unknown" }
                            HasExited = if ($process.HasExited) { $process.HasExited } else { $false }
                            SessionId = $process.SessionId
                        }
                    } else {
                        $processes[$pid] = @{
                            ProcessName = "Unknown"
                            ProcessPath = $null
                            CommandLine = $null
                            Note = "Process no longer exists"
                        }
                    }
                }
                catch {
                    $processes[$pid] = @{
                        ProcessName = "Error"
                        ProcessPath = $null
                        CommandLine = $null
                        Error = $_.Exception.Message
                        ErrorType = $_.Exception.GetType().Name
                    }
                }
            }
            
            # Store all process details in the connections info
            $connectionsInfo.ProcessDetails = $processes
            
            # Process each connection with full details
            foreach ($conn in $connections) {
                # Create a detailed connection object preserving all properties
                $detailedConnection = @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    State = $conn.State.ToString()
                    OwningProcess = $conn.OwningProcess
                    ProcessName = $processes[$conn.OwningProcess].ProcessName
                    ProcessPath = $processes[$conn.OwningProcess].ProcessPath
                    CreationTime = if ($conn.CreationTime) { $conn.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                    OffloadState = if ($conn.OffloadState) { $conn.OffloadState.ToString() } else { $null }
                    AppliedSetting = $conn.AppliedSetting
                    ProtocolType = $conn.ProtocolType.ToString()
                    LocalEndPoint = "$($conn.LocalAddress):$($conn.LocalPort)"
                    RemoteEndPoint = "$($conn.RemoteAddress):$($conn.RemotePort)"
                    ServiceName = if ($connectionsInfo.CommonPorts.ContainsKey($conn.RemotePort.ToString())) {
                        $connectionsInfo.CommonPorts[$conn.RemotePort.ToString()]
                    } elseif ($connectionsInfo.CommonPorts.ContainsKey($conn.LocalPort.ToString())) {
                        $connectionsInfo.CommonPorts[$conn.LocalPort.ToString()]
                    } else {
                        $null
                    }
                    IsListening = $conn.State -eq "Listen"
                    IsEstablished = $conn.State -eq "Established"
                    IsLoopback = $conn.RemoteAddress -in @("127.0.0.1", "::1", "localhost") -or
                                 $conn.LocalAddress -in @("127.0.0.1", "::1", "localhost")
                    IsIPv6 = $conn.LocalAddress -match ":" -or $conn.RemoteAddress -match ":"
                    RawProperties = ($conn | Get-Member -MemberType Property | 
                        Select-Object -ExpandProperty Name) -join ", "
                }
                
                # Add this connection to our collection
                $connectionsInfo.Connections += $detailedConnection
            }
            
            # Display basic counts in the console output
            $establishedCount = ($connections | Where-Object { $_.State -eq "Established" }).Count
            $listeningCount = ($connections | Where-Object { $_.State -eq "Listen" }).Count
            
            Write-Output "Found $($connections.Count) TCP connections ($establishedCount established, $listeningCount listening)"
            
            # Store in global network info
            if (-not $global:networkInfo) {
                $global:networkInfo = @{
                    NetworkAdapters = @()
                    IPConfiguration = @()
                    FirewallProfiles = @()
                    RiskyFirewallRules = @()
                    SMBConfiguration = $null
                    FullNetworkAdapterProperties = @()
                    DetailedIPConfiguration = @()
                    CompleteFirewallRules = @()
                    RawNetAdapterStatistics = @()
                    NetworkConnectionDetails = @()
                    InterfaceMetrics = @()
                    BindingInformation = @()
                    AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
            
            $global:networkInfo.NetworkConnectionDetails = $connectionsInfo
            
            # Add finding with detailed connection information
            Add-Finding -CheckName "Network Connections" -Status "Info" `
                -Details "Found $($connections.Count) TCP connections." -Category "NetworkConfig" `
                -AdditionalInfo $connectionsInfo
                
            # Add specific findings for interesting connections
            $remoteConnections = $connections | Where-Object { 
                $_.State -eq "Established" -and
                $_.RemoteAddress -ne "127.0.0.1" -and
                $_.RemoteAddress -ne "::1" -and
                $_.RemoteAddress -ne $_.LocalAddress
            }
            
            if ($remoteConnections) {
                Write-Output "Found $($remoteConnections.Count) established connections to remote systems:"
                
                $remoteConnectionDetails = $remoteConnections | ForEach-Object {
                    $processName = $processes[$_.OwningProcess].ProcessName
                    $serviceName = if ($connectionsInfo.CommonPorts.ContainsKey($_.RemotePort.ToString())) {
                        $connectionsInfo.CommonPorts[$_.RemotePort.ToString()]
                    } else { "Unknown" }
                    
                    "$($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) ($processName) [$serviceName]"
                }
                
                $remoteConnectionDetails | ForEach-Object { Write-Output "  $_" }
                
                Add-Finding -CheckName "Remote Connections" -Status "Info" `
                    -Details "Found $($remoteConnections.Count) established connections to remote systems." -Category "NetworkConfig" `
                    -AdditionalInfo @{
                        RemoteConnectionCount = $remoteConnections.Count
                        RemoteConnections = $remoteConnections | ForEach-Object {
                            @{
                                LocalEndPoint = "$($_.LocalAddress):$($_.LocalPort)"
                                RemoteEndPoint = "$($_.RemoteAddress):$($_.RemotePort)"
                                State = $_.State.ToString()
                                OwningProcess = $_.OwningProcess
                                ProcessName = $processes[$_.OwningProcess].ProcessName
                                ProcessPath = $processes[$_.OwningProcess].ProcessPath
                                CreationTime = if ($_.CreationTime) { $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                                ServiceName = if ($connectionsInfo.CommonPorts.ContainsKey($_.RemotePort.ToString())) {
                                    $connectionsInfo.CommonPorts[$_.RemotePort.ToString()]
                                } else { "Unknown" }
                            }
                        }
                    }
            }
        } else {
            Write-Output "No TCP connections found."
            $connectionsInfo.Error = "No TCP connections found"
            
            Add-Finding -CheckName "Network Connections" -Status "Info" `
                -Details "No TCP connections found." -Category "NetworkConfig" `
                -AdditionalInfo $connectionsInfo
        }
    }
    catch {
        Write-Output "Error retrieving network connections: $_"
        $connectionsInfo.Error = $_.Exception.Message
        $connectionsInfo.ErrorType = $_.Exception.GetType().Name
        $connectionsInfo.StackTrace = $_.ScriptStackTrace
        
        Add-Finding -CheckName "Network Connections" -Status "Warning" `
            -Details "Error retrieving network connections: $($_.Exception.Message)" -Category "NetworkConfig" `
            -AdditionalInfo $connectionsInfo
    }
}

function Test-ListeningTcpPorts {
    Write-SectionHeader "Listening Services"
    
    $listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    
    if ($listeningPorts) {
        Write-Output "Found $($listeningPorts.Count) listening TCP connections:"
        
        # Enhance the output with process information
        $listeningPortsDetailed = $listeningPorts | ForEach-Object {
            try {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                
                [PSCustomObject]@{
                    LocalAddress    = $(if ($_.LocalAddress -eq "0.0.0.0") { "Any" } else { $_.LocalAddress })
                    LocalPort       = $_.LocalPort
                    ProcessId       = $_.OwningProcess
                    ProcessName     = $process.Name
                    ProcessPath     = $process.Path
                }
            }
            catch {
                [PSCustomObject]@{
                    LocalAddress    = $(if ($_.LocalAddress -eq "0.0.0.0") { "Any" } else { $_.LocalAddress })
                    LocalPort       = $_.LocalPort
                    ProcessId       = $_.OwningProcess
                    ProcessName     = "Unknown"
                    ProcessPath     = "Unknown"
                }
            }
        }
        
        # Display the listening ports
        $listeningPortsDetailed | Format-Table -AutoSize
        
        # Create detailed information for JSON output
        $listeningPortsJson = $listeningPortsDetailed | ForEach-Object {
            @{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                ProcessId = $_.ProcessId
                ProcessName = $_.ProcessName
                ProcessPath = $_.ProcessPath
            }
        }
        
        # Add a summary finding with all listening ports details
        Add-Finding -CheckName "Listening Ports Summary" -Status "Info" `
            -Details "Found $($listeningPorts.Count) listening TCP connections." -Category "NetworkSecurity" `
            -AdditionalInfo @{
                ListeningPortCount = $listeningPorts.Count
                ListeningPorts = $listeningPortsJson
            }
        
        # Check for unusual high ports
        $highPorts = $listeningPortsDetailed | Where-Object { $_.LocalPort -gt 10000 -and $_.ProcessName -notin @("svchost", "System", "lsass") }
        foreach ($port in $highPorts) {
            Add-Finding -CheckName "Unusual High Port: $($port.LocalPort)" -Status "Warning" `
                -Details "Unusual high port $($port.LocalPort) is listening via process: $($port.ProcessName)" `
                -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    Port = $port.LocalPort
                    ProcessId = $port.ProcessId
                    ProcessName = $port.ProcessName
                    ProcessPath = $port.ProcessPath
                    LocalAddress = $port.LocalAddress
                    Recommendation = "Verify this is a legitimate service. High ports are sometimes used by malware for command and control."
                }
        }
    }
    else {
        Write-Output "No listening TCP connections found."
        Add-Finding -CheckName "Listening Services" -Status "Info" `
            -Details "No listening TCP services detected." -Category "NetworkSecurity" `
            -AdditionalInfo @{
                ListeningPortCount = 0
                ListeningPorts = @()
            }
    }
}

function Test-NetTCPConnection {
    Write-SectionHeader "Listening Services"
    
    $listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    
    if ($listeningPorts) {
        Write-Output "Found $($listeningPorts.Count) listening TCP connections:"
        
        # Enhance the output with process information
        $listeningPortsDetailed = $listeningPorts | ForEach-Object {
            try {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                
                [PSCustomObject]@{
                    LocalAddress    = $(if ($_.LocalAddress -eq "0.0.0.0") { "Any" } else { $_.LocalAddress })
                    LocalPort       = $_.LocalPort
                    ProcessId       = $_.OwningProcess
                    ProcessName     = $process.Name
                    ProcessPath     = $process.Path
                }
            }
            catch {
                # Return basic info if we can't get process details
                [PSCustomObject]@{
                    LocalAddress    = $(if ($_.LocalAddress -eq "0.0.0.0") { "Any" } else { $_.LocalAddress })
                    LocalPort       = $_.LocalPort
                    ProcessId       = $_.OwningProcess
                    ProcessName     = "Unknown"
                    ProcessPath     = "Unknown"
                }
            }
        }
        
        # Display the listening ports
        $listeningPortsDetailed | Format-Table -AutoSize
        
        # Create detailed information for JSON output
        $listeningPortsJson = $listeningPortsDetailed | ForEach-Object {
            @{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                ProcessId = $_.ProcessId
                ProcessName = $_.ProcessName
                ProcessPath = $_.ProcessPath
            }
        }
        
        # Add a summary finding with all listening ports details
        Add-Finding -CheckName "Listening Ports Summary" -Status "Info" `
            -Details "Found $($listeningPorts.Count) listening TCP connections." -Category "NetworkSecurity" `
            -AdditionalInfo @{
                ListeningPortCount = $listeningPorts.Count
                ListeningPorts = $listeningPortsJson
            }
        
        # Check for common risky ports
        $riskyPorts = @{
            21    = "FTP"
            22    = "SSH"
            23    = "Telnet"
            25    = "SMTP"
            53    = "DNS"
            135   = "RPC"
            139   = "NetBIOS"
            445   = "SMB"
            1433  = "MSSQL"
            3306  = "MySQL"
            3389  = "RDP"
            5432  = "PostgreSQL"
            5985  = "WinRM HTTP"
            5986  = "WinRM HTTPS"
            8080  = "HTTP Alt"
            8443  = "HTTPS Alt"
        }
        
        foreach ($port in $riskyPorts.Keys) {
            $match = $listeningPortsDetailed | Where-Object { $_.LocalPort -eq $port }
            if ($match) {
                $service = $riskyPorts[$port]
                $process = $match.ProcessName
                
                # Determine risk level
                $risk = "Warning"
                $details = "Port $port ($service) is listening via process: $process"
                
                # More serious risks
                if ($port -in @(23, 135, 139, 445)) {
                    $risk = "Fail"
                    $details = "High-risk port $port ($service) is listening via process: $process"
                }
                
                # Add the finding with detailed information for JSON
                Add-Finding -CheckName "Listening Port: $port" -Status $risk `
                    -Details $details -Category "NetworkSecurity" `
                    -AdditionalInfo @{
                        Port = $port
                        Service = $service
                        ProcessId = $match.ProcessId
                        ProcessName = $match.ProcessName
                        ProcessPath = $match.ProcessPath
                        LocalAddress = $match.LocalAddress
                        RiskLevel = $risk
                        Recommendation = if ($port -in @(23, 135, 139, 445)) {
                            "This port poses significant security risks. Consider disabling if not absolutely necessary."
                        } else {
                            "Ensure this port is properly secured and only accessible by trusted sources."
                        }
                    }
            }
        }
        
        # Check for unusual high ports
        $highPorts = $listeningPortsDetailed | Where-Object { $_.LocalPort -gt 10000 -and $_.ProcessName -notin @("svchost", "System", "lsass") }
        foreach ($port in $highPorts) {
            Add-Finding -CheckName "Unusual High Port: $($port.LocalPort)" -Status "Warning" `
                -Details "Unusual high port $($port.LocalPort) is listening via process: $($port.ProcessName)" `
                -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    Port = $port.LocalPort
                    ProcessId = $port.ProcessId
                    ProcessName = $port.ProcessName
                    ProcessPath = $port.ProcessPath
                    LocalAddress = $port.LocalAddress
                    Recommendation = "Verify this is a legitimate service. High ports are sometimes used by malware for command and control."
                }
        }
    }
    else {
        Write-Output "No listening TCP connections found."
        Add-Finding -CheckName "Listening Services" -Status "Info" `
            -Details "No listening TCP services detected." -Category "NetworkSecurity" `
            -AdditionalInfo @{
                ListeningPortCount = 0
                ListeningPorts = @()
            }
    }
}
function Test-NetworkNeighborCache {
    Write-SectionHeader "Network Neighbor Cache"
    
    # Get and display basic information in console
    Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress | Format-Table -AutoSize
    
    try {
        # Get comprehensive neighbor information for detailed JSON output
        $neighbors = Get-NetNeighbor -ErrorAction SilentlyContinue
        $neighborDetails = @()
        
        if ($neighbors) {
            # Create comprehensive detailed information for each neighbor entry with all available properties
            $neighborDetails = $neighbors | ForEach-Object {
                # Get detailed network adapter information for the interface
                $interfaceDetails = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
                
                # Extract MAC vendor OUI if possible
                $oui = if ($_.LinkLayerAddress -match "^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})") {
                    $matches[1]
                } else { $null }
                
                # Create comprehensive record with all available properties
                @{
                    # Basic neighbor properties
                    IPAddress = $_.IPAddress
                    LinkLayerAddress = $_.LinkLayerAddress
                    State = $_.State.ToString()
                    InterfaceIndex = $_.InterfaceIndex
                    InterfaceAlias = $_.InterfaceAlias
                    AddressFamily = $_.AddressFamily.ToString()
                    
                    # Additional network analysis
                    IsMulticast = $_.IPAddress -match "^(224\.|ff)"
                    IsRouter = $_.State -eq 'Reachable' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00'
                    PolicyStore = $_.PolicyStore
                    IsStale = $_.State -eq 'Stale'
                    IsIncomplete = $_.LinkLayerAddress -eq '00-00-00-00-00-00'
                    EntryType = if ($_.LinkLayerAddress -eq '00-00-00-00-00-00') { "Incomplete" } 
                           elseif ($_.State -eq 'Permanent') { "Static" } 
                           else { "Dynamic" }
                    
                    # IP address classification
                    IsPrivate = $_.IPAddress -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)"
                    IsIPv4 = $_.AddressFamily -eq "IPv4"
                    IsIPv6 = $_.AddressFamily -eq "IPv6"
                    IsLinkLocal = $_.IPAddress -match "^(169\.254\.|fe80:)"
                    
                    # MAC details
                    NormalizedMAC = $_.LinkLayerAddress -replace "-", ":"
                    OUI = $oui
                    IsLocalMAC = if ($_.LinkLayerAddress -match "^([0-9A-F]{2})") { 
                        [convert]::ToInt32($matches[1], 16) -band 0x02 -ne 0 
                    } else { $null }
                    
                    # Detailed interface information
                    InterfaceDetails = if ($interfaceDetails) {
                        @{
                            Name = $interfaceDetails.Name
                            MacAddress = $interfaceDetails.MacAddress
                            Status = $interfaceDetails.Status.ToString()
                            MediaType = $interfaceDetails.MediaType
                            PhysicalMediaType = $interfaceDetails.PhysicalMediaType
                            InterfaceDescription = $interfaceDetails.InterfaceDescription
                            LinkSpeed = $interfaceDetails.LinkSpeed
                            AdminStatus = $interfaceDetails.AdminStatus.ToString()
                            MediaConnectionState = $interfaceDetails.MediaConnectionState.ToString()
                            MtuSize = $interfaceDetails.MtuSize
                            FullDuplex = $interfaceDetails.FullDuplex
                            Virtual = $interfaceDetails.Virtual
                            DriverProvider = $interfaceDetails.DriverProvider
                            DriverVersion = $interfaceDetails.DriverVersion
                            DriverDate = if ($interfaceDetails.DriverDate) {
                                $interfaceDetails.DriverDate.ToString("yyyy-MM-dd HH:mm:ss")
                            } else { $null }
                        }
                    } else { $null }
                    
                    # Raw object properties
                    PSComputerName = $_.PSComputerName
                    CimClass = $_.CimClass
                    CimInstanceProperties = $_.CimInstanceProperties | ForEach-Object { $_.Name }
                    
                    # Metadata
                    CaptureTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    ComputerName = $env:COMPUTERNAME
                    UserContext = $env:USERNAME
                    OSVersion = [System.Environment]::OSVersion.VersionString
                }
            }
            
            # Store in global network info if available
            if (Get-Variable -Name networkInfo -Scope Global -ErrorAction SilentlyContinue) {
                $global:networkInfo.NeighborCache = $neighborDetails
            }
            
            # Add finding with complete details - no summaries or aggregations
            Add-Finding -CheckName "Network Neighbors" -Status "Info" `
                -Details "Network neighbor cache entries found." -Category "NetworkConfig" `
                -AdditionalInfo @{
                    RawNeighborEntries = $neighborDetails
                    DetectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    HostName = $env:COMPUTERNAME
                    UserContext = $env:USERNAME
                    OSVersion = [System.Environment]::OSVersion.VersionString
                    NetworkInterfaceDetails = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
                        @{
                            Name = $_.Name
                            Status = $_.Status.ToString()
                            MacAddress = $_.MacAddress
                            LinkSpeed = $_.LinkSpeed
                            MediaType = $_.MediaType
                            PhysicalMediaType = $_.PhysicalMediaType
                            InterfaceDescription = $_.InterfaceDescription
                            AdminStatus = $_.AdminStatus.ToString()
                            MediaConnectionState = $_.MediaConnectionState.ToString()
                            InterfaceIndex = $_.InterfaceIndex
                        }
                    }
                    CommandExecuted = "Get-NetNeighbor -ErrorAction SilentlyContinue"
                }
        } else {
            Add-Finding -CheckName "Network Neighbors" -Status "Info" `
                -Details "No neighbor cache entries found." -Category "NetworkConfig" `
                -AdditionalInfo @{
                    RawNeighborEntries = @()
                    NetAdapterStatus = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
                        @{
                            Name = $_.Name
                            Status = $_.Status.ToString()
                            MacAddress = $_.MacAddress
                            InterfaceDescription = $_.InterfaceDescription
                            MediaConnectionState = $_.MediaConnectionState.ToString()
                            InterfaceIndex = $_.InterfaceIndex
                        }
                    }
                    DetectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    HostName = $env:COMPUTERNAME
                    UserContext = $env:USERNAME
                    OSVersion = [System.Environment]::OSVersion.VersionString
                    CommandExecuted = "Get-NetNeighbor -ErrorAction SilentlyContinue"
                    ErrorsEncountered = $false
                }
            }
    }
    catch {
        Write-Output "Error retrieving network neighbor information: $_"
        Add-Finding -CheckName "Network Neighbors" -Status "Warning" `
            -Details "Error retrieving network neighbor information: $($_.Exception.Message)" -Category "NetworkConfig" `
            -AdditionalInfo @{
                Error = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
                StackTrace = $_.ScriptStackTrace
                CommandExecuted = "Get-NetNeighbor -ErrorAction SilentlyContinue"
                DetectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                HostName = $env:COMPUTERNAME
                UserContext = $env:USERNAME
                OSVersion = [System.Environment]::OSVersion.VersionString
            }
    }
}

function Test-LocalRouteTable {
    Write-SectionHeader "Local Route Table"
    
    # Initialize a comprehensive object for JSON output
    $routeTableInfo = @{
        Routes = @()
        DefaultGateways = @()
        SuspiciousRoutes = @()
        AnalysisResults = @{
            TotalRouteCount = 0
            IPv4RouteCount = 0
            IPv6RouteCount = 0
            StaticRouteCount = 0
            DynamicRouteCount = 0
            DefaultGatewayCount = 0
            SuspiciousRouteCount = 0
            MultipleDefaultGateways = $false
        }
        NetworkInterfaces = @()
        LocalIPAddresses = @()
        AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CommandExecuted = "Get-NetRoute -ErrorAction SilentlyContinue"
        HostInformation = @{
            Hostname = $env:COMPUTERNAME
            Username = $env:USERNAME
            OSVersion = [System.Environment]::OSVersion.VersionString
        }
    }
    
    try {
        # Get all routes with full details
        $routes = Get-NetRoute -ErrorAction SilentlyContinue
        
        if ($routes) {
            # Display standard route information
            $routes | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric | Format-Table -AutoSize
            
            # Collect local IP addresses for analysis
            $localIPAddresses = Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress
            $routeTableInfo.LocalIPAddresses = $localIPAddresses
            
            # Collect interface details for reference
            $interfaces = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
                @{
                    InterfaceIndex = $_.InterfaceIndex
                    InterfaceAlias = $_.InterfaceAlias
                    Name = $_.Name
                    MacAddress = $_.MacAddress
                    MediaType = $_.MediaType
                    PhysicalMediaType = $_.PhysicalMediaType
                    Status = $_.Status.ToString()
                    AdminStatus = $_.AdminStatus.ToString()
                    LinkSpeed = $_.LinkSpeed
                    IPAddresses = if ($ipConfig) {
                        @($ipConfig.IPv4Address.IPAddress) + @($ipConfig.IPv6Address.IPAddress) | Where-Object { $_ }
                    } else { @() }
                    DefaultGateways = if ($ipConfig.IPv4DefaultGateway) {
                        @($ipConfig.IPv4DefaultGateway.NextHop)
                    } else { @() }
                }
            }
            $routeTableInfo.NetworkInterfaces = $interfaces
            
            # Update analysis counts
            $routeTableInfo.AnalysisResults.TotalRouteCount = $routes.Count
            $routeTableInfo.AnalysisResults.IPv4RouteCount = ($routes | Where-Object { $_.AddressFamily -eq "IPv4" }).Count
            $routeTableInfo.AnalysisResults.IPv6RouteCount = ($routes | Where-Object { $_.AddressFamily -eq "IPv6" }).Count
            $routeTableInfo.AnalysisResults.StaticRouteCount = ($routes | Where-Object { $_.Protocol -eq "Local" }).Count
            $routeTableInfo.AnalysisResults.DynamicRouteCount = ($routes | Where-Object { $_.Protocol -ne "Local" }).Count
            
            # Process each route with full details
            foreach ($route in $routes) {
                # Create detailed route object preserving all properties
                $routeDetail = @{
                    DestinationPrefix = $route.DestinationPrefix
                    NextHop = $route.NextHop
                    InterfaceAlias = $route.InterfaceAlias
                    InterfaceIndex = $route.InterfaceIndex
                    InterfaceMetric = $route.InterfaceMetric
                    RouteMetric = $route.RouteMetric
                    Protocol = $route.Protocol.ToString()
                    AdminDistance = $route.AdminDistance
                    AddressFamily = $route.AddressFamily.ToString()
                    IsStatic = ($route.Protocol -eq "Local")
                    IsDefaultGateway = ($route.DestinationPrefix -eq "0.0.0.0/0" -or $route.DestinationPrefix -eq "::/0")
                    ValidLifetime = if ($route.ValidLifetime) { $route.ValidLifetime.ToString() } else { "Infinite" }
                    PreferredLifetime = if ($route.PreferredLifetime) { $route.PreferredLifetime.ToString() } else { "Infinite" }
                    Store = $route.Store.ToString()
                    Publish = $route.Publish.ToString()
                    InstallTimeStamp = if ($route.InstallTimeStamp) { $route.InstallTimeStamp.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                    Origin = $route.Origin.ToString()
                    DestinationNetwork = if ($route.DestinationPrefix -match "^(.+)/") { $matches[1] } else { $route.DestinationPrefix }
                    PrefixLength = if ($route.DestinationPrefix -match "/(\d+)$") { [int]$matches[1] } else { $null }
                    Type = if ($route.DestinationPrefix -eq "0.0.0.0/0" -or $route.DestinationPrefix -eq "::/0") { 
                        "DefaultGateway" 
                    } elseif ($route.NextHop -eq "0.0.0.0" -or $route.NextHop -eq "::") { 
                        "DirectConnection" 
                    } elseif ($route.NextHop -in $localIPAddresses) {
                        "LocalRouting"
                    } else { 
                        "ForwardedRoute" 
                    }
                    InterfaceDetails = $interfaces | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex } | Select-Object -First 1
                }
                
                # Add to main routes collection
                $routeTableInfo.Routes += $routeDetail
                
                # Track default gateways
                if ($routeDetail.IsDefaultGateway -and $route.NextHop -ne "0.0.0.0" -and $route.NextHop -ne "::") {
                    $routeTableInfo.DefaultGateways += $routeDetail
                }
                
                # Track suspicious routes
                $isSuspicious = ($route.NextHop -ne "0.0.0.0" -and 
                                $route.NextHop -ne "::" -and 
                                $route.NextHop -notin $localIPAddresses -and
                                # Exclude typical RFC1918 gateways
                                -not ($route.NextHop -match "^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)") -and
                                # IPv6 link-local addresses are normal
                                -not ($route.NextHop -match "^fe80:"))
                
                if ($isSuspicious) {
                    $suspiciousDetail = $routeDetail.Clone()
                    $suspiciousDetail.SuspicionReasons = @()
                    
                    if (-not ($route.NextHop -match "^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|\d+\.\d+\.\d+\.255|fe80:)")) {
                        $suspiciousDetail.SuspicionReasons += "Unusual next-hop outside common address ranges"
                    }
                    
                    if ($route.Protocol -eq "Local" -and -not $routeDetail.IsDefaultGateway) {
                        $suspiciousDetail.SuspicionReasons += "Manually added static route"
                    }
                    
                    $routeTableInfo.SuspiciousRoutes += $suspiciousDetail
                }
            }
            
            # Update analysis results
            $routeTableInfo.AnalysisResults.DefaultGatewayCount = $routeTableInfo.DefaultGateways.Count
            $routeTableInfo.AnalysisResults.MultipleDefaultGateways = $routeTableInfo.DefaultGateways.Count -gt 1
            $routeTableInfo.AnalysisResults.SuspiciousRouteCount = $routeTableInfo.SuspiciousRoutes.Count
            
            # Generate findings based on analysis
            if ($routeTableInfo.AnalysisResults.MultipleDefaultGateways) {
                Write-Output "WARNING: Multiple default gateways detected:"
                $routeTableInfo.DefaultGateways | ForEach-Object {
                    Write-Output "  $($_.DestinationPrefix) via $($_.NextHop) on $($_.InterfaceAlias) (metric: $($_.RouteMetric))"
                }
                
                Add-Finding -CheckName "Multiple Default Gateways" -Status "Warning" `
                    -Details "Found $($routeTableInfo.DefaultGateways.Count) default gateway routes." -Category "NetworkConfig" `
                    -AdditionalInfo @{
                        DefaultGateways = $routeTableInfo.DefaultGateways
                        MultipleGatewayImplications = @{
                            RoutingBehavior = "Windows will use the route with the lowest metric"
                            PotentialIssues = @(
                                "Traffic may be routed through unexpected paths",
                                "Network connectivity issues due to asymmetric routing",
                                "Failover behavior may not work as expected"
                            )
                            PossibleReasons = @(
                                "Multiple network interfaces connected to different networks",
                                "VPN connections with default routes",
                                "Network misconfiguration"
                            )
                            RecommendedAction = "Review routing configuration and adjust metrics if needed"
                        }
                    }
            }
            
            if ($routeTableInfo.SuspiciousRoutes.Count -gt 0) {
                Write-Output "WARNING: Potentially suspicious routes detected:"
                $routeTableInfo.SuspiciousRoutes | ForEach-Object {
                    Write-Output "  $($_.DestinationPrefix) via $($_.NextHop) on $($_.InterfaceAlias) (Protocol: $($_.Protocol))"
                }
                
                Add-Finding -CheckName "Suspicious Routes" -Status "Warning" `
                    -Details "Found $($routeTableInfo.SuspiciousRoutes.Count) routes with unusual next-hop addresses." -Category "NetworkSecurity" `
                    -AdditionalInfo @{
                        SuspiciousRoutes = $routeTableInfo.SuspiciousRoutes
                        SecurityImplications = @{
                            PotentialThreatVectors = @(
                                "Traffic redirection or interception (man-in-the-middle)",
                                "Data exfiltration through unexpected routing",
                                "Network persistence mechanism"
                            )
                            DetectionMethod = "Analysis of next-hop addresses outside expected ranges"
                            FalsePositiveFactors = @(
                                "Custom routing for specialized network configurations",
                                "VPN or virtual network adapters",
                                "Overlay network technologies"
                            )
                            RecommendedActions = @(
                                "Verify each suspicious route's purpose and origin",
                                "Remove unauthorized routes with 'Remove-NetRoute' cmdlet",
                                "Monitor for unauthorized route additions"
                            )
                        }
                    }
            }
            
            # Add comprehensive route table information to findings
            Add-Finding -CheckName "Local Route Table" -Status "Info" `
                -Details "Found $($routes.Count) entries in the local route table." -Category "NetworkConfig" `
                -AdditionalInfo $routeTableInfo
                
        } else {
            Write-Output "No entries found in the local route table."
            $routeTableInfo.AnalysisResults.Error = "No route entries returned"
            
            Add-Finding -CheckName "Local Route Table" -Status "Warning" `
                -Details "Unable to retrieve route table entries." -Category "NetworkConfig" `
                -AdditionalInfo @{
                    RoutingDetails = $routeTableInfo
                    RouteTableAccessError = $true
                    PossibleCauses = @(
                        "Insufficient permissions to access network configuration",
                        "Network components not functioning properly",
                        "Required services not running (e.g., Base Filtering Engine)"
                    )
                    TroubleshootingSteps = @(
                        "Verify 'iphlpsvc' service is running",
                        "Run PowerShell as administrator",
                        "Check network adapter status with 'Get-NetAdapter'"
                    )
                    AlternativeCommands = @(
                        "route print",
                        "netstat -r"
                    )
                }
        }
    }
    catch {
        Write-Output "Error retrieving local route table: $_"
        $routeTableInfo.AnalysisResults.Error = $_.Exception.Message
        $routeTableInfo.AnalysisResults.ErrorType = $_.Exception.GetType().Name
        $routeTableInfo.AnalysisResults.ErrorStack = $_.ScriptStackTrace
        
        Add-Finding -CheckName "Local Route Table" -Status "Fail" `
            -Details "Error retrieving local route table: $($_.Exception.Message)" -Category "NetworkConfig" `
            -AdditionalInfo @{
                RoutingDetails = $routeTableInfo
                RouteTableAccessFailed = $true
                ErrorDetails = @{
                    Message = $_.Exception.Message
                    Type = $_.Exception.GetType().Name
                    StackTrace = $_.ScriptStackTrace
                    InnerException = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $null }
                }
            }
    }
}

function Test-Clipboard {
    Write-SectionHeader "Clipboard Content"
    try {
        $clip = Get-Clipboard -ErrorAction SilentlyContinue
        $clipboardInfo = @{
            IsEmpty = [string]::IsNullOrEmpty($clip)
            ContentLength = if ($clip) { $clip.Length } else { 0 }
            ContentType = "Unknown"
            Lines = 0
            Words = 0
            Characters = 0
            ContainsScriptContent = $false
            ContainsUrls = $false
            ContainsPotentialCredentials = $false
            ContainsPotentialPaths = $false
            RawContent = $null
            SampleContent = $null
            HashSHA256 = $null
            DetectionPatterns = @{
                PowerShellScript = @("^Write-Host", "Get-Clipboard", "\btry\b.*\bcatch\b", "function\\s+\\w+", "param\\s*\\(", "\$\w+\\s*=", "if\\s*\\(", "foreach\\s*\\(")
                PotentialCredentials = @("password", "credential", "apikey", "secret", "token")
                Urls = @("http://", "https://", "ftp://")
                FilePaths = @("C:\\", "[A-Z]:\\", "\\\\", "/etc/", "/var/")
            }
            AssessmentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                UserName = $env:USERNAME
                ProcessId = $PID
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            }
        }
        if ($clip) {
            $clipboardInfo.Lines = ($clip -split "`n").Count
            $clipboardInfo.Words = ($clip -split '\\s+' | Where-Object { $_ -match '\\S' }).Count
            $clipboardInfo.Characters = $clip.Length
            $clipboardInfo.RawContent = $clip
            $clipboardInfo.HashSHA256 = [System.BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes($clip)
                )
            ).Replace("-", "").ToLower()
            if ($clip -match ($clipboardInfo.DetectionPatterns.PowerShellScript -join '|')) {
                $clipboardInfo.ContentType = "PowerShellScript"
                $clipboardInfo.ContainsScriptContent = $true
            } elseif ($clip -match '^\s*[{[]|".*":|^\s*<\?xml') {
                $clipboardInfo.ContentType = "StructuredData"
            } elseif ($clip -match "^\s*<(!DOCTYPE|html|head|body)") {
                $clipboardInfo.ContentType = "HTML"
            } elseif ($clip -match ($clipboardInfo.DetectionPatterns.Urls -join '|')) {
                $clipboardInfo.ContentType = "TextWithUrls"
                $clipboardInfo.ContainsUrls = $true
            } else {
                $clipboardInfo.ContentType = "PlainText"
            }
            $clipboardInfo.ContainsPotentialCredentials = $clip -match ($clipboardInfo.DetectionPatterns.PotentialCredentials -join '|')
            $clipboardInfo.ContainsPotentialPaths = $clip -match ($clipboardInfo.DetectionPatterns.FilePaths -join '|')
            $clipboardInfo.SampleContent = if ($clip.Length -gt 200) { $clip.Substring(0, 200) + "..." } else { $clip }
            if ($clipboardInfo.ContainsScriptContent) {
                Write-Host "   Clipboard contains script content (filtered)." -ForegroundColor DarkYellow
                Add-Finding -CheckName "Clipboard Content" -Status "Warning" `
                    -Details "Clipboard contains PowerShell script content ($($clipboardInfo.Characters) characters)." -Category "DataExposure" `
                    -AdditionalInfo $clipboardInfo
            } elseif ($clipboardInfo.ContainsPotentialCredentials) {
                Write-Host "   Clipboard may contain sensitive information (filtered)." -ForegroundColor Red
                Add-Finding -CheckName "Clipboard Content" -Status "Warning" `
                    -Details "Clipboard may contain sensitive information ($($clipboardInfo.Characters) characters)." -Category "DataExposure" `
                    -AdditionalInfo $clipboardInfo
            } else {
                Write-Host "   Clipboard contains content ($($clipboardInfo.ContentType), $($clipboardInfo.Characters) characters)" -ForegroundColor Yellow
                Add-Finding -CheckName "Clipboard Content" -Status "Info" `
                    -Details "Clipboard contains $($clipboardInfo.ContentType) content ($($clipboardInfo.Characters) characters)." -Category "DataExposure" `
                    -AdditionalInfo $clipboardInfo
            }
        } else {
            Write-Host "   Empty or inaccessible."
            $clipboardInfo.ContentType = "Empty"
            Add-Finding -CheckName "Clipboard Content" -Status "Pass" `
                -Details "Clipboard is empty or inaccessible." -Category "DataExposure" `
                -AdditionalInfo $clipboardInfo
        }
    } catch {
        Write-Host "   Clipboard access failed or is not supported on this system." -ForegroundColor Red
        $errorInfo = @{
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            ErrorCategory = $_.CategoryInfo.Category
            ErrorDetails = $_.ErrorDetails
            StackTrace = $_.ScriptStackTrace
            InnerException = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $null }
            AccessFailed = $true
            IsEmpty = $true
            AccessAttemptTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                UserName = $env:USERNAME
                ProcessId = $PID
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                SessionType = if ([System.Environment]::UserInteractive) { "Interactive" } else { "Non-Interactive" }
                OperatingSystem = [System.Environment]::OSVersion.VersionString
            }
        }
        Add-Finding -CheckName "Clipboard Content" -Status "Info" `
            -Details "Clipboard access failed: $($_.Exception.Message)" -Category "DataExposure" `
            -AdditionalInfo $errorInfo
    }
}

function Test-SoftwareInventory {
    Write-SectionHeader "Software Inventory"

    #region Initialize Data Structures
    $softwareInventoryInfo = @{
        InstalledSoftware       = @()
        RegistryPathsScanned    = @()
        TotalSoftwareCount      = 0
        ScanTimestamp           = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        HostInfo                = @{
            ComputerName = $env:COMPUTERNAME
            Username     = $env:USERNAME
            OSVersion    = [System.Environment]::OSVersion.VersionString
        }
        Architecture            = @{
            "32-bit" = 0
            "64-bit" = 0
        }
        PublisherStats          = @{}
        ScanErrors              = @()
    }

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $softwareInventoryInfo.RegistryPathsScanned = $regPaths
    #endregion

    #region Registry Scanning
    foreach ($path in $regPaths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }

            foreach ($item in $items) {
                #region Build Software Details
                $softwareDetails = @{}

                $item.PSObject.Properties | Where-Object {
                    $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider')
                } | ForEach-Object {
                    $softwareDetails[$_.Name] = $_.Value
                }

                $softwareDetails["RegistryPath"]   = $item.PSPath
                $softwareDetails["Architecture"]   = if ($path -like "*WOW6432Node*") { "32-bit" } else { "64-bit" }
                $softwareDetails["DetectionTime"]  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                # Format install date if in YYYYMMDD format
                if ($item.InstallDate -match '^\d{8}$') {
                    try {
                        $year  = $item.InstallDate.Substring(0, 4)
                        $month = $item.InstallDate.Substring(4, 2)
                        $day   = $item.InstallDate.Substring(6, 2)
                        $softwareDetails["InstallDateFormatted"] = "$year-$month-$day"
                    } catch {}
                }

                # Convert EstimatedSize (in KB) to MB
                if ($null -ne $item.EstimatedSize) {
                    $softwareDetails["EstimatedSizeMB"] = [math]::Round($item.EstimatedSize / 1024, 2)
                }
                #endregion

                #region Update Aggregated Stats
                $archKey = $softwareDetails["Architecture"]
                $softwareInventoryInfo.Architecture[$archKey]++

                $publisher = if ($item.Publisher) { $item.Publisher } else { "Unknown" }
                if ($softwareInventoryInfo.PublisherStats.ContainsKey($publisher)) {
                    $softwareInventoryInfo.PublisherStats[$publisher]++
                } else {
                    $softwareInventoryInfo.PublisherStats[$publisher] = 1
                }
                #endregion

                # Store result
                $softwareInventoryInfo.InstalledSoftware += $softwareDetails

                # Add individual finding
                Add-Finding -CheckName "Software: $($item.DisplayName)" -Status "Info" `
                    -Details "Version: $($item.DisplayVersion), Publisher: $($item.Publisher)" -Category "Software" `
                    -AdditionalInfo $softwareDetails
            }
        } catch {
            $softwareInventoryInfo.ScanErrors += @{
                Path      = $path
                Error     = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
                StackTrace = $_.ScriptStackTrace
            }
        }
    }
    #endregion

    #region Output and Summary
    $softwareInventoryInfo.TotalSoftwareCount = $softwareInventoryInfo.InstalledSoftware.Count

    if ($softwareInventoryInfo.TotalSoftwareCount -gt 0) {
        Write-Output "Found $($softwareInventoryInfo.TotalSoftwareCount) installed software packages:"
        $softwareInventoryInfo.InstalledSoftware | ForEach-Object {
            [PSCustomObject]@{
                DisplayName   = $_.DisplayName
                DisplayVersion = $_.DisplayVersion
                Publisher     = $_.Publisher
                InstallDate   = if ($_.InstallDateFormatted) { $_.InstallDateFormatted } else { $_.InstallDate }
                Architecture  = $_.Architecture
            }
        } | Sort-Object DisplayName | Format-Table -AutoSize

        Add-Finding -CheckName "Software Inventory Summary" -Status "Info" `
            -Details "Found $($softwareInventoryInfo.TotalSoftwareCount) software packages installed." `
            -Category "Software" -AdditionalInfo $softwareInventoryInfo
    } else {
        Write-Output "Software inventory not retrieved."
        Add-Finding -CheckName "Software Inventory" -Status "Warning" `
            -Details "Unable to retrieve software inventory." -Category "Software" `
            -AdditionalInfo @{
                Error             = "Failed to retrieve software inventory"
                RegPathsChecked   = $regPaths
                ScanErrors        = $softwareInventoryInfo.ScanErrors
                HostInfo          = $softwareInventoryInfo.HostInfo
                ScanTimestamp     = $softwareInventoryInfo.ScanTimestamp
            }
    }
    #endregion
}

function Test-RegistrySecurity {
    Write-SectionHeader "Registry Security"

    #region Initialize Objects
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $autorunInfo = @{
        Keys = @()
        IsFullyDisabled = $true
        RecommendedValue = 255
        SecurityRisk = "AutoRun allows automatic execution of code from removable media"
        AssessmentTimestamp = $timestamp
        HostName = $env:COMPUTERNAME
        RegistryTypes = @{
            "255" = "All drives"
            "95"  = "All drives except CD-ROM"
            "91"  = "All drives except CD-ROM and removable drives"
            "4"   = "Fixed drives only"
            "0"   = "None (AutoRun enabled for all drives)"
        }
        RegValueInfo = "Registry value is a bit mask where each bit represents a drive type"
        RemediationSteps = @(
            "Set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun=255",
            "Set HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun=255"
        )
    }

    $elevatedInfo = @{
        Keys = @()
        IsEnabled = $false
        SecurityRisk = "Always Install Elevated allows standard users to install MSI packages with SYSTEM privileges"
        AssessmentTimestamp = $timestamp
        HostName = $env:COMPUTERNAME
        RecommendedValue = 0
        RemediationSteps = @(
            "Set HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated=0",
            "Set HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated=0"
        )
        MITREAttackReference = "T1078 - Valid Accounts, T1548 - Abuse Elevation Control Mechanism"
    }

    $regPermInfo = @{
        SensitiveKeys = @()
        KeysWithExcessivePermissions = @()
        AssessmentTimestamp = $timestamp
        HostName = $env:COMPUTERNAME
        Username = $env:USERNAME
        ScanMode = "Standard"
        SecurityRisk = "Registry keys with excessive permissions can be modified by non-administrators"
    }
    #endregion

    #region AutoRun Evaluation
    $autorunDisabled = $true
    $autorunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    )

    foreach ($key in $autorunKeys) {
        $keyInfo = @{
            Path = $key; Value = $null; Exists = (Test-Path $key)
            Owner = $null; LastWriteTime = $null; SubkeyCount = 0; ValueCount = 0
            Permissions = @(); ValueType = $null; RawRegKey = $null
        }

        if ($keyInfo.Exists) {
            $regKey = Get-Item -Path $key -ErrorAction SilentlyContinue
            if ($regKey) {
                $keyInfo.LastWriteTime = $regKey.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                $keyInfo.SubkeyCount = ($regKey.GetSubKeyNames()).Count
                $keyInfo.ValueCount = ($regKey.GetValueNames()).Count
                $keyInfo.RawRegKey = $regKey.Name

                try {
                    $acl = Get-Acl -Path $key -ErrorAction SilentlyContinue
                    $keyInfo.Owner = $acl.Owner
                    $keyInfo.Permissions = $acl.Access | ForEach-Object {
                        @{
                            IdentityReference = $_.IdentityReference.ToString()
                            RegistryRights    = $_.RegistryRights.ToString()
                            AccessControlType = $_.AccessControlType.ToString()
                            IsInherited       = $_.IsInherited
                            InheritanceFlags  = $_.InheritanceFlags.ToString()
                            PropagationFlags  = $_.PropagationFlags.ToString()
                        }
                    }
                } catch {
                    $keyInfo.OwnerError = $_.Exception.Message
                }
            }

            $value = (Get-ItemProperty -Path $key -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
            $keyInfo.Value = $value
            $keyInfo.ValueType = if ($null -ne $value) {
                (Get-ItemProperty -Path $key -Name "NoDriveTypeAutoRun").NoDriveTypeAutoRun.GetType().FullName
            } else { $null }
            $keyInfo.ValueInterpretation = if ($null -ne $value) {
                $autorunInfo.RegistryTypes["$value"]
            } else { "Not set" }

            if ($value -ne 255) {
                $autorunDisabled = $false
                $autorunInfo.IsFullyDisabled = $false
            }
        }

        $autorunInfo.Keys += $keyInfo
    }

    if ($autorunDisabled) {
        Write-Output "PASS: AutoRun is disabled."
        Add-Finding -CheckName "AutoRun Disabled" -Status "Pass" `
            -Details "AutoRun/AutoPlay is properly disabled." -Category "RegistrySecurity" `
            -AdditionalInfo $autorunInfo
    } else {
        Write-Output "FAIL: AutoRun is not fully disabled."
        Add-Finding -CheckName "AutoRun Disabled" -Status "Fail" `
            -Details "AutoRun/AutoPlay is not fully disabled." -Category "RegistrySecurity" `
            -AdditionalInfo $autorunInfo
    }
    #endregion

    #region Always Install Elevated Check
    $installElevated = $false
    $elevatedKeys = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
        "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    )

    foreach ($key in $elevatedKeys) {
        $keyInfo = @{
            Path = $key; Value = $null; Exists = (Test-Path $key)
            Owner = $null; LastWriteTime = $null; SubkeyCount = 0; ValueCount = 0
            Permissions = @(); ValueType = $null; RawRegKey = $null
        }

        if ($keyInfo.Exists) {
            $regKey = Get-Item -Path $key -ErrorAction SilentlyContinue
            if ($regKey) {
                $keyInfo.LastWriteTime = $regKey.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                $keyInfo.SubkeyCount = ($regKey.GetSubKeyNames()).Count
                $keyInfo.ValueCount = ($regKey.GetValueNames()).Count
                $keyInfo.RawRegKey = $regKey.Name

                try {
                    $acl = Get-Acl -Path $key -ErrorAction SilentlyContinue
                    $keyInfo.Owner = $acl.Owner
                    $keyInfo.Permissions = $acl.Access | ForEach-Object {
                        @{
                            IdentityReference = $_.IdentityReference.ToString()
                            RegistryRights    = $_.RegistryRights.ToString()
                            AccessControlType = $_.AccessControlType.ToString()
                            IsInherited       = $_.IsInherited
                            InheritanceFlags  = $_.InheritanceFlags.ToString()
                            PropagationFlags  = $_.PropagationFlags.ToString()
                        }
                    }
                } catch {
                    $keyInfo.OwnerError = $_.Exception.Message
                }
            }

            $value = (Get-ItemProperty -Path $key -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
            $keyInfo.Value = $value
            $keyInfo.ValueType = if ($null -ne $value) {
                $value.GetType().FullName
            } else { $null }

            if ($value -eq 1) {
                $installElevated = $true
                $elevatedInfo.IsEnabled = $true
            }
        }

        $elevatedInfo.Keys += $keyInfo
    }

    if ($installElevated) {
        Write-Output "FAIL: 'Always Install Elevated' is enabled."
        Add-Finding -CheckName "Always Install Elevated" -Status "Fail" `
            -Details "The 'Always Install Elevated' policy is enabled, which is a security risk." `
            -Category "RegistrySecurity" -AdditionalInfo $elevatedInfo
    } else {
        Write-Output "PASS: 'Always Install Elevated' is disabled."
        Add-Finding -CheckName "Always Install Elevated" -Status "Pass" `
            -Details "The 'Always Install Elevated' policy is disabled." `
            -Category "RegistrySecurity" -AdditionalInfo $elevatedInfo
    }
    #endregion

    #region Registry Permission Scan
    $sensitiveKeys = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Category = "Startup"; Description = "Programs that run automatically at system startup"; CriticalityLevel = "High"; MITREAttackReference = "T1547.001" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Category = "Authentication"; Description = "Controls Windows logon process and credentials"; CriticalityLevel = "High"; MITREAttackReference = "T1547.004" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Category = "Authentication"; Description = "Local Security Authority configuration"; CriticalityLevel = "Critical"; MITREAttackReference = "T1003.001" }
    )

    foreach ($meta in $sensitiveKeys) {
        $key = $meta.Path
        # (Keep your full permission check logic here, unchanged for brevity — see previous response)
        # Make sure to update $regPermInfo.KeysWithExcessivePermissions or $regPermInfo.SensitiveKeys accordingly
    }
    #endregion

    #region Final Summary Finding
    Add-Finding -CheckName "Registry Security Summary" -Status "Info" `
        -Details "Registry security assessment completed." -Category "RegistrySecurity" `
        -AdditionalInfo @{
            AutorunStatus              = $autorunInfo
            AlwaysInstallElevatedStatus = $elevatedInfo
            RegistryPermissions        = $regPermInfo
            SecurityRecommendations   = @(
                "Disable AutoRun completely by setting NoDriveTypeAutoRun to 255",
                "Ensure 'Always Install Elevated' policy is disabled",
                "Restrict sensitive registry key permissions to administrators only"
            )
            Assessment = @{
                Timestamp    = $timestamp
                ComputerName = $env:COMPUTERNAME
                Username     = $env:USERNAME
                OSVersion    = [System.Environment]::OSVersion.VersionString
            }
        }
    #endregion
}

function Test-AdvancedNetworkSecurity {
    Write-SectionHeader "Network Services"
    
    # Initialize comprehensive object for JSON output
    $networkSecurityInfo = @{
        RDP = @{
            Enabled = $false
            NLAEnabled = $false
            EncryptionLevel = $null
            SecurityStatus = "N/A"
        }
        WinRM = @{
            Enabled = $false
            BasicAuth = $false
            AllowUnencrypted = $false
            ServiceStatus = "Not Running"
            ListenerInfo = @()
        }
        DNS = @{
            PublicDNSDetected = $false
            DNSServers = @()
        }
    }
    
    # Check for RDP security
    $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
    $networkSecurityInfo.RDP.Enabled = $rdpEnabled
    
    if ($rdpEnabled) {
        Write-Output "RDP is enabled."
        # Check NLA requirement
        $nlaEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication -eq 1
        $networkSecurityInfo.RDP.NLAEnabled = $nlaEnabled
        
        if ($nlaEnabled) {
            Write-Output "PASS: RDP requires Network Level Authentication."
            Add-Finding -CheckName "RDP NLA" -Status "Pass" `
                -Details "RDP requires Network Level Authentication." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    RDPEnabled = $true
                    NLAEnabled = $true
                    RegistryPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                    SettingName = "UserAuthentication"
                    Value = 1
                    SecurityImplication = "NLA provides an additional authentication layer before a full RDP connection is established"
                }
        } else {
            Write-Output "FAIL: RDP does not require Network Level Authentication."
            Add-Finding -CheckName "RDP NLA" -Status "Fail" `
                -Details "RDP does not require Network Level Authentication." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    RDPEnabled = $true
                    NLAEnabled = $false
                    RegistryPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                    SettingName = "UserAuthentication"
                    Value = 0
                    SecurityImplication = "Without NLA, the system is more vulnerable to brute force attacks and potential RDP vulnerabilities"
                    Remediation = "Enable NLA by setting UserAuthentication to 1 in the registry"
                }
        }
        
        # Check RDP encryption level
        $encryptionLevel = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
        $networkSecurityInfo.RDP.EncryptionLevel = $encryptionLevel
        
        # Add encryption level meaning
        $encryptionLevelMeaning = switch ($encryptionLevel) {
            0 {"No encryption"}
            1 {"Low encryption (56-bit)"}
            2 {"Client compatible encryption"}
            3 {"High encryption (128-bit)"}
            4 {"FIPS compliant encryption"}
            default {"Unknown"}
        }
        $networkSecurityInfo.RDP.EncryptionLevelMeaning = $encryptionLevelMeaning
        
        if ($encryptionLevel -ge 3) {
            Write-Output "PASS: RDP encryption level is high."
            $networkSecurityInfo.RDP.SecurityStatus = "Secure"
            Add-Finding -CheckName "RDP Encryption" -Status "Pass" `
                -Details "RDP encryption level is set to high ($encryptionLevel)." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    RDPEnabled = $true
                    EncryptionLevel = $encryptionLevel
                    EncryptionDescription = $encryptionLevelMeaning
                    RegistryPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                    SettingName = "MinEncryptionLevel"
                    RecommendedValue = "3 or higher"
                    Meets128BitRequirement = $true
                }
        } else {
            Write-Output "FAIL: RDP encryption level is too low."
            $networkSecurityInfo.RDP.SecurityStatus = "Insecure"
            Add-Finding -CheckName "RDP Encryption" -Status "Fail" `
                -Details "RDP encryption level is set too low ($encryptionLevel)." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    RDPEnabled = $true
                    EncryptionLevel = $encryptionLevel
                    EncryptionDescription = $encryptionLevelMeaning
                    RegistryPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                    SettingName = "MinEncryptionLevel"
                    RecommendedValue = "3 or higher"
                    Meets128BitRequirement = $false
                    SecurityImplication = "Lower encryption levels may allow traffic interception or decryption"
                    Remediation = "Set MinEncryptionLevel to 3 or higher in the registry"
                }
        }
    } else {
        Write-Output "RDP is disabled."
        $networkSecurityInfo.RDP.SecurityStatus = "Disabled"
    }
    
    # Check for Windows Remote Management (WinRM)
    $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    if ($winrmService -and $winrmService.Status -eq "Running") {
        Write-Output "WinRM service is running."
        $networkSecurityInfo.WinRM.Enabled = $true
        $networkSecurityInfo.WinRM.ServiceStatus = $winrmService.Status
        
        # Check WinRM settings
        $winrmConfig = winrm get winrm/config 2>$null
        $basicAuth = $winrmConfig -match "Basic = true"
        $networkSecurityInfo.WinRM.BasicAuth = $basicAuth
        
        # Try to get listener information
        try {
            $listeners = winrm enumerate winrm/config/listener 2>$null
            if ($listeners) {
                # Extract listener details
                $currentListener = $null
                foreach ($line in $listeners) {
                    if ($line -match "Listener") {
                        if ($currentListener) {
                            $networkSecurityInfo.WinRM.ListenerInfo += $currentListener
                        }
                        $currentListener = @{}
                    } elseif ($line -match "^\s+(\w+)\s+=\s+(.+)$") {
                        $key = $matches[1]
                        $value = $matches[2]
                        if ($currentListener) {
                            $currentListener[$key] = $value
                        }
                    }
                }
                # Add the last listener if exists
                if ($currentListener) {
                    $networkSecurityInfo.WinRM.ListenerInfo += $currentListener
                }
            }
        } catch {
            # Listener enumeration failed
        }
        
        if ($basicAuth) {
            Write-Output "FAIL: WinRM allows Basic Authentication."
            Add-Finding -CheckName "WinRM Basic Auth" -Status "Fail" `
                -Details "WinRM allows insecure Basic Authentication." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    WinRMEnabled = $true
                    BasicAuthenticationEnabled = $true
                    SecurityImplication = "Basic Authentication transmits credentials in a format that can be easily decoded"
                    Remediation = "Disable Basic Authentication in WinRM configuration"
                    ListenerInfo = $networkSecurityInfo.WinRM.ListenerInfo
                }
        } else {
            Write-Output "PASS: WinRM does not allow Basic Authentication."
            Add-Finding -CheckName "WinRM Basic Auth" -Status "Pass" `
                -Details "WinRM does not allow Basic Authentication." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    WinRMEnabled = $true
                    BasicAuthenticationEnabled = $false
                    ListenerInfo = $networkSecurityInfo.WinRM.ListenerInfo
                }
        }
        
        $unencrypted = $winrmConfig -match "AllowUnencrypted = true"
        $networkSecurityInfo.WinRM.AllowUnencrypted = $unencrypted
        
        if ($unencrypted) {
            Write-Output "FAIL: WinRM allows unencrypted traffic."
            Add-Finding -CheckName "WinRM Encryption" -Status "Fail" `
                -Details "WinRM allows unencrypted traffic." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    WinRMEnabled = $true
                    AllowUnencrypted = $true
                    SecurityImplication = "Unencrypted WinRM traffic can be intercepted and read by attackers"
                    Remediation = "Set AllowUnencrypted to false in WinRM configuration"
                    ListenerInfo = $networkSecurityInfo.WinRM.ListenerInfo
                }
        } else {
            Write-Output "PASS: WinRM requires encrypted traffic."
            Add-Finding -CheckName "WinRM Encryption" -Status "Pass" `
                -Details "WinRM requires encrypted traffic." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    WinRMEnabled = $true
                    AllowUnencrypted = $false
                    ListenerInfo = $networkSecurityInfo.WinRM.ListenerInfo
                }
        }
    } else {
        Write-Output "WinRM service is not running."
        $networkSecurityInfo.WinRM.Enabled = $false
    }
    
    # Check DNS Client settings
    $dnsClients = Get-DnsClientServerAddress -ErrorAction SilentlyContinue
    if ($dnsClients) {
        # Extract all DNS server addresses for JSON
        $allDNSServers = $dnsClients | Where-Object { $_.ServerAddresses } | ForEach-Object {
            @{
                InterfaceAlias = $_.InterfaceAlias
                AddressFamily = $_.AddressFamily.ToString()
                ServerAddresses = $_.ServerAddresses
            }
        }
        $networkSecurityInfo.DNS.DNSServers = $allDNSServers
        
        $suspiciousDNS = $dnsClients | Where-Object { 
            $_.ServerAddresses -and ($_.ServerAddresses -contains "8.8.8.8" -or $_.ServerAddresses -contains "1.1.1.1") 
        }
        
        if ($suspiciousDNS) {
            Write-Output "WARNING: Public DNS servers detected:"
            $suspiciousDNS | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
            $networkSecurityInfo.DNS.PublicDNSDetected = $true
            
            # Extract suspicious DNS details for JSON
            $suspiciousDNSDetails = $suspiciousDNS | ForEach-Object {
                @{
                    InterfaceAlias = $_.InterfaceAlias
                    AddressFamily = $_.AddressFamily.ToString()
                    ServerAddresses = $_.ServerAddresses
                }
            }
            
            Add-Finding -CheckName "Public DNS" -Status "Warning" `
                -Details "Public DNS servers (Google, Cloudflare) are being used." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    PublicDNSDetected = $true
                    SuspiciousInterfaces = $suspiciousDNSDetails
                    SecurityImplication = "Using public DNS servers may bypass internal DNS monitoring and security controls"
                    RecommendedAction = "Use enterprise DNS servers that support security monitoring"
                }
        } else {
            Write-Output "PASS: No public DNS servers detected."
            Add-Finding -CheckName "Public DNS" -Status "Pass" `
                -Details "No public DNS servers detected." -Category "NetworkSecurity" `
                -AdditionalInfo @{
                    PublicDNSDetected = $false
                    AllDNSServers = $allDNSServers
                }
        }
    }
    
    # Add summary finding with all network services security information
    Add-Finding -CheckName "Network Services Security Summary" -Status "Info" `
        -Details "Summary of network services security settings." -Category "NetworkSecurity" `
        -AdditionalInfo $networkSecurityInfo
}

function Test-WindowsServices {
    Write-SectionHeader "Windows Services"
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    if ($services) {
        # Get more detailed service information
        $detailedServices = $services | ForEach-Object {
            $serviceDetails = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                Name = $_.Name
                Status = $_.Status
                StartType = $serviceDetails.StartMode
                RunAs = $serviceDetails.StartName
                Path = $serviceDetails.PathName
                Description = $serviceDetails.Description
            }
        }
        
        # Display basic information in a table
        $detailedServices | Select-Object DisplayName, Name, Status, StartType, RunAs | Format-Table -AutoSize
        
        # Create detailed service information for JSON output
        $serviceDetails = $detailedServices | ForEach-Object {
            @{
                DisplayName = $_.DisplayName
                Name = $_.Name
                Status = $_.Status.ToString()
                StartType = $_.StartType
                RunAs = $_.RunAs
                Path = $_.Path
                Description = $_.Description
                HasElevatedPrivileges = $_.RunAs -match "LocalSystem|NT AUTHORITY\\(System|LocalService|NetworkService)"
                AutoStart = $_.StartType -eq "Auto"
            }
        }
        
        # Look for potentially suspicious services
        $suspiciousServices = $detailedServices | Where-Object { 
            $_.Path -match "\\Temp\\|\\AppData\\|powershell|cmd\.exe" -or
            $_.Path -notmatch "C:\\Windows\\|C:\\Program Files\\|C:\\Program Files \(x86\)\\"
        }
        
        if ($suspiciousServices) {
            Write-Output "Potentially suspicious services found:"
            $suspiciousServices | Select-Object Name, Path | Format-Table -AutoSize
            
            # Add findings for suspicious services
            foreach ($suspicious in $suspiciousServices) {
                Add-Finding -CheckName "Suspicious Service: $($suspicious.Name)" -Status "Warning" `
                    -Details "Service runs from unusual location: $($suspicious.Path)" -Category "Services" `
                    -AdditionalInfo @{
                        DisplayName = $suspicious.DisplayName
                        Name = $suspicious.Name
                        Status = $suspicious.Status.ToString()
                        StartType = $suspicious.StartType
                        RunAs = $suspicious.RunAs
                        Path = $suspicious.Path
                        Description = $suspicious.Description
                    }
            }
        }
      
        Add-Finding -CheckName "Running Services" -Status "Info" `
            -Details "$($services.Count) services are running." -Category "Services" `
            -AdditionalInfo @{
                ServiceCount = $services.Count
                Services = $serviceDetails
                SystemServices = ($serviceDetails | Where-Object { $_.RunAs -match "LocalSystem|NT AUTHORITY\\System" }).Count
                AutoStartServices = ($serviceDetails | Where-Object { $_.AutoStart }).Count
                SuspiciousServiceCount = if ($suspiciousServices) { $suspiciousServices.Count } else { 0 }
            }
    } else {
        Write-Output "No running services found."
        Add-Finding -CheckName "Running Services" -Status "Warning" `
            -Details "No running services found." -Category "Services" `
            -AdditionalInfo @{
                ServiceCount = 0
                Services = @()
                Error = "Failed to retrieve running services"
            }
    }
}

function Test-SmbSigningEnabled {
    Write-SectionHeader "SMB Signing Configuration"
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    
    # Create comprehensive object for JSON output
    $smbSecurityInfo = @{
        SigningRequired = $null
        SigningEnabled = $null
        SMBv1Enabled = $null
        ConfigurationRetrieved = $false
        SecurityRisk = "SMB without required signing is vulnerable to man-in-the-middle attacks"
        Recommendation = "Enable and require SMB signing in Windows security policy or directly in SMB configuration"
    }
    
    if ($null -ne $smbConfig) {
        $smbSecurityInfo.ConfigurationRetrieved = $true
        $smbSecurityInfo.SigningRequired = $smbConfig.RequireSecuritySignature
        $smbSecurityInfo.SigningEnabled = $smbConfig.EnableSecuritySignature
        $smbSecurityInfo.SMBv1Enabled = $smbConfig.EnableSMB1Protocol
        
        if ($smbConfig.RequireSecuritySignature -eq $true) {
            Write-Output "PASS: SMB signing is required."
            Add-Finding -CheckName "SMB Signing Required" -Status "Pass" `
                -Details "SMB signing is properly configured." -Category "NetworkSecurity" `
                -AdditionalInfo $smbSecurityInfo
        } else {
            Write-Output "FAIL: SMB signing is not required."
            Add-Finding -CheckName "SMB Signing Required" -Status "Fail" `
                -Details "SMB signing is not required; vulnerable to MITM attacks." -Category "NetworkSecurity" `
                -AdditionalInfo $smbSecurityInfo
        }
        
        # Additional check for EnableSecuritySignature
        if ($smbConfig.EnableSecuritySignature -eq $true) {
            Write-Output "INFO: SMB signing is enabled."
        } else {
            Write-Output "FAIL: SMB signing is not enabled."
            Add-Finding -CheckName "SMB Signing Enabled" -Status "Fail" `
                -Details "SMB signing is not enabled." -Category "NetworkSecurity" `
                -AdditionalInfo $smbSecurityInfo
        }
    } else {
        Write-Output "Failed to retrieve SMB server configuration."
        $smbSecurityInfo.ConfigurationRetrieved = $false
        Add-Finding -CheckName "SMB Configuration" -Status "Fail" `
            -Details "Unable to retrieve SMB configuration." -Category "NetworkSecurity" `
            -AdditionalInfo $smbSecurityInfo
    }
    
    # Add a comprehensive SMB security summary finding
    Add-Finding -CheckName "SMB Security Summary" -Status "Info" `
        -Details "SMB security configuration assessment." -Category "NetworkSecurity" `
        -AdditionalInfo $smbSecurityInfo
}

function Test-AccessibilityExecutables {
    Write-SectionHeader "Accessibility Executables Integrity"
    
    $accessibilityExecutables = @(
        "C:\Windows\System32\sethc.exe",
        "C:\Windows\System32\osk.exe",
        "C:\Windows\System32\utilman.exe", 
        "C:\Windows\System32\magnify.exe",
        "C:\Windows\System32\narrator.exe",
        "C:\Windows\System32\displayswitch.exe",
        "C:\Windows\System32\atbroker.exe",
        "C:\Windows\System32\doskey.exe",
        "C:\Windows\System32\eventvwr.exe",
        "C:\Windows\System32\fodhelper.exe",
        "C:\Windows\System32\Magnification.dll",
        "C:\Windows\System32\wscript.exe",
        "C:\Windows\System32\cscript.exe",
        "C:\Windows\System32\credwiz.exe",
        "C:\Windows\System32\slui.exe"
    )
    
    # Create detailed info object for JSON output
    $accessibilityInfo = @{
        ExecutablesChecked = $accessibilityExecutables.Count
        ExecutableDetails = @()
        MissingFiles = 0
        PotentiallyCompromised = 0
        SecurityRisk = "Modified system executables can be used for backdoor access to login screens or privilege escalation"
    }
    
    foreach ($file in $accessibilityExecutables) {
        if (Test-Path $file) {
            try {
                $fileInfo = Get-Item -Path $file -ErrorAction SilentlyContinue
                $hash = Get-FileHash -Path $file -Algorithm SHA256 -ErrorAction SilentlyContinue
                $signature = Get-AuthenticodeSignature -FilePath $file -ErrorAction SilentlyContinue
                
                # Create detailed file information for JSON
                $fileDetails = @{
                    Path = $file
                    Exists = $true
                    FileName = [System.IO.Path]::GetFileName($file)
                    FileSize = $fileInfo.Length
                    LastModified = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    CreationTime = $fileInfo.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                    SHA256Hash = $hash.Hash
                    SignatureStatus = $signature.Status.ToString()
                    SignedBy = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "Not signed" }
                    OriginalFilename = $null  # Will be filled if available
                }
                
                # Try to extract version info including Original Filename
                try {
                    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file)
                    $fileDetails.OriginalFilename = $versionInfo.OriginalFilename
                    $fileDetails.FileVersion = $versionInfo.FileVersion
                    $fileDetails.ProductVersion = $versionInfo.ProductVersion
                    $fileDetails.CompanyName = $versionInfo.CompanyName
                } catch {
                    # Version info couldn't be retrieved
                }
                
                Write-Output "$($file): $($hash.Hash)"
                $accessibilityInfo.ExecutableDetails += $fileDetails
                
                # Check if signature is valid
                if ($signature.Status -ne "Valid") {
                    Write-Output "WARNING: $file has an invalid signature status: $($signature.Status)"
                    $accessibilityInfo.PotentiallyCompromised++
                    
                    Add-Finding -CheckName "System File Signature" -Status "Fail" `
                        -Details "$file has invalid signature: $($signature.Status)" -Category "SystemIntegrity" `
                        -AdditionalInfo $fileDetails
                }
                
                Add-Finding -CheckName "System File Hash" -Status "Info" `
                    -Details "$file SHA256: $($hash.Hash)" -Category "SystemIntegrity" `
                    -AdditionalInfo $fileDetails
            }
            catch {
                Write-Output "ERROR: Could not analyze $file - $_"
                
                $fileDetails = @{
                    Path = $file
                    Exists = $true
                    Error = $_.Exception.Message
                    ErrorType = $_.Exception.GetType().Name
                }
                
                $accessibilityInfo.ExecutableDetails += $fileDetails
                
                Add-Finding -CheckName "System File Analysis Error" -Status "Warning" `
                    -Details "Error analyzing $file : $($_.Exception.Message)" -Category "SystemIntegrity" `
                    -AdditionalInfo $fileDetails
            }
        } else {
            Write-Output "${file}: File not found"
            $accessibilityInfo.MissingFiles++
            
            $fileDetails = @{
                Path = $file
                Exists = $false
                FileName = [System.IO.Path]::GetFileName($file)
                SecurityRisk = "Missing system files could indicate tampering or system corruption"
            }
            
            $accessibilityInfo.ExecutableDetails += $fileDetails
            
            Add-Finding -CheckName "System File Missing" -Status "Fail" `
                -Details "$file is missing" -Category "SystemIntegrity" `
                -AdditionalInfo $fileDetails
        }
    }
}

function Test-SelfSignedCerts {
    Write-SectionHeader "Self-Signed Certificates"
    
    # Initialize detailed info for JSON output
    $certInfo = @{
        SelfSignedCount = 0
        TotalCertsChecked = 0
        CertificateStoresChecked = @("Cert:\LocalMachine\Root", "Cert:\LocalMachine\CA")
        SelfSignedCertificates = @()
        ErrorEncountered = $false
        ErrorDetails = $null
        SecurityRisk = "Self-signed certificates in trusted stores can be used for TLS interception and may indicate compromise"
    }
    
    try {
        # Get certificates from trusted stores
        $certs = Get-ChildItem -Path Cert:\LocalMachine\Root, Cert:\LocalMachine\CA -ErrorAction SilentlyContinue
        $certInfo.TotalCertsChecked = $certs.Count
        
        # Find self-signed certificates
        # Root CA certs often have same subject/issuer but aren't self-signed in the risky sense
        # Better check for certificates that aren't from known CAs and are self-signed
        $selfSignedCerts = $certs | Where-Object {
            # Skip well-known root CAs
            $_.Subject -eq $_.Issuer -and 
            $null -ne $_.Subject -and
            -not ($_.Subject -match "Microsoft|Amazon|Digicert|GlobalSign|Comodo|Thawte|VeriSign|Entrust|GeoTrust|USERTrust|Actalis|QuoVadis|IdenTrust|DST|Baltimore|Certum|Telia|ISRG|Starfield|Buypass|T-TeleSec|SECOM|GoDaddy|AddTrust|TeliaSonera|Unizeto|Chunghwa|SecureTrust|SSL\.com")
        }
        
        $certInfo.SelfSignedCount = $selfSignedCerts.Count
        
        # Add each certificate's details to JSON
        foreach ($cert in $selfSignedCerts) {
            $certInfo.SelfSignedCertificates += @{
                Subject = $cert.Subject
                Issuer = $cert.Issuer
                Thumbprint = $cert.Thumbprint
                SerialNumber = $cert.SerialNumber
                NotBefore = $cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')
                NotAfter = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
                KeyAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                Store = $cert.PSParentPath -replace ".*::", ""
                HasPrivateKey = $cert.HasPrivateKey
                EnhancedKeyUsage = ($cert.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ", "
                TemplateInformation = if ($cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Certificate Template Information" }) { 
                    ($cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Certificate Template Information" }).Format($false) 
                } else { $null }
            }
        }
        
        if ($selfSignedCerts -and $selfSignedCerts.Count -gt 0) {
            Write-Output "Found $($selfSignedCerts.Count) self-signed certificates in trusted stores:"
            $selfSignedCerts | Select-Object Subject, Thumbprint, NotBefore, NotAfter | Format-Table -AutoSize
            
            Add-Finding -CheckName "Self-Signed Certificates" -Status "Warning" `
                -Details "Found $($selfSignedCerts.Count) self-signed certificates in trusted stores." -Category "CertificateSecurity" `
                -AdditionalInfo $certInfo
                
            # Add individual findings for each certificate for better filtering
            foreach ($cert in $selfSignedCerts) {
                $subjectName = if ($cert.Subject -match "CN=([^,]+)") { $Matches[1] } else { "Unknown" }
                
                Add-Finding -CheckName "Self-Signed Certificate: $subjectName" -Status "Warning" `
                    -Details "Self-signed certificate detected: $($cert.Subject) (Valid until: $($cert.NotAfter.ToString('yyyy-MM-dd')))" -Category "CertificateSecurity" `
                    -AdditionalInfo @{
                        Subject = $cert.Subject
                        Issuer = $cert.Issuer
                        Thumbprint = $cert.Thumbprint
                        NotBefore = $cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')
                        NotAfter = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
                        Store = $cert.PSParentPath -replace ".*::", ""
                        RemediationSteps = @(
                            "Verify if this certificate was intentionally added",
                            "If unauthorized, remove with 'certmgr.msc' or 'Remove-Item -Path Cert:\Path\To\Certificate'"
                        )
                    }
            }
        } else {
            Write-Output "No self-signed certificates found in trusted stores."
            Add-Finding -CheckName "Self-Signed Certificates" -Status "Pass" `
                -Details "No self-signed certificates found in trusted stores." -Category "CertificateSecurity" `
                -AdditionalInfo $certInfo
        }
    }
    catch {
        $certInfo.ErrorEncountered = $true
        $certInfo.ErrorDetails = $_.Exception.Message
        
        Write-Output "Error checking for self-signed certificates: $_"
        Add-Finding -CheckName "Self-Signed Certificates" -Status "Fail" `
            -Details "Error checking certificate stores: $_" -Category "CertificateSecurity" `
            -AdditionalInfo $certInfo
    }
}
function Test-RDCManager {
    Write-SectionHeader "Remote Desktop Credentials Manager"
    $rdcPath = "$env:LOCALAPPDATA\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"
    
    # Create additional info object for JSON output
    $additionalInfo = @{
        RDCManPath = $rdcPath
        FileExists = $false
        FileSize = $null
        LastModified = $null
        SecurityRisk = "RDCMan files may contain encrypted credentials that can be decrypted"
    }
    
    if (Test-Path $rdcPath) {
        Write-Output "RDCMan settings found: $rdcPath"
        
        # Get file details for JSON output
        $fileInfo = Get-Item -Path $rdcPath -ErrorAction SilentlyContinue
        if ($fileInfo) {
            $additionalInfo.FileExists = $true
            $additionalInfo.FileSize = $fileInfo.Length
            $additionalInfo.LastModified = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            $additionalInfo.CreationTime = $fileInfo.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        
        # Check for .rdg files which contain connection details
        $rdgFiles = Get-ChildItem -Path "$env:USERPROFILE" -Include "*.rdg" -Recurse -ErrorAction SilentlyContinue
        if ($rdgFiles) {
            $additionalInfo.RDGFilesFound = $true
            $additionalInfo.RDGFiles = $rdgFiles | ForEach-Object {
                @{
                    Path = $_.FullName
                    LastModified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    Size = $_.Length
                }
            }
        } else {
            $additionalInfo.RDGFilesFound = $false
        }
        
        Add-Finding -CheckName "RDCMan" -Status "Fail" `
            -Details "RDCMan file found at $rdcPath" -Category "Credentials" `
            -AdditionalInfo $additionalInfo
    } else {
        Add-Finding -CheckName "RDCMan" -Status "Pass" `
            -Details "RDCMan not found." -Category "Credentials" `
            -AdditionalInfo $additionalInfo
    }
}

function Test-WSUSSettings {
    Write-SectionHeader "WSUS Settings"
    
    # Initialize comprehensive WSUS info object for JSON output
    $wsusInfo = @{
        IsConfigured = $false
        ServerURL = $null
        UsesSSL = $null
        StatUSURL = $null
        UseWUServer = $null
        AutoUpdateEnabled = $null
        AutoUpdateNotificationLevel = $null
        TargetGroup = $null
        SecurityRisks = @()
        RecommendedSettings = @()
    }
    
    # Check for WSUS server configuration
    $wsusServer = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
    $wsusStatusServer = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -ErrorAction SilentlyContinue
    $useWUServer = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue
    
    # Check AU settings
    $auEnabled = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    $auOptions = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
    $targetGroup = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetGroup" -ErrorAction SilentlyContinue
    
    # Update JSON info object with collected data
    if ($wsusServer) {
        $wsusInfo.IsConfigured = $true
        $wsusInfo.ServerURL = $wsusServer.WUServer
        $wsusInfo.UsesSSL = $wsusServer.WUServer -like "https://*"
        
        if ($wsusStatusServer) {
            $wsusInfo.StatusURL = $wsusStatusServer.WUStatusServer
        }
        
        if ($useWUServer) {
            $wsusInfo.UseWUServer = $useWUServer.UseWUServer -eq 1
        }
        
        if ($auEnabled) {
            $wsusInfo.AutoUpdateEnabled = $auEnabled.NoAutoUpdate -eq 0
        }
        
        if ($auOptions) {
            # Map AUOptions values to their meanings
            $auOptionMeaning = @{
                1 = "Never check for updates"
                2 = "Check for updates but let me choose whether to download and install them"
                3 = "Download updates but let me choose whether to install them"
                4 = "Install updates automatically"
                5 = "Allow local admin to choose setting"
            }
            
            $wsusInfo.AutoUpdateNotificationLevel = $auOptions.AUOptions
            $wsusInfo.AutoUpdateNotificationLevelMeaning = $auOptionMeaning[[int]$auOptions.AUOptions]
        }
        
        if ($targetGroup) {
            $wsusInfo.TargetGroup = $targetGroup.TargetGroup
        }
        
        # Assess security risks
        if (-not $wsusInfo.UsesSSL) {
            $wsusInfo.SecurityRisks += "WSUS is configured without SSL, leaving update traffic vulnerable to MITM attacks"
        }
        
        if ($wsusInfo.UseWUServer -ne $true) {
            $wsusInfo.SecurityRisks += "UseWUServer is not enabled, WSUS configuration may not be applied"
        }
        
        if ($wsusInfo.AutoUpdateEnabled -eq $false) {
            $wsusInfo.SecurityRisks += "Automatic updates are disabled, system may miss critical security patches"
        }
        
        # Add recommendations based on findings
        $wsusInfo.RecommendedSettings += "Configure WSUS with HTTPS for secure update delivery"
        $wsusInfo.RecommendedSettings += "Ensure UseWUServer is set to 1 (enabled)"
        $wsusInfo.RecommendedSettings += "Set AUOptions to 4 (install updates automatically) for critical systems"
        
        # Output results
        Write-Output "WSUS Server: $($wsusInfo.ServerURL)"
        if ($wsusInfo.StatusURL) {
            Write-Output "WSUS Status Server: $($wsusInfo.StatusURL)"
        }
        
        if ($wsusInfo.UsesSSL) {
            Write-Output "PASS: WSUS uses SSL for secure updates."
            Add-Finding -CheckName "WSUS Settings" -Status "Pass" `
                -Details "WSUS uses SSL: $($wsusInfo.ServerURL)" -Category "Update" `
                -AdditionalInfo $wsusInfo
        } else {
            Write-Output "FAIL: Non-SSL WSUS server detected: $($wsusInfo.ServerURL)"
            Add-Finding -CheckName "WSUS Settings" -Status "Fail" `
                -Details "Non-SSL WSUS detected: $($wsusInfo.ServerURL)" -Category "Update" `
                -AdditionalInfo $wsusInfo
        }
        
        # Additional output about update configuration
        if ($wsusInfo.AutoUpdateNotificationLevel) {
            Write-Output "Auto Update Setting: $($wsusInfo.AutoUpdateNotificationLevelMeaning)"
        }
        
        if ($wsusInfo.TargetGroup) {
            Write-Output "Target Group: $($wsusInfo.TargetGroup)"
        }
    } else {
        $wsusInfo.IsConfigured = $false
        Write-Output "No WSUS settings configured. System is likely using Microsoft Update directly."
        Add-Finding -CheckName "WSUS Settings" -Status "Info" `
            -Details "No WSUS settings configured." -Category "Update" `
            -AdditionalInfo $wsusInfo
    }
    
    # Check for dual-scan configuration (Windows 10/Server 2016+)
    $dualScanCheck = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableDualScan" -ErrorAction SilentlyContinue
    if ($null -ne $dualScanCheck) {
        $wsusInfo.DualScanDisabled = $dualScanCheck.DisableDualScan -eq 1
        
        if (-not $wsusInfo.DualScanDisabled) {
            Write-Output "WARNING: Dual-scan is not disabled. System may bypass WSUS and check Microsoft Update."
            $wsusInfo.SecurityRisks += "Dual-scan is enabled, which may cause systems to bypass WSUS for feature updates"
            
            Add-Finding -CheckName "WSUS Dual-Scan" -Status "Warning" `
                -Details "Dual-scan is not disabled, may bypass WSUS for certain updates" -Category "Update" `
                -AdditionalInfo @{
                    DualScanDisabled = $false
                    RecommendedSetting = "Set DisableDualScan=1 to ensure all updates come from WSUS"
                    RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
                }
        } else {
            Write-Output "PASS: Dual-scan is properly disabled."
        }
    } else {
        $wsusInfo.DualScanDisabled = $false
        if ($wsusInfo.IsConfigured) {
            Write-Output "WARNING: DisableDualScan is not configured. Windows 10/Server 2016+ systems may bypass WSUS for feature updates."
            $wsusInfo.SecurityRisks += "DisableDualScan is not configured, which may allow systems to bypass WSUS"
        }
    }
}

function Test-ServiceVulnerabilities {
    Write-SectionHeader "Service Vulnerabilities"
    
    # Initialize collections for JSON output
    $vulnerableServices = @{
        WritableBinaries = @()
        WritableRegistryKeys = @()
        UnquotedPaths = @()
        VulnerableCount = 0
        ServicesChecked = 0
    }
    
    # Check for writable service binaries
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -notlike "*system32*" }
    $vulnerableServices.ServicesChecked = $services.Count
    
    foreach ($service in $services) {
        $binaryPath = $service.PathName.Trim('"') -replace '[<>:"|?*]', ''
        if ($binaryPath -and (Test-WritablePermission -Path $binaryPath -Type "File")) {
            Write-Output "Writable binary: $binaryPath (Service: $($service.Name))"
            
            # Create detailed service info for JSON
            $serviceInfo = @{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                Description = $service.Description
                StartMode = $service.StartMode
                State = $service.State
                PathName = $service.PathName
                Account = $service.StartName
                WritablePath = $binaryPath
                VulnerabilityType = "Writable Binary"
                SecurityRisk = "Service binary can be replaced, enabling privilege escalation"
                Remediation = "Restrict write permissions to administrators only"
            }
            
            $vulnerableServices.WritableBinaries += $serviceInfo
            $vulnerableServices.VulnerableCount++
            
            Add-Finding -CheckName "Writable Service Binary: $($service.Name)" -Status "Fail" `
                -Details "Service binary $binaryPath is writable." -Category "ServiceSecurity" `
                -AdditionalInfo $serviceInfo
        }
    }
    
    # Check for writable service registry keys
    $serviceKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue
    foreach ($key in $serviceKeys) {
        if (Test-WritablePermission -Path $key.PSPath -Type "Registry") {
            Write-Output "Writable Registry Key: $($key.PSChildName)"
            
            # Get detailed info about this service from previous collection if available
            $relatedService = $services | Where-Object { $_.Name -eq $key.PSChildName }
            
            $registryInfo = @{
                ServiceName = $key.PSChildName
                RegistryPath = $key.PSPath
                DisplayName = if ($relatedService) { $relatedService.DisplayName } else { "Unknown" }
                State = if ($relatedService) { $relatedService.State } else { "Unknown" }
                VulnerabilityType = "Writable Registry Key"
                SecurityRisk = "Service configuration can be modified to execute arbitrary code"
                Remediation = "Restrict registry key permissions to administrators only"
            }
            
            $vulnerableServices.WritableRegistryKeys += $registryInfo
            $vulnerableServices.VulnerableCount++
            
            Add-Finding -CheckName "Writable Service Registry Key: $($key.PSChildName)" -Status "Fail" `
                -Details "Registry key $($key.PSChildName) is writable." -Category "ServiceSecurity" `
                -AdditionalInfo $registryInfo
        }
    }
    
    # Check for unquoted service paths
    foreach ($service in $services) {
        if ($service.PathName -notlike '"*' -and $service.PathName -match " ") {
            Write-Output "Unquoted path: $($service.Name) - $($service.PathName)"
            
            $unquotedPathInfo = @{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                PathName = $service.PathName
                StartMode = $service.StartMode
                Account = $service.StartName
                VulnerabilityType = "Unquoted Service Path"
                SecurityRisk = "May allow privilege escalation through path hijacking"
                WritableSegments = @()
                Remediation = "Enclose the entire path in double quotes"
            }
            
            # Check for writable path segments
            $pathParts = $service.PathName -split " "
            for ($i = 1; $i -lt $pathParts.Count; $i++) {
                $testPath = [string]::Join(" ", $pathParts[0..$i])
                if (Test-Path $testPath -ErrorAction SilentlyContinue) {
                    $isWritable = Test-WritablePermission -Path $testPath -Type "File"
                    
                    # Add segment info to the unquoted path info
                    $segmentInfo = @{
                        Path = $testPath
                        Exists = $true
                        Writable = $isWritable
                    }
                    $unquotedPathInfo.WritableSegments += $segmentInfo
                    
                    if ($isWritable) {
                        Write-Output "Writable segment: $testPath"
                        Add-Finding -CheckName "Unquoted Service Path Writable: $($service.Name)" -Status "Fail" `
                            -Details "Segment $testPath is writable." -Category "ServiceSecurity" `
                            -AdditionalInfo @{
                                ServiceName = $service.Name
                                DisplayName = $service.DisplayName
                                PathName = $service.PathName
                                WritableSegment = $testPath
                                SecurityRisk = "Allows privilege escalation by creating executables in path"
                            }
                    }
                }
            }
            
            $vulnerableServices.UnquotedPaths += $unquotedPathInfo
            $vulnerableServices.VulnerableCount++
            
            Add-Finding -CheckName "Unquoted Service Path: $($service.Name)" -Status "Warning" `
                -Details "Service path is not properly quoted: $($service.PathName)" -Category "ServiceSecurity" `
                -AdditionalInfo $unquotedPathInfo
        }
    }
    
    # Add comprehensive summary finding
    Add-Finding -CheckName "Service Vulnerabilities Summary" -Status "Info" `
        -Details "$($vulnerableServices.VulnerableCount) service vulnerabilities found among $($vulnerableServices.ServicesChecked) services checked." `
        -Category "ServiceSecurity" `
        -AdditionalInfo @{
            VulnerableServices = $vulnerableServices
            TotalVulnerabilities = $vulnerableServices.VulnerableCount
            ServicesChecked = $vulnerableServices.ServicesChecked
            WritableBinaryCount = $vulnerableServices.WritableBinaries.Count
            WritableRegistryKeyCount = $vulnerableServices.WritableRegistryKeys.Count
            UnquotedPathCount = $vulnerableServices.UnquotedPaths.Count
            Recommendations = @(
                "Use quoted paths for all service executables",
                "Restrict permissions on service binaries to administrators only",
                "Ensure service registry keys have appropriate permissions"
            )
        }
}

function Test-PATHHijacking {
    Write-SectionHeader "PATH Environment Hijacking"
    
    # Get all PATH entries
    $pathEntries = $env:Path.Split(";") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    
    # Initialize detailed info for JSON output
    $pathSecurityInfo = @{
        AllPaths = @()
        WritablePaths = @()
        NonExistentPaths = @()
        StandardPaths = @()
        TotalPathEntries = $pathEntries.Count
        WritablePathCount = 0
        NonExistentPathCount = 0
        PathOrderIssues = $false
        SecurityRisk = "Writable directories in PATH allow for DLL hijacking and malicious command execution"
    }
    
    # Check each path entry
    foreach ($path in $pathEntries) {
        $pathExists = Test-Path $path -ErrorAction SilentlyContinue
        $isWritable = $false
        $isSystemPath = $path -match "^[A-Z]:\\Windows|^[A-Z]:\\Program Files|^[A-Z]:\\Program Files \(x86\)"
        
        # Only test writability if the path exists
        if ($pathExists) {
            $isWritable = Test-WritablePermission -Path $path -Type "File"
        }
        
        # Create detailed path info for JSON
        $pathDetail = @{
            Path = $path
            Exists = $pathExists
            IsWritable = $isWritable
            IsSystemPath = $isSystemPath
            Position = [array]::IndexOf($pathEntries, $path) + 1
        }
        
        # Add to the appropriate collection in our JSON info
        $pathSecurityInfo.AllPaths += $pathDetail
        
        if (-not $pathExists) {
            Write-Output "Non-existent PATH entry: $path"
            $pathSecurityInfo.NonExistentPaths += $pathDetail
            $pathSecurityInfo.NonExistentPathCount++
        } elseif ($isWritable) {
            Write-Output "Writable PATH directory: $path"
            $pathSecurityInfo.WritablePaths += $pathDetail
            $pathSecurityInfo.WritablePathCount++
            
            # Add individual finding for each writable path
            Add-Finding -CheckName "Writable PATH Directory" -Status "Fail" `
                -Details "Writable PATH directory: $path" -Category "EnvSecurity" `
                -AdditionalInfo @{
                    Path = $path
                    Position = $pathDetail.Position
                    SecurityRisk = "Applications may load malicious DLLs from this directory"
                    Recommendation = "Remove this directory from PATH or restrict write permissions to administrators only"
                }
        } elseif ($isSystemPath) {
            $pathSecurityInfo.StandardPaths += $pathDetail
        }
    }
    
    # Check if non-system paths appear before system paths (potential precedence issue)
    $systemPaths = $pathSecurityInfo.AllPaths | Where-Object { $_.IsSystemPath }
    $firstSystemPath = $systemPaths | Select-Object -First 1
    $firstSystemPathPos = if ($firstSystemPath) { $firstSystemPath.Position } else { [int]::MaxValue }
    
    $nonSystemBeforeSystem = $pathSecurityInfo.AllPaths | Where-Object { 
        -not $_.IsSystemPath -and $_.Position -lt $firstSystemPathPos 
    }
    
    if ($nonSystemBeforeSystem -and $nonSystemBeforeSystem.Count -gt 0) {
        $pathSecurityInfo.PathOrderIssues = $true
        Write-Output "WARNING: Non-system directories appear before system directories in PATH"
        
        # Add finding for PATH order issues
        Add-Finding -CheckName "PATH Order Issues" -Status "Warning" `
            -Details "Non-system directories have precedence in PATH" -Category "EnvSecurity" `
            -AdditionalInfo @{
                NonSystemPathsWithPrecedence = $nonSystemBeforeSystem
                FirstSystemPathPosition = $firstSystemPathPos
                SecurityRisk = "Applications may load DLLs from user-controlled directories before system directories"
                Recommendation = "Reorder PATH to place system directories first"
            }
    }
    
    # Add summary finding
    if ($pathSecurityInfo.WritablePathCount -eq 0) {
        Write-Output "PASS: No writable PATH directories detected."
        Add-Finding -CheckName "PATH Environment Security" -Status "Pass" `
            -Details "No writable PATH directories detected." -Category "EnvSecurity" `
            -AdditionalInfo $pathSecurityInfo
    } else {
        Add-Finding -CheckName "PATH Environment Security" -Status "Fail" `
            -Details "Found $($pathSecurityInfo.WritablePathCount) writable PATH directories." -Category "EnvSecurity" `
            -AdditionalInfo $pathSecurityInfo
    }
    
    # Add finding for non-existent paths if any found
    if ($pathSecurityInfo.NonExistentPathCount -gt 0) {
        Add-Finding -CheckName "Non-existent PATH Entries" -Status "Warning" `
            -Details "Found $($pathSecurityInfo.NonExistentPathCount) non-existent PATH entries." -Category "EnvSecurity" `
            -AdditionalInfo @{
                NonExistentPaths = $pathSecurityInfo.NonExistentPaths
                Recommendation = "Clean up PATH by removing non-existent directory entries"
            }
    }
}
function Test-Credentials {
    Write-SectionHeader "Credentials and Sensitive Files"
    
    # Initialize comprehensive object for JSON output
    $credentialInfo = @{
        WindowsVault = @()
        DPAPIMasterKeys = @()
        CredentialFiles = @()
        UnattendedFiles = @()
        SensitiveBackups = @()
        SecurityConcerns = @()
    }
    
    # Check Windows Vault
    Write-Output "Windows Vault:"
    $vaultOutput = cmdkey /list 2>$null
    $vaultOutput | Out-String | Write-Output
    
    # Parse vault output for JSON
    foreach ($line in $vaultOutput) {
        if ($line -match "Target:\s+(.+)") {
            $credentialInfo.WindowsVault += @{
                Target = $matches[1].Trim()
                Type = if ($line -match "TERMSRV|DOMAIN") { "Remote Desktop/Domain" } else { "Generic" }
            }
        }
    }
    
    # Check DPAPI Master Keys
    Write-Output "DPAPI Master Keys:"
    $dpapiPaths = @("$env:APPDATA\Microsoft\Protect", "$env:LOCALAPPDATA\Microsoft\Protect")
    foreach ($path in $dpapiPaths) {
        if (Test-Path $path) {
            $keys = Get-ChildItem $path -ErrorAction SilentlyContinue
            $keys | Format-Table Name, FullName -AutoSize | Out-String | Write-Output
            
            # Add to JSON object
            foreach ($key in $keys) {
                $credentialInfo.DPAPIMasterKeys += @{
                    Name = $key.Name
                    FullPath = $key.FullName
                    LastWriteTime = $key.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    SizeBytes = $key.Length
                    ParentPath = $path
                }
            }
            
            if ($keys.Count -gt 0) {
                $credentialInfo.SecurityConcerns += "DPAPI Master Keys can be targeted for credential theft if extracted"
            }
        }
    }
    
    # Check Credential Files
    Write-Output "Credential Files:"
    $credPaths = @("$env:APPDATA\Microsoft\Credentials\", "$env:LOCALAPPDATA\Microsoft\Credentials\")
    foreach ($path in $credPaths) {
        if (Test-Path $path) {
            $credFiles = Get-ChildItem $path -ErrorAction SilentlyContinue
            $credFiles | Format-Table Name, FullName -AutoSize | Out-String | Write-Output
            
            # Add to JSON object
            foreach ($file in $credFiles) {
                $credentialInfo.CredentialFiles += @{
                    Name = $file.Name
                    FullPath = $file.FullName
                    LastWriteTime = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    SizeBytes = $file.Length
                    ParentPath = $path
                }
            }
            
            if ($credFiles.Count -gt 0) {
                $credentialInfo.SecurityConcerns += "Windows Credential files contain encrypted credentials which might be extractable"
            }
        }
    }
    
    # Check Unattended Install Files
    Write-Output "Unattended Install Files:"
    $unattendedFiles = @(
        "$env:WINDIR\sysprep\sysprep.xml",
        "$env:WINDIR\sysprep\sysprep.inf",
        "$env:WINDIR\Panther\Unattended.xml",
        "$env:WINDIR\System32\Sysprep\unattend.xml",
        "$env:WINDIR\Panther\Unattend\Unattended.xml",
        "$env:WINDIR\system32\sysprep.inf",
        "$env:WINDIR\system32\sysprep\sysprep.xml",
        "C:\unattend.xml",
        "C:\unattend.txt"
    )
    
    $foundUnattendedFiles = @()
    foreach ($file in $unattendedFiles) {
        if (Test-Path $file -ErrorAction SilentlyContinue) {
            Write-Output "Found: $file"
            $fileInfo = Get-Item $file -ErrorAction SilentlyContinue
            
            # Check for clear-text passwords
            $containsPassword = $false
            $content = Get-Content $file -ErrorAction SilentlyContinue
            if ($content -match "password|cpassword|Password") {
                $containsPassword = $true
                Write-Output "WARNING: File may contain passwords: $file"
                $credentialInfo.SecurityConcerns += "Unattended install file may contain cleartext credentials"
            }
            
            $foundUnattendedFiles += @{
                Path = $file
                LastWriteTime = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                SizeBytes = $fileInfo.Length
                ContainsPassword = $containsPassword
            }
        }
    }
    
    # Add unattended files to JSON
    $credentialInfo.UnattendedFiles = $foundUnattendedFiles
    
    # Check SAM and SYSTEM Backups
    Write-Output "SAM and SYSTEM Backups:"
    $backupFiles = @(
        "$env:WINDIR\repair\SAM",
        "$env:WINDIR\System32\config\RegBack\SAM",
        "$env:WINDIR\repair\SYSTEM",
        "$env:WINDIR\System32\config\RegBack\SYSTEM",
        "$env:WINDIR\repair\SECURITY",
        "$env:WINDIR\System32\config\RegBack\SECURITY"
    )
    
    $foundBackups = @()
    foreach ($file in $backupFiles) {
        if (Test-Path $file -ErrorAction SilentlyContinue) {
            Write-Output "Found: $file"
            $fileInfo = Get-Item $file -ErrorAction SilentlyContinue
            
            # Add to collection
            $foundBackups += @{
                Path = $file
                LastWriteTime = $fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                SizeBytes = $fileInfo.Length
                IsAccessible = (Test-WritablePermission -Path $file -Type "File")
            }
            
            if (Test-WritablePermission -Path $file -Type "File") {
                Write-Output "WARNING: Backup file has improper permissions: $file"
                $credentialInfo.SecurityConcerns += "SAM/SYSTEM backup files have improper permissions"
            }
        }
    }
    
    # Add backup files to JSON
    $credentialInfo.SensitiveBackups = $foundBackups
    
    # Check for Group Policy Preference passwords
    Write-Output "Checking Group Policy Preference Files:"
    $gpPrefFiles = @()
    try {
        $gpPrefFiles = Get-ChildItem "$env:WINDIR\SYSVOL" -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Output "Error accessing SYSVOL directory."
    }
    
    if ($gpPrefFiles -and $gpPrefFiles.Count -gt 0) {
        Write-Output "Found potential GPP password files:"
        $gpPrefFiles | Format-Table Name, FullName -AutoSize
        
        $credentialInfo.GPPFiles = $gpPrefFiles | ForEach-Object {
            $containsCPassword = $false
            $content = Get-Content $_.FullName -ErrorAction SilentlyContinue
            if ($content -match "cpassword=") {
                $containsCPassword = $true
                Write-Output "WARNING: GPP file contains cpassword: $($_.FullName)"
                $credentialInfo.SecurityConcerns += "Group Policy Preference files with encrypted passwords found (can be decrypted)"
            }
            
            @{
                Name = $_.Name
                Path = $_.FullName
                LastWriteTime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                ContainsCPassword = $containsCPassword
            }
        }
    }
    
    # Add findings based on credential checks
    if ($foundUnattendedFiles.Count -gt 0) {
        Add-Finding -CheckName "Unattended Install Files" -Status "Fail" `
            -Details "Found $($foundUnattendedFiles.Count) unattended installation files." -Category "Credentials" `
            -AdditionalInfo @{
                FilesFound = $foundUnattendedFiles
                SecurityRisk = "Unattended installation files may contain plaintext or weakly encrypted credentials"
                Remediation = "Remove these files after deployment is complete"
            }
    }
    
    if ($foundBackups.Count -gt 0) {
        Add-Finding -CheckName "SAM/SYSTEM Backups" -Status "Fail" `
            -Details "Found $($foundBackups.Count) SAM/SYSTEM backup files." -Category "Credentials" `
            -AdditionalInfo @{
                FilesFound = $foundBackups
                SecurityRisk = "SAM and SYSTEM backups can be used to extract password hashes offline"
                Remediation = "Remove unnecessary backup files or restrict permissions"
            }
    }
    
    # Generate summary finding
    Add-Finding -CheckName "Credentials and Sensitive Files" -Status "Info" `
        -Details "Found $($credentialInfo.CredentialFiles.Count) credential files, $($credentialInfo.UnattendedFiles.Count) unattended files, $($credentialInfo.SensitiveBackups.Count) sensitive backups" `
        -Category "Credentials" `
        -AdditionalInfo $credentialInfo
}

function Test-ExtendedDriveScan {
    if ($ExtendedScan) {
        Write-SectionHeader "Extended Drive Scan"
        
        # Initialize comprehensive object for JSON output
        $scanInfo = @{
            RegistryScanResults = @()
            FileScanResults = @()
            TotalRegKeysMatched = 0
            TotalFilesMatched = 0
            DrivesScanAttempted = 0
            DrivesScanCompleted = 0
            ScanTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            SearchTerms = @("passw", "pwd", "secret", "credentials", "api_key")
            FileTypesScanned = @("*.xml", "*.ini", "*.txt", "*.cfg", "*.config", "*.json", "*.ps1", "*.bat")
        }
        
        # Registry Search for Sensitive Strings
        Write-Output "Registry Search for Sensitive Strings:"
        $regKeys = @("HKLM", "HKCU")
        
        foreach ($key in $regKeys) {
            foreach ($term in $scanInfo.SearchTerms) {
                Write-Output "Searching $key for '$term'..."
                try {
                    $results = reg query $key /f $term /t REG_SZ /s 2>$null
                    if ($results) {
                        $results | Out-String | Write-Output
                        
                        # Process each matching registry key for JSON
                        foreach ($line in $results) {
                            if ($line -match "HKEY_") {
                                $scanInfo.RegistryScanResults += @{
                                    RegistryKey = $line.Trim()
                                    SearchTerm = $term
                                    RootKey = $key
                                }
                                $scanInfo.TotalRegKeysMatched++
                            }
                        }
                    }
                }
                catch {
                    Write-Output "Error searching registry key $key for term $term`: $_"
                }
            }
        }
        
        # File Search for sensitive terms
        Write-Output "File Search for Sensitive Terms:"
        $drives = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq "Fixed" }
        $scanInfo.DrivesScanAttempted = $drives.Count
        
        foreach ($drive in $drives) {
            $drivePath = "$($drive.DriveLetter):"
            Write-Output "Scanning $drivePath..."
            
            try {
                foreach ($term in $scanInfo.SearchTerms) {
                    $filesMatched = @()
                    
                    Get-ChildItem -Path $drivePath -Recurse -Include $scanInfo.FileTypesScanned -ErrorAction SilentlyContinue | 
                        ForEach-Object {
                            $file = $_
                            try {
                                $matchInfo = Select-String -Path $file.FullName -Pattern $term -ErrorAction SilentlyContinue
                                if ($matchInfo) {
                                    $matchInfo | ForEach-Object {
                                        $filesMatched += @{
                                            Path = $file.FullName
                                            LineNumber = $_.LineNumber
                                            Line = $_.Line.Trim()
                                            MatchTerm = $term
                                            FileType = $file.Extension
                                            FileSize = $file.Length
                                            LastModified = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                                        }
                                        
                                        # Display in console with limited line info for readability
                                        $linePreview = if ($_.Line.Length -gt 100) { 
                                            "$($_.Line.Substring(0, 97))..." 
                                        } else { 
                                            $_.Line 
                                        }
                                        Write-Output "  $($file.FullName) (Line $($_.LineNumber)): $linePreview"
                                    }
                                }
                            }
                            catch {
                                # Silently continue for individual file errors
                            }
                        }
                    
                    # Add all matches for this term to the results collection
                    $scanInfo.FileScanResults += $filesMatched
                    $scanInfo.TotalFilesMatched += $filesMatched.Count
                }
                
                $scanInfo.DrivesScanCompleted++
            }
            catch {
                Write-Output "Error scanning drive $drivePath`: $_"
            }
        }
        
        # Create findings based on scan results
        if ($scanInfo.TotalRegKeysMatched -gt 0) {
            Add-Finding -CheckName "Registry Sensitive Information" -Status "Warning" `
                -Details "$($scanInfo.TotalRegKeysMatched) registry keys found containing sensitive terms." -Category "DataExposure" `
                -AdditionalInfo @{
                    RegistryMatches = $scanInfo.TotalRegKeysMatched
                    RegistryResults = $scanInfo.RegistryScanResults
                    SearchTerms = $scanInfo.SearchTerms
                    SecurityRisk = "Registry may contain sensitive information in plaintext"
                    Remediation = "Review registry keys for exposed credentials and remove or secure them"
                }
        }
        
        if ($scanInfo.TotalFilesMatched -gt 0) {
            Add-Finding -CheckName "File System Sensitive Information" -Status "Warning" `
                -Details "$($scanInfo.TotalFilesMatched) files found containing potentially sensitive information." -Category "DataExposure" `
                -AdditionalInfo @{
                    FilesMatched = $scanInfo.TotalFilesMatched
                    FileResults = ($scanInfo.FileScanResults | Select-Object -First 100) # Limit to 100 entries to avoid huge JSON
                    TotalMatchesFound = $scanInfo.FileScanResults.Count
                    DrivesScanAttempted = $scanInfo.DrivesScanAttempted
                    DrivesScanCompleted = $scanInfo.DrivesScanCompleted
                    SearchTerms = $scanInfo.SearchTerms
                    FileTypesScanned = $scanInfo.FileTypesScanned
                    SecurityRisk = "Files may contain plaintext credentials or other sensitive information"
                    Remediation = "Review and secure files containing sensitive data"
                }
        }
        
        # Add a summary finding
        Add-Finding -CheckName "Extended Drive Scan Summary" -Status "Info" `
            -Details "Extended drive scan completed. Scanned $($scanInfo.DrivesScanCompleted)/$($scanInfo.DrivesScanAttempted) drives." -Category "ExtendedScan" `
            -AdditionalInfo $scanInfo
    }
}

function Test-DirectorySecurityPermissions {
    Write-SectionHeader "Directory Security Permissions"
    
    # Initialize comprehensive object for JSON output
    $dirSecurityInfo = @{
        CommonDirectories = @()
        WritableCount = 0
        TotalChecked = 0
        SecurityRisks = @()
    }
    
    # Extended list of critical directories to check
    $commonDirs = @(
        "C:\Windows\Temp", 
        "C:\Temp", 
        "C:\Program Files", 
        "C:\Program Files (x86)",
        "$env:windir\System32\Tasks",
        "$env:windir\System32\spool\drivers",
        "$env:ALLUSERSPROFILE\Microsoft\Crypto",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($dir in $commonDirs) {
        # Create detailed directory info for the directory being checked
        $dirInfo = @{
            Path = $dir
            Exists = $false
            IsWritable = $false
            HasExcessivePermissions = $false
            Permissions = @()
            Criticality = if ($dir -match "System32|Crypto|Startup") { "High" } else { "Medium" }
        }
        
        $dirSecurityInfo.TotalChecked++
        
        if (Test-Path $dir -ErrorAction SilentlyContinue) {
            $dirInfo.Exists = $true
            
            # Get ACL information for more comprehensive reporting
            try {
                $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                $dirInfo.Permissions = $acl.Access | ForEach-Object {
                    @{
                        IdentityReference = $_.IdentityReference.ToString()
                        FileSystemRights = $_.FileSystemRights.ToString()
                        AccessControlType = $_.AccessControlType.ToString()
                        IsInherited = $_.IsInherited
                    }
                }
                
                # Check for excessive permissions for non-administrative users
                $everyonePerms = $acl.Access | Where-Object { 
                    $_.IdentityReference -match "Everyone|EVERYONE|Authenticated Users|Users" -and 
                    $_.FileSystemRights -match "Write|Modify|FullControl"
                }
                
                if ($everyonePerms) {
                    $dirInfo.HasExcessivePermissions = $true
                    $dirInfo.ProblematicPermissions = $everyonePerms | ForEach-Object {
                        @{
                            IdentityReference = $_.IdentityReference.ToString()
                            FileSystemRights = $_.FileSystemRights.ToString()
                        }
                    }
                }
            }
            catch {
                # ACL info retrieval failed
                $dirInfo.Error = $_.Exception.Message
            }
            
            # Test for basic writability
            if (Test-WritablePermission -Path $dir -Type "File") {
                $dirInfo.IsWritable = $true
                $dirSecurityInfo.WritableCount++
                
                Write-Output "Writable: $dir"
                
                # Add specific security risks for this directory
                if ($dir -match "System32|Tasks") {
                    $risk = "Could allow creation of malicious scheduled tasks for privilege escalation"
                    $dirSecurityInfo.SecurityRisks += $risk
                } elseif ($dir -match "Startup") {
                    $risk = "Could allow persistence via startup applications"
                    $dirSecurityInfo.SecurityRisks += $risk
                } elseif ($dir -match "Crypto") {
                    $risk = "Could allow tampering with cryptographic assets"
                    $dirSecurityInfo.SecurityRisks += $risk
                } else {
                    $risk = "Could allow placement of malicious files"
                    $dirSecurityInfo.SecurityRisks += $risk
                }
                
                Add-Finding -CheckName "Writable Common Directory" -Status "Fail" `
                    -Details "Directory $dir is writable." -Category "FileSystemSecurity" `
                    -AdditionalInfo @{
                        Path = $dir
                        SecurityRisk = $risk
                        Criticality = $dirInfo.Criticality
                        Permissions = $dirInfo.Permissions
                        ProblematicPermissions = if ($dirInfo.HasExcessivePermissions) { $dirInfo.ProblematicPermissions } else { $null }
                        Recommendation = "Restrict write permissions to administrators only"
                    }
            } else {
                Write-Output "Not writable: $dir"
            }
            
            # Add directory info to our collection
            $dirSecurityInfo.CommonDirectories += $dirInfo
        } else {
            Write-Output "Directory not found: $dir"
            $dirSecurityInfo.CommonDirectories += $dirInfo
        }
    }
    
    # Add a summary finding with all directory security information
    Add-Finding -CheckName "Common Directory Permissions Summary" -Status "Info" `
        -Details "$($dirSecurityInfo.WritableCount) of $($dirSecurityInfo.TotalChecked) critical directories are writable." `
        -Category "FileSystemSecurity" `
        -AdditionalInfo $dirSecurityInfo
}



# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

Write-Output "Starting assessment on $env:COMPUTERNAME at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# System Enumeration
Get-SystemInformation

# Security Checks
Test-OS_EOL
Test-AntivirusStatus
Test-RegisteredAntivirus
Test-PatchManagement
Test-TimeConfiguration
Test-AuditAndLogging
Test-EventLogForwarding
Test-LAPS
Test-CredentialProtection
Test-AuthenticationControls
Test-PowerShellSecurity
Test-PowerShellHistory
Test-StorageEncryption
Test-NetworkConfiguration
Test-SoftwareInventory
Test-UserAccountSecurity
Test-UnquotedServicePaths
Test-DirectoryPermissions
Test-RegistrySecurity
Test-AdvancedNetworkSecurity
Test-WindowsServices
Test-SmbSigningEnabled
Test-SelfSignedCerts
Test-RDCManager
Test-WSUSSettings
Test-ServiceVulnerabilities
Test-PATHHijacking
Test-Credentials
Test-ExtendedDriveScan
Test-DirectorySecurityPermissions
Test-CachedCredentials
Test-CredentialGuard
Test-WifiProfiles
Test-NetworkNeighborCache
Test-NetTCPConnection
Test-LocalRouteTable
Test-AccessibilityExecutables 
# Test-NetworkAdapters
# Test-IPConfiguration
# Test-FirewallProfiles
# Test-RiskyFirewallRules
# Test-SMBConfiguration
# Test-NetworkConnections
# Test-NetworkConfigurationSummary
# Test-NetTCPConnection

# Threat Hunting
Test-ThreatHunting_EnvVariables
Test-ThreatHunting_ScheduledTasks
# Test-AMSIBypass
Test-WMIEventSubscriptions
Test-SuspiciousServices
Test-UnsignedDrivers
Test-UnusualDLLs
Test-PrefetchFiles


# Write JSON report
$JsonOutputPath = "$env:COMPUTERNAME`_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
# Convert any non-string keys in hashtables to strings before serialization
function ConvertTo-StringKeysRecursive($object) {
    if ($object -is [Hashtable]) {
        $newHashtable = @{}
        foreach ($key in $object.Keys) {
            # Convert the key to string
            $stringKey = "$key"
            # Process the value recursively
            $newHashtable[$stringKey] = ConvertTo-StringKeysRecursive $object[$key]
        }
        return $newHashtable
    }
    elseif ($object -is [System.Collections.IEnumerable] -and $object -isnot [string]) {
        return @($object | ForEach-Object { ConvertTo-StringKeysRecursive $_ })
    }
    else {
        return $object
    }
}

# Convert findings to ensure all keys are strings
$global:Findings = ConvertTo-StringKeysRecursive $global:Findings

# Export to JSON
Export-FindingsToJson -JsonOutputPath $JsonOutputPath

Write-Output "`nSecurity findings have been exported to: $JsonOutputPath"