# -----------------------------------------------------------------------------
# System Services Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for Windows service configurations and security settings.

.DESCRIPTION
    This function analyzes Windows services for security-related configurations,
    including service accounts, startup types, and dependencies.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of service configurations.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-SystemServices -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-SystemServices {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$DetailedAnalysis,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators
    )

    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-SystemServices" -Category "System" `
        -Description "Analyzes Windows service configurations and security settings"

    try {
        # Get all services
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType

        # Check for services running with elevated privileges
        $elevatedServices = $services | Where-Object { $_.ServiceType -eq "Win32OwnProcess" }
        if ($elevatedServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Elevated Services" -Status "Info" `
                -Description "Found $($elevatedServices.Count) services running with elevated privileges" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Service Type"
                    Count = $elevatedServices.Count
                    Services = $elevatedServices | Select-Object Name, DisplayName
                }
        }

        # Check for auto-start services
        $autoStartServices = $services | Where-Object { $_.StartType -eq "Automatic" }
        if ($autoStartServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Auto-Start Services" -Status "Info" `
                -Description "Found $($autoStartServices.Count) services configured to start automatically" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Start Type"
                    Count = $autoStartServices.Count
                    Services = $autoStartServices | Select-Object Name, DisplayName
                }
        }

        # Check for stopped services
        $stoppedServices = $services | Where-Object { $_.Status -eq "Stopped" }
        if ($stoppedServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Stopped Services" -Status "Info" `
                -Description "Found $($stoppedServices.Count) services that are stopped" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Service Status"
                    Count = $stoppedServices.Count
                    Services = $stoppedServices | Select-Object Name, DisplayName
                }
        }

        # Check for services running under LocalSystem
        $systemServices = Get-WmiObject -Class Win32_Service | Where-Object { $_.StartName -eq "LocalSystem" }
        if ($systemServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "LocalSystem Services" -Status "Warning" `
                -Description "Found $($systemServices.Count) services running under LocalSystem account" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Service Account"
                    Count = $systemServices.Count
                    Services = $systemServices | Select-Object Name, DisplayName
                    Recommendation = "Review and restrict services running under LocalSystem account"
                }
        }

        # Check for services with weak permissions
        $weakPermServices = @()
        foreach ($service in $services) {
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
            $acl = Get-Acl -Path $servicePath -ErrorAction SilentlyContinue
            if ($acl) {
                $weakPerms = $acl.Access | Where-Object { 
                    $_.IdentityReference -notmatch "NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService" -and
                    $_.FileSystemRights -match "FullControl|Modify|Write"
                }
                if ($weakPerms) {
                    $weakPermServices += @{
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        WeakPermissions = $weakPerms | Select-Object IdentityReference, FileSystemRights
                    }
                }
            }
        }

        if ($weakPermServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Weak Service Permissions" -Status "Warning" `
                -Description "Found $($weakPermServices.Count) services with weak permissions" -RiskLevel "High" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Service Permissions"
                    Count = $weakPermServices.Count
                    Services = $weakPermServices
                    Recommendation = "Review and restrict service permissions to authorized accounts only"
                }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during system services analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SystemServices 