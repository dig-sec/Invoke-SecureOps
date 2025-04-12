# -----------------------------------------------------------------------------
# Windows Services Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for security issues in Windows services.

.DESCRIPTION
    This function analyzes Windows services for security issues,
    unauthorized configurations, and potential vulnerabilities.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of services.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-WindowsServices -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-WindowsServices {
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
    $result = Initialize-JsonOutput -Category "Security" -RiskLevel "Info" -ActionLevel "Review"
    $result.Description = "Analysis of Windows services for security issues"

    try {
        # Get all services
        $services = Get-Service -ErrorAction Stop
        
        # Check for services with automatic restart
        $autoRestartServices = $services | Where-Object { $_.StartType -eq "Automatic" }
        
        if ($autoRestartServices) {
            $serviceDetails = $autoRestartServices | ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Status = $_.Status
                    StartType = $_.StartType
                }
            }
            
            Add-Finding -TestResult $result -FindingName "Automatic Start Services" `
                -Status "Info" -RiskLevel "Info" `
                -Description "Found $($autoRestartServices.Count) services configured to start automatically" `
                -AdditionalInfo @{
                    Component = "WindowsServices"
                    ServiceCount = $autoRestartServices.Count
                    Services = $serviceDetails
                    Recommendation = "Review these services and verify they are necessary"
                }
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result `
                    -FindingName "Automatic Services" `
                    -EvidenceType "WindowsServices" `
                    -EvidenceData @{
                        ServiceCount = $autoRestartServices.Count
                        Services = $serviceDetails
                    } `
                    -Description "Services configured to start automatically"
            }
        }
        
        # Check for services with delayed auto-start
        $delayedServices = $services | Where-Object { $_.StartType -eq "Automatic" }
        
        if ($delayedServices) {
            $serviceDetails = $delayedServices | ForEach-Object {
                $serviceConfig = Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Status = $_.Status
                    StartType = $_.StartType
                    DelayedAutoStart = if ($serviceConfig) { $serviceConfig.DelayedAutoStart } else { $false }
                }
            }
            
            $delayedServices = $serviceDetails | Where-Object { $_.DelayedAutoStart -eq $true }
            
            if ($delayedServices) {
                Add-Finding -TestResult $result -FindingName "Delayed Auto-Start Services" `
                    -Status "Info" -RiskLevel "Info" `
                    -Description "Found $($delayedServices.Count) services configured with delayed auto-start" `
                    -AdditionalInfo @{
                        Component = "WindowsServices"
                        ServiceCount = $delayedServices.Count
                        Services = $delayedServices
                        Recommendation = "Review these services and verify they are necessary"
                    }
                
                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Delayed Services" `
                        -EvidenceType "WindowsServices" `
                        -EvidenceData @{
                            ServiceCount = $delayedServices.Count
                            Services = $delayedServices
                        } `
                        -Description "Services configured with delayed auto-start"
                }
            }
        }
        
        # Check for services running under the Network Service account
        $networkServiceServices = $services | Where-Object { $_.StartType -eq "Automatic" }
        
        if ($networkServiceServices) {
            $serviceDetails = $networkServiceServices | ForEach-Object {
                $serviceConfig = Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Status = $_.Status
                    StartType = $_.StartType
                    StartName = if ($serviceConfig) { $serviceConfig.StartName } else { "Unknown" }
                }
            }
            
            $networkServiceServices = $serviceDetails | Where-Object { $_.StartName -eq "NT AUTHORITY\NetworkService" }
            
            if ($networkServiceServices) {
                Add-Finding -TestResult $result -FindingName "Network Service Account Services" `
                    -Status "Warning" -RiskLevel "Medium" `
                    -Description "Found $($networkServiceServices.Count) services running under the Network Service account" `
                    -AdditionalInfo @{
                        Component = "WindowsServices"
                        ServiceCount = $networkServiceServices.Count
                        Services = $networkServiceServices
                        Recommendation = "Review these services and verify they should run under the Network Service account"
                    }
                
                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Network Service Account" `
                        -EvidenceType "WindowsServices" `
                        -EvidenceData @{
                            ServiceCount = $networkServiceServices.Count
                            Services = $networkServiceServices
                        } `
                        -Description "Services running under the Network Service account"
                }
            }
        }
        
        # Check for services with weak permissions
        $weakPermissionServices = $services | Where-Object { $_.StartType -eq "Automatic" }
        
        if ($weakPermissionServices) {
            $serviceDetails = $weakPermissionServices | ForEach-Object {
                $serviceConfig = Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
                $acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -ErrorAction SilentlyContinue
                
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Status = $_.Status
                    StartType = $_.StartType
                    StartName = if ($serviceConfig) { $serviceConfig.StartName } else { "Unknown" }
                    Acl = if ($acl) { $acl.Access | ForEach-Object { @{ IdentityReference = $_.IdentityReference; FileSystemRights = $_.FileSystemRights; AccessControlType = $_.AccessControlType } } } else { @() }
                }
            }
            
            $weakPermissionServices = $serviceDetails | Where-Object { 
                $_.Acl | Where-Object { 
                    $_.IdentityReference -eq "BUILTIN\Users" -and 
                    $_.FileSystemRights -match "Modify|FullControl" -and 
                    $_.AccessControlType -eq "Allow" 
                }
            }
            
            if ($weakPermissionServices) {
                Add-Finding -TestResult $result -FindingName "Weak Service Permissions" `
                    -Status "Warning" -RiskLevel "High" `
                    -Description "Found $($weakPermissionServices.Count) services with weak permissions" `
                    -AdditionalInfo @{
                        Component = "WindowsServices"
                        ServiceCount = $weakPermissionServices.Count
                        Services = $weakPermissionServices
                        Recommendation = "Review and strengthen permissions for these services"
                    }
                
                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Weak Permissions" `
                        -EvidenceType "WindowsServices" `
                        -EvidenceData @{
                            ServiceCount = $weakPermissionServices.Count
                            Services = $weakPermissionServices
                        } `
                        -Description "Services with weak permissions"
                }
            }
        }
        
        # Export results if path is provided
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Windows Services Analysis"
        
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during Windows services analysis: $($errorInfo.ErrorMessage)" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and service access"
            }
        
        # Export results if path is provided
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
} 