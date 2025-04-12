# -----------------------------------------------------------------------------
# Windows Services Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for Windows-specific service configurations and security settings.

.DESCRIPTION
    This function analyzes Windows services for security-related configurations,
    including service dependencies, recovery options, and Windows-specific settings.

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
    $result = Initialize-TestResult -TestName "Test-WindowsServices" -Category "System" `
        -Description "Analyzes Windows-specific service configurations and security settings"

    try {
        # Get all Windows services with detailed information
        $services = Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, State, StartMode, 
            PathName, ProcessId, ServiceType, StartName, Description, ErrorControl, TagId, 
            DelayedAutoStart, ServiceDependencies

        # Check for services with automatic restart on failure
        $autoRestartServices = $services | Where-Object { $_.ErrorControl -eq 1 }
        if ($autoRestartServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Auto-Restart Services" -Status "Info" `
                -Description "Found $($autoRestartServices.Count) services configured to restart automatically on failure" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Error Control"
                    Count = $autoRestartServices.Count
                    Services = $autoRestartServices | Select-Object Name, DisplayName
                }
        }

        # Check for delayed auto-start services
        $delayedServices = $services | Where-Object { $_.DelayedAutoStart -eq $true }
        if ($delayedServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Delayed Auto-Start Services" -Status "Info" `
                -Description "Found $($delayedServices.Count) services configured for delayed auto-start" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Delayed Auto-Start"
                    Count = $delayedServices.Count
                    Services = $delayedServices | Select-Object Name, DisplayName
                }
        }

        # Check for services with dependencies
        $dependentServices = $services | Where-Object { $_.ServiceDependencies.Count -gt 0 }
        if ($dependentServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Dependent Services" -Status "Info" `
                -Description "Found $($dependentServices.Count) services with dependencies" -RiskLevel "Low" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Service Dependencies"
                    Count = $dependentServices.Count
                    Services = $dependentServices | Select-Object Name, DisplayName, ServiceDependencies
                }
        }

        # Check for services running with network service account
        $networkServices = $services | Where-Object { $_.StartName -eq "NT AUTHORITY\NetworkService" }
        if ($networkServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Network Service Account" -Status "Info" `
                -Description "Found $($networkServices.Count) services running under NetworkService account" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Service Account"
                    Count = $networkServices.Count
                    Services = $networkServices | Select-Object Name, DisplayName
                }
        }

        # Check for services with weak recovery options
        $weakRecoveryServices = @()
        foreach ($service in $services) {
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
            $recoveryOptions = Get-ItemProperty -Path $servicePath -ErrorAction SilentlyContinue
            if ($recoveryOptions) {
                $actions = @(
                    $recoveryOptions.FailureActions,
                    $recoveryOptions.FirstFailureAction,
                    $recoveryOptions.SecondFailureAction,
                    $recoveryOptions.ThirdFailureAction
                )
                if ($actions -contains 1) { # 1 = Restart
                    $weakRecoveryServices += @{
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        RecoveryActions = $actions
                    }
                }
            }
        }

        if ($weakRecoveryServices.Count -gt 0) {
            Add-Finding -TestResult $result -FindingName "Weak Recovery Options" -Status "Warning" `
                -Description "Found $($weakRecoveryServices.Count) services with potentially weak recovery options" -RiskLevel "Medium" `
                -AdditionalInfo @{
                    Component = "Services"
                    Setting = "Recovery Options"
                    Count = $weakRecoveryServices.Count
                    Services = $weakRecoveryServices
                    Recommendation = "Review and restrict service recovery options to prevent potential security issues"
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
            -Description "Error during Windows services analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-WindowsServices 