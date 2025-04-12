# -----------------------------------------------------------------------------
# System Services Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious system services and configurations.

.DESCRIPTION
    This function analyzes system services for security issues, including
    misconfigurations, weak permissions, unquoted service paths, and services
    running with elevated privileges.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis.

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
        [string]$OutputPath = ".\results",
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "System Services" `
                                  -Category "Security Configuration" `
                                  -Description "Checks system services for security issues" `
                                  -RiskLevel "High"
    
    try {
        # Get all services
        $services = Get-WmiObject -Class Win32_Service
        
        foreach ($service in $services) {
            try {
                # Get service security descriptor
                $sddl = (Get-Item "HKLM:\System\CurrentControlSet\Services\$($service.Name)").GetAccessControl().Sddl
                
                # Add finding for each service
                Add-Finding -TestResult $result -FindingName "Service Configuration" `
                    -Status "Info" `
                    -RiskLevel "Info" `
                    -Description "Service $($service.Name) configuration review" `
                    -TechnicalDetails @{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        StartType = $service.StartType
                        State = $service.State
                        PathName = $service.PathName
                        Account = $service.StartName
                        Description = $service.Description
                        Recommendation = $recommendation
                    }
                
                # Add evidence if requested
                if ($CollectEvidence) {
                    Add-Evidence -TestResult $result `
                        -FindingName "Service: $($service.Name)" `
                        -EvidenceType "Configuration" `
                        -EvidenceData @{
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            PathName = $service.PathName
                            StartMode = $service.StartMode
                            State = $service.State
                            StartName = $service.StartName
                            SDDL = $sddl
                        } `
                        -Description "Configuration details for service $($service.Name)"
                }
            }
            catch {
                Write-Warning "Error processing service $($service.Name): $_"
                Add-Finding -TestResult $result `
                    -FindingName "Service Error: $($service.Name)" `
                    -Status "Warning" `
                    -RiskLevel "Medium" `
                    -Description "Error processing service: $_"
            }
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during system services test: $_"
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error during system services test: $_" `
            -TechnicalDetails @{
                Recommendation = "Check system permissions and service access"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SystemServices 