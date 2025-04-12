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
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-SystemServices" -Category "Security" -Description "Analyzes system services for security issues"
    
    try {
        # Get all services
        $services = Get-WmiObject -Class Win32_Service
        
        foreach ($service in $services) {
            # Check for unquoted service paths
            if ($service.PathName -and 
                $service.PathName -notlike '"*"' -and 
                $service.PathName -like "* *") {
                
                Add-Finding -TestResult $result -FindingName "Unquoted Service Path" `
                    -Status "Warning" -RiskLevel "High" `
                    -Description "Service '$($service.Name)' has unquoted path: $($service.PathName)" `
                    -AdditionalInfo @{
                        Component = "SystemServices"
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        PathName = $service.PathName
                        StartMode = $service.StartMode
                        State = $service.State
                        Recommendation = "Add quotes around the service path"
                    }
            }
            
            # Check for services running as SYSTEM
            if ($service.StartName -eq "LocalSystem") {
                Add-Finding -TestResult $result -FindingName "High Privilege Service" `
                    -Status "Info" -RiskLevel "Medium" `
                    -Description "Service '$($service.Name)' runs with SYSTEM privileges" `
                    -AdditionalInfo @{
                        Component = "SystemServices"
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        Account = $service.StartName
                        PathName = $service.PathName
                        StartMode = $service.StartMode
                        State = $service.State
                        Recommendation = "Verify if SYSTEM privileges are required"
                    }
            }
            
            # Check service executable path
            if ($service.PathName) {
                $execPath = $service.PathName.Split('"')[1]
                if (-not $execPath) {
                    $execPath = $service.PathName.Split(' ')[0]
                }
                
                if (Test-Path $execPath) {
                    # Check file signature
                    $signature = Get-AuthenticodeSignature -FilePath $execPath -ErrorAction SilentlyContinue
                    
                    if (-not $signature.Status -eq 'Valid') {
                        Add-Finding -TestResult $result -FindingName "Unsigned Service Binary" `
                            -Status "Warning" -RiskLevel "High" `
                            -Description "Service '$($service.Name)' uses unsigned executable: $execPath" `
                            -AdditionalInfo @{
                                Component = "SystemServices"
                                ServiceName = $service.Name
                                DisplayName = $service.DisplayName
                                ExecutablePath = $execPath
                                SignatureStatus = $signature.Status
                                StartMode = $service.StartMode
                                State = $service.State
                                Recommendation = "Verify service binary authenticity"
                            }
                    }
                    
                    # Check file permissions
                    $acl = Get-Acl -Path $execPath -ErrorAction SilentlyContinue
                    $weakPermissions = $acl.Access | Where-Object {
                        $_.FileSystemRights -match "FullControl|Modify|Write" -and
                        $_.IdentityReference -notmatch "NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators"
                    }
                    
                    if ($weakPermissions) {
                        Add-Finding -TestResult $result -FindingName "Weak Service Binary Permissions" `
                            -Status "Warning" -RiskLevel "High" `
                            -Description "Service '$($service.Name)' binary has weak permissions" `
                            -AdditionalInfo @{
                                Component = "SystemServices"
                                ServiceName = $service.Name
                                DisplayName = $service.DisplayName
                                ExecutablePath = $execPath
                                WeakPermissions = $weakPermissions | ForEach-Object {
                                    @{
                                        Identity = $_.IdentityReference.Value
                                        Rights = $_.FileSystemRights.ToString()
                                    }
                                }
                                Recommendation = "Review and restrict file permissions"
                            }
                    }
                }
                else {
                    Add-Finding -TestResult $result -FindingName "Missing Service Binary" `
                        -Status "Warning" -RiskLevel "High" `
                        -Description "Service '$($service.Name)' executable not found: $execPath" `
                        -AdditionalInfo @{
                            Component = "SystemServices"
                            ServiceName = $service.Name
                            DisplayName = $service.DisplayName
                            ExecutablePath = $execPath
                            StartMode = $service.StartMode
                            State = $service.State
                            Recommendation = "Verify service configuration and binary location"
                        }
                }
            }
            
            # Check service permissions
            $sddl = $service.GetSecurityDescriptor().Descriptor.SDDL
            if ($sddl -match "A;.*;WD") {
                Add-Finding -TestResult $result -FindingName "Weak Service Permissions" `
                    -Status "Warning" -RiskLevel "High" `
                    -Description "Service '$($service.Name)' has weak DACL permissions" `
                    -AdditionalInfo @{
                        Component = "SystemServices"
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        SDDL = $sddl
                        StartMode = $service.StartMode
                        State = $service.State
                        Recommendation = "Review and restrict service permissions"
                    }
                }
            }
            
            if ($CollectEvidence) {
                Add-Evidence -TestResult $result `
                    -FindingName "Service Configuration" `
                    -EvidenceType "ServiceConfig" `
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
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during system services test: $_"
        Add-Finding -TestResult $result -Name "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "An error occurred while checking system services: $_" `
            -Recommendation "Check system permissions and service access"
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SystemServices 