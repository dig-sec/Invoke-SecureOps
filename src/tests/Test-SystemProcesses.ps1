# -----------------------------------------------------------------------------
# System Processes Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious system processes and behaviors.

.DESCRIPTION
    This function analyzes running system processes for suspicious characteristics,
    including high resource usage, unusual paths, unsigned executables, and known
    malicious process names or behaviors.

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
    Test-SystemProcesses -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-SystemProcesses {
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
    $result = Initialize-TestResult -TestName "Test-SystemProcesses" -Category "Security" -Description "Analyzes running system processes for suspicious behavior"
    
    try {
        # Get all running processes
        $processes = Get-Process | Where-Object { $_.Path -ne $null }
        
        # Define suspicious process characteristics
        $suspiciousCharacteristics = @(
            @{
                Check = { param($proc) $proc.CPU -gt 80 }
                Description = "High CPU Usage"
                RiskLevel = "Medium"
            },
            @{
                Check = { param($proc) $proc.WorkingSet64 / 1MB -gt 1000 }
                Description = "High Memory Usage"
                RiskLevel = "Medium"
            },
            @{
                Check = { param($proc) $proc.Path -match "\\temp\\|\\downloads\\" }
                Description = "Running from Temporary Location"
                RiskLevel = "High"
            },
            @{
                Check = { param($proc) -not (Get-AuthenticodeSignature $proc.Path).Status -eq 'Valid' }
                Description = "Unsigned Executable"
                RiskLevel = "High"
            }
        )
        
        # Define known suspicious process names
        $suspiciousNames = @(
            @{
                Name = "mimikatz"
                Description = "Known Password Dumping Tool"
                RiskLevel = "Critical"
            },
            @{
                Name = "psexec"
                Description = "Remote Administration Tool"
                RiskLevel = "High"
            },
            @{
                Name = "netcat|nc\."
                Description = "Network Utility Tool"
                RiskLevel = "High"
            },
            @{
                Name = "powershell_empire|empire"
                Description = "Post-Exploitation Framework"
                RiskLevel = "Critical"
            }
        )
        
        foreach ($process in $processes) {
            try {
                # Check for suspicious process names
                foreach ($suspicious in $suspiciousNames) {
                    if ($process.ProcessName -match $suspicious.Name) {
                        Add-Finding -TestResult $result -Name "Suspicious Process Name" `
                            -Status "Warning" -RiskLevel $suspicious.RiskLevel `
                            -Description "Found process with suspicious name: $($process.ProcessName)" `
                            -AdditionalInfo @{
                                Component = "SystemProcesses"
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                Path = $process.Path
                                StartTime = $process.StartTime
                                Description = $suspicious.Description
                                Recommendation = "Investigate this process and terminate if unauthorized"
                            }
                    }
                }
                
                # Check process characteristics
                foreach ($characteristic in $suspiciousCharacteristics) {
                    if (& $characteristic.Check $process) {
                        Add-Finding -TestResult $result -Name "Suspicious Process Behavior" `
                            -Status "Warning" -RiskLevel $characteristic.RiskLevel `
                            -Description "$($characteristic.Description): $($process.ProcessName)" `
                            -AdditionalInfo @{
                                Component = "SystemProcesses"
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                Path = $process.Path
                                CPU = $process.CPU
                                Memory = [math]::Round($process.WorkingSet64 / 1MB, 2)
                                StartTime = $process.StartTime
                                Description = $characteristic.Description
                                Recommendation = "Review process behavior and resource usage"
                            }
                    }
                }
                
                # Check process modules and loaded DLLs
                if ($DetailedAnalysis) {
                    $modules = $process.Modules | ForEach-Object {
                        try {
                            $signature = Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue
                            
                            if (-not $signature.Status -eq 'Valid') {
                                Add-Finding -TestResult $result -Name "Unsigned Process Module" `
                                    -Status "Warning" -RiskLevel "High" `
                                    -Description "Found unsigned module in process: $($process.ProcessName)" `
                                    -AdditionalInfo @{
                                        Component = "SystemProcesses"
                                        ProcessName = $process.ProcessName
                                        ProcessId = $process.Id
                                        ModuleName = $_.ModuleName
                                        ModulePath = $_.FileName
                                        SignatureStatus = $signature.Status
                                        Recommendation = "Verify this module is authorized"
                                    }
                            }
                            
                            @{
                                ModuleName = $_.ModuleName
                                FileName = $_.FileName
                                FileVersion = $_.FileVersion
                                Size = $_.Size
                                Company = $_.Company
                                Description = $_.Description
                                Signed = $signature.Status -eq 'Valid'
                                SignatureStatus = $signature.Status
                            }
                        }
                        catch {
                            Write-Warning "Error processing module $($_.ModuleName): $_"
                            $null
                        }
                    } | Where-Object { $_ -ne $null }
                    
                    if ($CollectEvidence) {
                        Add-Evidence -TestResult $result `
                            -FindingName "Process Modules" `
                            -EvidenceType "ProcessModules" `
                            -EvidenceData @{
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                Modules = $modules
                            } `
                            -Description "Loaded modules for process $($process.ProcessName)"
                    }
                }
            }
            catch {
                Write-Warning "Error processing process $($process.ProcessName): $_"
            }
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during system processes test: $_"
        Add-Finding -TestResult $result -Name "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "An error occurred while checking system processes: $_" `
            -Recommendation "Check system permissions and process access"
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SystemProcesses 