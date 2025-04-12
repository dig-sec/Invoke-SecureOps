# -----------------------------------------------------------------------------
# Suspicious Files Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious files and executables.

.DESCRIPTION
    This function analyzes the system for suspicious files, including
    unknown executables, hidden files, and files with suspicious names or locations.

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

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-SuspiciousFiles -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-SuspiciousFiles {
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
        [switch]$CollectEvidence
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-SuspiciousFiles" `
                                  -Category "Security" `
                                  -Description "Analyzes system for suspicious files" `
                                  -Status "Info" `
                                  -RiskLevel "Info"
    
    try {
        # Define suspicious file patterns
        $suspiciousPatterns = @(
            "*.exe",
            "*.dll",
            "*.bat",
            "*.ps1",
            "*.vbs",
            "*.js",
            "*.wsf"
        )
        
        # Define suspicious locations
        $suspiciousLocations = @(
            "$env:ProgramData",
            "$env:APPDATA",
            "$env:LOCALAPPDATA",
            "$env:TEMP",
            "$env:SystemRoot\Temp"
        )
        
        # Search for suspicious files
        foreach ($location in $suspiciousLocations) {
            foreach ($pattern in $suspiciousPatterns) {
                $files = Get-ChildItem -Path $location -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue
                
                foreach ($file in $files) {
                    # Skip system files and known good executables
                    if ($file.FullName -match "Windows|Program Files|Program Files \(x86\)") {
                        continue
                    }
                    
                    # Check file properties
                    $fileInfo = Get-Item $file.FullName -Force
                    $isHidden = $fileInfo.Attributes -band [System.IO.FileAttributes]::Hidden
                    $isSystem = $fileInfo.Attributes -band [System.IO.FileAttributes]::System
                    
                    Add-Finding -TestResult $result `
                        -FindingName "Suspicious File" `
                        -Status "Warning" `
                        -RiskLevel "Medium" `
                        -Description "Found suspicious file: $($file.FullName)" `
                        -TechnicalDetails @{
                            FileName = $file.Name
                            FullPath = $file.FullName
                            Size = $file.Length
                            CreationTime = $file.CreationTime
                            LastWriteTime = $file.LastWriteTime
                            IsHidden = $isHidden
                            IsSystem = $isSystem
                            FileHash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                            Recommendation = "Review this file and verify its purpose"
                        }
                    
                    if ($CollectEvidence) {
                        Add-Evidence -TestResult $result `
                            -FindingName "Suspicious File" `
                            -EvidenceType "File" `
                            -EvidenceData @{
                                FileName = $file.Name
                                FullPath = $file.FullName
                                Size = $file.Length
                                CreationTime = $file.CreationTime
                                LastWriteTime = $file.LastWriteTime
                                IsHidden = $isHidden
                                IsSystem = $isSystem
                                FileHash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                            } `
                            -Description "Details of suspicious file"
                    }
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
        Write-Error "Error during suspicious files test: $_"
        Add-Finding -TestResult $result `
            -Name "Test Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error during suspicious files test: $_" `
            -TechnicalDetails @{
                Recommendation = "Check system permissions and file access"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousFiles 