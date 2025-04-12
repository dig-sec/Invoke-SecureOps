# -----------------------------------------------------------------------------
# Suspicious Files Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious files and potentially malicious content.

.DESCRIPTION
    This function analyzes the system for suspicious files, including known malware patterns,
    unauthorized executables, scripts with potentially malicious content, and files in
    suspicious locations.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of files.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

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
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-JsonOutput -Category "Security" -RiskLevel "Info" -ActionLevel "Review"
    $result.Description = "Analyzes system for suspicious files and potentially malicious content"
    
    try {
        # Define suspicious file locations to check
        $suspiciousLocations = @(
            @{
                Path = "$env:TEMP"
                Description = "Temporary Directory"
                RiskLevel = "Medium"
                FileTypes = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.bat", "*.cmd")
            },
            @{
                Path = "$env:SystemRoot\Temp"
                Description = "System Temp Directory"
                RiskLevel = "High"
                FileTypes = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.bat", "*.cmd")
            },
            @{
                Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
                Description = "User Startup Directory"
                RiskLevel = "High"
                FileTypes = @("*.*")
            },
            @{
                Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
                Description = "Common Startup Directory"
                RiskLevel = "High"
                FileTypes = @("*.*")
            }
        )
        
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location.Path) {
                foreach ($fileType in $location.FileTypes) {
                    $files = Get-ChildItem -Path $location.Path -Filter $fileType -File -Recurse -ErrorAction SilentlyContinue
                    
                    if ($files) {
                        $fileDetails = $files | ForEach-Object {
                            $signature = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
                            
                            @{
                                Name = $_.Name
                                Path = $_.FullName
                                CreationTime = $_.CreationTime
                                LastWriteTime = $_.LastWriteTime
                                Size = $_.Length
                                Hash = (Get-FileHash -Path $_.FullName -ErrorAction SilentlyContinue).Hash
                                Signed = if ($signature) { $signature.Status -eq 'Valid' } else { $false }
                                SignatureStatus = if ($signature) { $signature.Status.ToString() } else { "Unsigned" }
                            }
                        }
                        
                        Add-Finding -TestResult $result -FindingName "$($location.Description) - $fileType Files" `
                            -Status "Warning" -RiskLevel $location.RiskLevel `
                            -Description "Found $($files.Count) $fileType files in $($location.Path)" `
                            -AdditionalInfo @{
                                Component = "FileSystem"
                                Location = $location.Path
                                FileType = $fileType
                                FileCount = $files.Count
                                Files = $fileDetails
                                Recommendation = "Review these files and verify they are authorized"
                            }
                        
                        if ($CollectEvidence) {
                            Add-Evidence -TestResult $result `
                                -FindingName "$($location.Description) - $fileType Files" `
                                -EvidenceType "FileSystem" `
                                -EvidenceData $fileDetails `
                                -Description "Files found in $($location.Path)"
                        }
                    }
                }
            }
            else {
                Add-Finding -TestResult $result -FindingName "$($location.Description) Access" `
                    -Status "Info" -RiskLevel "Low" `
                    -Description "Unable to access $($location.Path)" `
                    -AdditionalInfo @{
                        Recommendation = "Verify directory permissions and existence"
                    }
            }
        }
        
        # Check for files with suspicious characteristics
        $suspiciousPatterns = @(
            @{
                Pattern = "powershell.*bypass"
                Description = "PowerShell Execution Bypass"
                RiskLevel = "Critical"
            },
            @{
                Pattern = "net\.webclient"
                Description = "Network Download Code"
                RiskLevel = "High"
            },
            @{
                Pattern = "invoke-expression"
                Description = "Dynamic Code Execution"
                RiskLevel = "High"
            }
        )
        
        $scriptLocations = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Downloads",
            "$env:TEMP",
            "$env:SystemRoot\Temp"
        )
        
        foreach ($location in $scriptLocations) {
            if (Test-Path $location) {
                $scripts = Get-ChildItem -Path $location -Include @("*.ps1", "*.psm1", "*.psd1", "*.vbs", "*.bat", "*.cmd") -File -Recurse -ErrorAction SilentlyContinue
                
                foreach ($script in $scripts) {
                    $content = Get-Content -Path $script.FullName -Raw -ErrorAction SilentlyContinue
                    
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($content -match $pattern.Pattern) {
                            Add-Finding -TestResult $result -FindingName "Suspicious Script Content" `
                                -Status "Warning" -RiskLevel $pattern.RiskLevel `
                                -Description "Found $($pattern.Description) pattern in $($script.Name)" `
                                -AdditionalInfo @{
                                    Component = "FileSystem"
                                    File = $script.FullName
                                    Pattern = $pattern.Pattern
                                    PatternDescription = $pattern.Description
                                    CreationTime = $script.CreationTime
                                    LastWriteTime = $script.LastWriteTime
                                    Recommendation = "Review script content and verify it is authorized"
                                }
                            
                            if ($CollectEvidence) {
                                Add-Evidence -TestResult $result `
                                    -FindingName "Suspicious Script Content" `
                                    -EvidenceType "FileContent" `
                                    -EvidenceData @{
                                        File = $script.FullName
                                        Pattern = $pattern.Pattern
                                        Content = $content
                                    } `
                                    -Description "Suspicious content found in $($script.Name)"
                            }
                        }
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
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during suspicious files test: $_" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and file access"
            }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousFiles 