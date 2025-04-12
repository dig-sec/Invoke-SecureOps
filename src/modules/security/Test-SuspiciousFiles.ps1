# -----------------------------------------------------------------------------
# Suspicious Files Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious files and executables.

.DESCRIPTION
    This function analyzes the system for suspicious files, executables, and scripts
    that may indicate malware, unauthorized software, or security risks.

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
        [hashtable]$CustomComparators
    )

    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-SuspiciousFiles" -Category "Security" -Description "Analysis of suspicious files and executables"

    try {
        # Define suspicious file patterns to check
        $suspiciousPatterns = @(
            @{
                Pattern = "*.exe"
                Description = "Executable Files"
                RiskLevel = "Medium"
            },
            @{
                Pattern = "*.dll"
                Description = "Dynamic Link Libraries"
                RiskLevel = "Medium"
            },
            @{
                Pattern = "*.ps1"
                Description = "PowerShell Scripts"
                RiskLevel = "High"
            },
            @{
                Pattern = "*.vbs"
                Description = "VBScript Files"
                RiskLevel = "High"
            },
            @{
                Pattern = "*.bat"
                Description = "Batch Files"
                RiskLevel = "Medium"
            },
            @{
                Pattern = "*.cmd"
                Description = "Command Files"
                RiskLevel = "Medium"
            }
        )

        # Define suspicious file locations to check
        $suspiciousLocations = @(
            @{
                Path = "$env:USERPROFILE\Downloads"
                Description = "Downloads Folder"
                RiskLevel = "Medium"
            },
            @{
                Path = "$env:USERPROFILE\Desktop"
                Description = "Desktop Folder"
                RiskLevel = "Medium"
            },
            @{
                Path = "$env:ProgramData"
                Description = "Program Data Folder"
                RiskLevel = "High"
            },
            @{
                Path = "$env:APPDATA"
                Description = "AppData Folder"
                RiskLevel = "High"
            },
            @{
                Path = "$env:LOCALAPPDATA"
                Description = "Local AppData Folder"
                RiskLevel = "High"
            }
        )

        # Check each suspicious location for suspicious file patterns
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location.Path) {
                foreach ($pattern in $suspiciousPatterns) {
                    $suspiciousFiles = Get-ChildItem -Path $location.Path -Filter $pattern.Pattern -Recurse -ErrorAction SilentlyContinue
                    
                    if ($suspiciousFiles) {
                        $fileDetails = $suspiciousFiles | ForEach-Object {
                            @{
                                Name = $_.Name
                                FullPath = $_.FullName
                                Size = $_.Length
                                CreationTime = $_.CreationTime
                                LastWriteTime = $_.LastWriteTime
                                LastAccessTime = $_.LastAccessTime
                                Attributes = $_.Attributes
                            }
                        }

                        Add-Finding -TestResult $result -FindingName "Suspicious Files: $($pattern.Description) in $($location.Description)" -Status "Warning" `
                            -Description "Found $($suspiciousFiles.Count) $($pattern.Description) in $($location.Path)" -RiskLevel $pattern.RiskLevel `
                            -AdditionalInfo @{
                                Component = "Files"
                                Location = $location.Path
                                Description = $location.Description
                                Pattern = $pattern.Pattern
                                FileType = $pattern.Description
                                FileCount = $suspiciousFiles.Count
                                Files = $fileDetails
                                Recommendation = "Review these files for potential security risks"
                            }
                    }
                }
            }
        }

        # Check for files with suspicious names
        $suspiciousNames = @(
            @{
                Name = "password"
                Description = "Password Files"
                RiskLevel = "High"
            },
            @{
                Name = "credential"
                Description = "Credential Files"
                RiskLevel = "High"
            },
            @{
                Name = "backup"
                Description = "Backup Files"
                RiskLevel = "Medium"
            },
            @{
                Name = "temp"
                Description = "Temporary Files"
                RiskLevel = "Medium"
            }
        )

        foreach ($name in $suspiciousNames) {
            $suspiciousFiles = Get-ChildItem -Path $env:USERPROFILE -Filter "*$($name.Name)*" -Recurse -ErrorAction SilentlyContinue
            
            if ($suspiciousFiles) {
                $fileDetails = $suspiciousFiles | ForEach-Object {
                    @{
                        Name = $_.Name
                        FullPath = $_.FullName
                        Size = $_.Length
                        CreationTime = $_.CreationTime
                        LastWriteTime = $_.LastWriteTime
                        LastAccessTime = $_.LastAccessTime
                        Attributes = $_.Attributes
                    }
                }

                Add-Finding -TestResult $result -FindingName "Suspicious File Names: $($name.Description)" -Status "Warning" `
                    -Description "Found $($suspiciousFiles.Count) files with '$($name.Name)' in the name" -RiskLevel $name.RiskLevel `
                    -AdditionalInfo @{
                        Component = "Files"
                        Pattern = $name.Name
                        Description = $name.Description
                        FileCount = $suspiciousFiles.Count
                        Files = $fileDetails
                        Recommendation = "Review these files for sensitive information"
                    }
            }
        }

        # Check for files with suspicious attributes
        $suspiciousAttributes = @(
            @{
                Attribute = "Hidden"
                Description = "Hidden Files"
                RiskLevel = "Medium"
            },
            @{
                Attribute = "System"
                Description = "System Files"
                RiskLevel = "Medium"
            }
        )

        foreach ($attr in $suspiciousAttributes) {
            $suspiciousFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.Attributes -match $attr.Attribute }
            
            if ($suspiciousFiles) {
                $fileDetails = $suspiciousFiles | ForEach-Object {
                    @{
                        Name = $_.Name
                        FullPath = $_.FullName
                        Size = $_.Length
                        CreationTime = $_.CreationTime
                        LastWriteTime = $_.LastWriteTime
                        LastAccessTime = $_.LastAccessTime
                        Attributes = $_.Attributes
                    }
                }

                Add-Finding -TestResult $result -FindingName "Suspicious File Attributes: $($attr.Description)" -Status "Warning" `
                    -Description "Found $($suspiciousFiles.Count) files with $($attr.Attribute) attribute" -RiskLevel $attr.RiskLevel `
                    -AdditionalInfo @{
                        Component = "Files"
                        Attribute = $attr.Attribute
                        Description = $attr.Description
                        FileCount = $suspiciousFiles.Count
                        Files = $fileDetails
                        Recommendation = "Review these files for potential security risks"
                    }
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
            -Description "Error during file analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousFiles 