# -----------------------------------------------------------------------------
# Dependencies Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for required dependencies and their versions.

.DESCRIPTION
    This function analyzes the system for required dependencies and their versions,
    ensuring that all necessary components are available and up-to-date.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of dependencies.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-Dependencies -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-Dependencies {
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
    $result = Initialize-JsonOutput -Category "Core" -RiskLevel "Info"
    $result.TestName = "Test-Dependencies"
    $result.Description = "Analyzes system dependencies and their versions"

    try {
        # Define required dependencies
        $requiredDependencies = @(
            @{
                Name = "PowerShell"
                MinVersion = "5.1"
                CheckScript = { $PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1 }
                GetVersion = { "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" }
            },
            @{
                Name = "Windows Management Framework"
                MinVersion = "5.1"
                CheckScript = { $PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1 }
                GetVersion = { "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" }
            },
            @{
                Name = ".NET Framework"
                MinVersion = "4.7.2"
                CheckScript = { 
                    $dotNetVersions = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse |
                        Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -match "^(?!S)\p{L}*\d" } |
                        Select-Object -ExpandProperty Version
                    ($dotNetVersions | ForEach-Object {
                        $version = [version]$_
                        $version.Major -ge 4 -and $version.Minor -ge 7 -and $version.Build -ge 2
                    } | Where-Object { $_ -eq $true } | Measure-Object).Count -gt 0
                }
                GetVersion = { 
                    $dotNetVersions = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse |
                        Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSChildName -match "^(?!S)\p{L}*\d" } |
                        Select-Object -ExpandProperty Version
                    $dotNetVersions | Sort-Object -Descending | Select-Object -First 1
                }
            }
        )

        # Check each dependency
        foreach ($dependency in $requiredDependencies) {
            $isInstalled = & $dependency.CheckScript
            $version = & $dependency.GetVersion
            
            if ($isInstalled) {
                Add-Finding -TestResult $result -FindingName "Dependency: $($dependency.Name)" -Status "Pass" `
                    -Description "$($dependency.Name) version $version is installed" -RiskLevel "Info" `
                    -AdditionalInfo @{
                        Component = "Dependencies"
                        Dependency = $dependency.Name
                        Version = $version
                        MinVersion = $dependency.MinVersion
                    }
            } else {
                Add-Finding -TestResult $result -FindingName "Dependency: $($dependency.Name)" -Status "Warning" `
                    -Description "$($dependency.Name) version $($dependency.MinVersion) or higher is required" -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "Dependencies"
                        Dependency = $dependency.Name
                        CurrentVersion = $version
                        MinVersion = $dependency.MinVersion
                        Recommendation = "Install or upgrade $($dependency.Name) to version $($dependency.MinVersion) or higher"
                    }
            }
        }

        # Check for optional dependencies
        $optionalDependencies = @(
            @{
                Name = "Windows Defender"
                CheckScript = { Get-MpComputerStatus -ErrorAction SilentlyContinue }
                GetVersion = { (Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureAge }
            },
            @{
                Name = "Windows Firewall"
                CheckScript = { Get-NetFirewallProfile -ErrorAction SilentlyContinue }
                GetVersion = { "N/A" }
            }
        )

        foreach ($dependency in $optionalDependencies) {
            $isInstalled = & $dependency.CheckScript
            $version = & $dependency.GetVersion
            
            if ($isInstalled) {
                Add-Finding -TestResult $result -FindingName "Optional Dependency: $($dependency.Name)" -Status "Info" `
                    -Description "$($dependency.Name) is available" -RiskLevel "Info" `
                    -AdditionalInfo @{
                        Component = "Dependencies"
                        Dependency = $dependency.Name
                        Version = $version
                        Type = "Optional"
                    }
            } else {
                Add-Finding -TestResult $result -FindingName "Optional Dependency: $($dependency.Name)" -Status "Info" `
                    -Description "$($dependency.Name) is not available" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Dependencies"
                        Dependency = $dependency.Name
                        Type = "Optional"
                        Recommendation = "Consider installing $($dependency.Name) for enhanced security"
                    }
            }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            $json = $result | ConvertTo-Json -Depth 10
            if ($PrettyOutput) {
                $json = $json | ConvertFrom-Json | ConvertTo-Json -Depth 10
            }
            $json | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
            Write-Host "Test result exported to $OutputPath"
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during dependencies analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            $json = $result | ConvertTo-Json -Depth 10
            if ($PrettyOutput) {
                $json = $json | ConvertFrom-Json | ConvertTo-Json -Depth 10
            }
            $json | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
            Write-Host "Test result exported to $OutputPath"
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-Dependencies 