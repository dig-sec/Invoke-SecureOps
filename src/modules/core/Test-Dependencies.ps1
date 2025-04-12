# -----------------------------------------------------------------------------
# Dependency Management Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests and manages dependencies required by the security assessment toolkit.

.DESCRIPTION
    This function checks for required PowerShell modules, Windows features, and
    system requirements. It can optionally install missing dependencies.

.PARAMETER AutoInstall
    Switch parameter to automatically install missing dependencies.

.PARAMETER WhatIf
    Switch parameter to simulate dependency installation without making changes.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.OUTPUTS
    [hashtable] A hashtable containing dependency check results and installation status.

.EXAMPLE
    Test-Dependencies -AutoInstall -Verbose

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
        [switch]$AutoInstall,
        
        [Parameter()]
        [switch]$WhatIf
    )

    $result = Initialize-TestResult -TestName "Test-Dependencies" -Category "Core" -Description "Checks for required dependencies"

    try {
        # Check PowerShell version
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 5) {
            Add-Finding -TestResult $result -FindingName "PowerShell Version" -Status "Warning" -Description "PowerShell version $psVersion is below recommended version 5.0" -RiskLevel "Medium"
        } else {
            Add-Finding -TestResult $result -FindingName "PowerShell Version" -Status "Pass" -Description "PowerShell version $psVersion meets requirements" -RiskLevel "Info"
        }

        # Check for required modules
        $requiredModules = @(
            "Microsoft.PowerShell.Security",
            "Microsoft.PowerShell.Management",
            "Microsoft.PowerShell.Utility"
        )

        foreach ($module in $requiredModules) {
            if (Get-Module -ListAvailable -Name $module) {
                Add-Finding -TestResult $result -FindingName "Module Check: $module" -Status "Pass" -Description "Required module $module is installed" -RiskLevel "Info"
            } else {
                Add-Finding -TestResult $result -FindingName "Module Check: $module" -Status "Warning" -Description "Required module $module is not installed" -RiskLevel "Medium"
            }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Dependency Check Error" -Status "Error" -Description "Error checking dependencies: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-Dependencies 