# -----------------------------------------------------------------------------
# Operating System End-of-Life Check
# -----------------------------------------------------------------------------

function Test-OS_EOL {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath,
        
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
    $testResult = Initialize-JsonOutput -Category "System" -RiskLevel "High"

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $osVersion = $os.Version
        $osCaption = $os.Caption

        # Check Windows version
        switch -Regex ($osVersion) {
            "^10\.0" {
                Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Pass" -Description "Windows 10/11 detected - Currently supported"
            }
            "^6\.3" {
                Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Warning" -Description "Windows 8.1/Server 2012 R2 detected - Consider upgrading to Windows 10/11"
            }
            "^6\.2" {
                Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Warning" -Description "Windows 8/Server 2012 detected - Consider upgrading to Windows 10/11"
            }
            "^6\.1" {
                Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Fail" -Description "Windows 7/Server 2008 R2 detected - End of support reached"
            }
            "^6\.0" {
                Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Fail" -Description "Windows Vista/Server 2008 detected - End of support reached"
            }
            "^5\.2" {
                Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Fail" -Description "Windows Server 2003 detected - End of support reached"
            }
            default {
                Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Warning" -Description "Unknown Windows version detected: $osCaption"
            }
        }
    }
    catch {
        Write-Error "Error checking OS version: $_"
        Add-Finding -TestResult $testResult -FindingName "OS End-of-Life" -Status "Error" -Description "Failed to check OS version: $_"
    }
    
    # Export results if output path provided
    if ($OutputPath) {
        Export-JsonOutput -TestResult $testResult `
                         -OutputPath $OutputPath `
                         -PrettyOutput:$PrettyOutput
    }
    
    return $testResult
}

Export-ModuleMember -Function Test-OS_EOL 