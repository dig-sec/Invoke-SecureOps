# -----------------------------------------------------------------------------
# Operating System End-of-Life Check
# -----------------------------------------------------------------------------

function Test-OS_EOL {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath = ".\os_eol.json",
        
        [Parameter()]
        [switch]$PrettyOutput
    )

    # Initialize test result
    $testResult = @{
        TestName = "Test-OS_EOL"
        Category = "System"
        Description = "Checks if the operating system is approaching or past end-of-life"
        Status = "Info"
        Findings = @()
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $osVersion = $os.Version
        $osCaption = $os.Caption

        # Check Windows version
        switch -Regex ($osVersion) {
            "^10\.0" {
                Add-Finding -CheckName "OS End-of-Life" -Status "Pass" -Details "Windows 10/11 detected - Currently supported"
            }
            "^6\.3" {
                Add-Finding -CheckName "OS End-of-Life" -Status "Warning" -Details "Windows 8.1/Server 2012 R2 detected - Consider upgrading to Windows 10/11"
            }
            "^6\.2" {
                Add-Finding -CheckName "OS End-of-Life" -Status "Warning" -Details "Windows 8/Server 2012 detected - Consider upgrading to Windows 10/11"
            }
            "^6\.1" {
                Add-Finding -CheckName "OS End-of-Life" -Status "Fail" -Details "Windows 7/Server 2008 R2 detected - End of support reached"
            }
            "^6\.0" {
                Add-Finding -CheckName "OS End-of-Life" -Status "Fail" -Details "Windows Vista/Server 2008 detected - End of support reached"
            }
            "^5\.2" {
                Add-Finding -CheckName "OS End-of-Life" -Status "Fail" -Details "Windows Server 2003 detected - End of support reached"
            }
            default {
                Add-Finding -CheckName "OS End-of-Life" -Status "Warning" -Details "Unknown Windows version detected: $osCaption"
            }
        }
    }
    catch {
        Write-Error "Error checking OS version: $_"
        Add-Finding -CheckName "OS End-of-Life" -Status "Error" -Details "Failed to check OS version: $_"
    }
}

Export-ModuleMember -Function Test-OS_EOL 