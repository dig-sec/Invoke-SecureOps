# -----------------------------------------------------------------------------
# Directory Permissions Analysis Module
# -----------------------------------------------------------------------------

function Test-DirectoryPermissions {
    [CmdletBinding()]
    param (
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

    Write-SectionHeader "Directory Permissions Check"
    Write-Output "Analyzing directory permissions..."

    # Initialize test result using helper function
    $testResult = Initialize-TestResult -TestName "Directory Permissions" `
                                     -Category "Security Configuration" `
                                     -Description "Checks critical directories for secure permissions" `
                                     -RiskLevel "High"
    
    try {
        # Define critical directories to check
        $criticalDirs = @(
            "C:\Windows\System32",
            "C:\Windows\System32\config",
            "C:\Program Files",
            "C:\Program Files (x86)",
            "C:\Users",
            "C:\ProgramData"
        )

        foreach ($dir in $criticalDirs) {
            if (Test-Path $dir) {
                $acl = Get-Acl $dir
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
                $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                
                # Check if current user has admin rights
                $isAdmin = $principal.IsInRole($adminRole)
                
                # Analyze ACL
                $hasInsecurePermissions = $false
                $insecureUsers = @()
                
                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference.Value -notmatch "^(NT AUTHORITY|BUILTIN|S-1-5-32)") {
                        $hasInsecurePermissions = $true
                        $insecureUsers += $access.IdentityReference.Value
                    }
                }
                
                if ($hasInsecurePermissions) {
                    $testResult = Add-Finding -TestResult $testResult `
                                           -FindingName "Insecure Directory Permissions" `
                                           -Status "Warning" `
                                           -RiskLevel "Medium" `
                                           -Description "Directory $dir has potentially insecure permissions" `
                                           -Recommendation "Review and restrict permissions to trusted users/groups only" `
                                           -TechnicalDetails @{
                                               Directory = $dir
                                               InsecureUsers = $insecureUsers
                                               CurrentUserIsAdmin = $isAdmin
                                           }
                }
                
                if ($CollectEvidence) {
                    $testResult = Add-Evidence -TestResult $testResult `
                                            -FindingName "Directory Permissions Evidence" `
                                            -EvidenceType "Configuration" `
                                            -EvidenceData $acl `
                                            -Description "ACL information for $dir"
                }
            }
        }
        
        return $testResult
    }
    catch {
        Write-Error "Error during directory permissions test: $_"
        $testResult = Add-Finding -TestResult $testResult `
                                -FindingName "Test Error" `
                                -Status "Error" `
                                -RiskLevel "High" `
                                -Description "Error occurred during directory permissions test" `
                                -TechnicalDetails @{
                                    Error = $_.Exception.Message
                                    StackTrace = $_.ScriptStackTrace
                                }
        return $testResult
    }
}

# Export the function
Export-ModuleMember -Function Test-DirectoryPermissions 