# -----------------------------------------------------------------------------
# Directory Permissions Analysis Module
# -----------------------------------------------------------------------------

function Test-DirectoryPermissions {
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

    Write-SectionHeader "Directory Permissions Check"
    Write-Output "Analyzing directory permissions..."

    # Initialize test result using helper function
    $testResult = Initialize-JsonOutput -Category "DirectoryPermissions" -RiskLevel "High"
    
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
                
                $isWritable = $false
                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference.Value -eq $identity.Name -or 
                        $access.IdentityReference.Value -eq "BUILTIN\Users" -or 
                        $access.IdentityReference.Value -eq "Everyone") {
                        if ($access.FileSystemRights -match "Modify|FullControl|Write|WriteData|AppendData|ChangePermissions|TakeOwnership") {
                            $isWritable = $true
                            break
                        }
                    }
                }
                
                if ($isWritable) {
                    $testResult = Add-Finding -TestResult $testResult `
                        -FindingName "Directory Permission Check - $dir" `
                        -Status "Warning" `
                        -Description "Directory $dir is writable by non-administrators" `
                        -RiskLevel "High" `
                        -AdditionalInfo @{
                            Path = $dir
                            CurrentUser = $identity.Name
                            IsAdmin = $principal.IsInRole($adminRole)
                            ACL = $acl.Access | ForEach-Object {
                                @{
                                    Identity = $_.IdentityReference.Value
                                    Rights = $_.FileSystemRights
                                    Type = $_.AccessControlType
                                }
                            }
                        }
                }
                else {
                    $testResult = Add-Finding -TestResult $testResult `
                        -FindingName "Directory Permission Check - $dir" `
                        -Status "Pass" `
                        -Description "Directory $dir has appropriate permissions" `
                        -RiskLevel "Info" `
                        -AdditionalInfo @{
                            Path = $dir
                            CurrentUser = $identity.Name
                            IsAdmin = $principal.IsInRole($adminRole)
                        }
                }
            }
            else {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Directory Permission Check - $dir" `
                    -Status "Info" `
                    -Description "Directory $dir does not exist" `
                    -RiskLevel "Info" `
                    -AdditionalInfo @{
                        Path = $dir
                        Exists = $false
                    }
            }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Directory Permissions Analysis"
        $testResult = Add-Finding -TestResult $testResult `
            -FindingName "Directory Permissions Error" `
            -Status "Error" `
            -Description "Failed to check directory permissions: $($_.Exception.Message)" `
            -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    # Export results if output path provided
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-DirectoryPermissions 