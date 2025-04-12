# -----------------------------------------------------------------------------
# Directory Permissions Analysis Module
# -----------------------------------------------------------------------------

function Test-DirectoryPermissions {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath = ".\directory_permissions.json",
        
        [Parameter()]
        [switch]$PrettyOutput
    )

    Write-SectionHeader "Directory Permissions Check"
    Write-Output "Analyzing directory permissions..."

    # Initialize JSON output object using common function
    $dirSecurityInfo = Initialize-JsonOutput -Category "DirectoryPermissions" -RiskLevel "High" -ActionLevel "Review"
    $dirSecurityInfo.TotalChecked = 0
    $dirSecurityInfo.WritableCount = 0
    $dirSecurityInfo.Details = @()

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
        
        $dirSecurityInfo.TotalChecked = $criticalDirs.Count

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
                            $dirSecurityInfo.WritableCount++
                            break
                        }
                    }
                }
                
                $dirSecurityInfo.Details += @{
                    Path = $dir
                    IsWritable = $isWritable
                    ACL = $acl.Access | ForEach-Object {
                        @{
                            Identity = $_.IdentityReference.Value
                            Rights = $_.FileSystemRights
                            Type = $_.AccessControlType
                        }
                    }
                }
                
                if ($isWritable) {
                    Add-Finding -CheckName "Directory Permissions" -Status "Warning" `
                        -Details "Directory $dir is writable by non-administrators" -Category "DirectoryPermissions" `
                        -AdditionalInfo @{
                            Path = $dir
                            CurrentUser = $identity.Name
                            IsAdmin = $principal.IsInRole($adminRole)
                        }
                }
                else {
                    Add-Finding -CheckName "Directory Permissions" -Status "Pass" `
                        -Details "Directory $dir has appropriate permissions" -Category "DirectoryPermissions" `
                        -AdditionalInfo @{
                            Path = $dir
                            CurrentUser = $identity.Name
                            IsAdmin = $principal.IsInRole($adminRole)
                        }
                }
            }
            else {
                Add-Finding -CheckName "Directory Permissions" -Status "Info" `
                    -Details "Directory $dir does not exist" -Category "DirectoryPermissions" `
                    -AdditionalInfo @{
                        Path = $dir
                        Exists = $false
                    }
            }
        }

        # Add a summary finding
        if ($dirSecurityInfo.WritableCount -gt 0) {
            Add-Finding -CheckName "Directory Permissions Summary" -Status "Warning" `
                -Details "$($dirSecurityInfo.WritableCount) of $($dirSecurityInfo.TotalChecked) critical directories are writable." `
                -Category "DirectoryPermissions" `
                -AdditionalInfo @{
                    WritableCount = $dirSecurityInfo.WritableCount
                    TotalChecked = $dirSecurityInfo.TotalChecked
                    WritablePercentage = [math]::Round(($dirSecurityInfo.WritableCount / $dirSecurityInfo.TotalChecked) * 100, 2)
                }
        }
        else {
            Add-Finding -CheckName "Directory Permissions Summary" -Status "Pass" `
                -Details "All critical directories have appropriate permissions." `
                -Category "DirectoryPermissions" `
                -AdditionalInfo @{
                    WritableCount = $dirSecurityInfo.WritableCount
                    TotalChecked = $dirSecurityInfo.TotalChecked
                    WritablePercentage = 0
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Directory Permissions Analysis"
        Add-Finding -CheckName "Directory Permissions" -Status "Fail" `
            -Details "Failed to check directory permissions: $($_.Exception.Message)" -Category "DirectoryPermissions" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $dirSecurityInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $dirSecurityInfo
}

# Export the function
Export-ModuleMember -Function Test-DirectoryPermissions 