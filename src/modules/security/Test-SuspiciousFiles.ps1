# -----------------------------------------------------------------------------
# Suspicious File Detection Module
# -----------------------------------------------------------------------------

function Test-SuspiciousFiles {
    param (
        [string]$OutputPath = ".\suspicious_files.json"
    )

    Write-SectionHeader "Suspicious File Analysis"
    Write-Output "Analyzing files for suspicious patterns..."

    # Initialize results object
    $results = @{
        SuspiciousActivities = @()
        TotalChecks = 0
        PassedChecks = 0
        FailedChecks = 0
        WarningChecks = 0
    }

    try {
        # Define suspicious file patterns
        $suspiciousPatterns = @(
            @{
                Name = "mimikatz"
                Description = "Credential dumping tool"
                RiskLevel = "Critical"
            },
            @{
                Name = "procdump"
                Description = "Process dumping tool"
                RiskLevel = "High"
            },
            @{
                Name = "wireshark"
                Description = "Network capture tool"
                RiskLevel = "Medium"
            },
            @{
                Name = "psexec"
                Description = "Remote execution tool"
                RiskLevel = "High"
            },
            @{
                Name = "netcat"
                Description = "Network utility tool"
                RiskLevel = "Medium"
            }
        )

        # Search in common locations
        $searchPaths = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:APPDATA",
            "$env:LOCALAPPDATA",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Desktop"
        )

        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                foreach ($pattern in $suspiciousPatterns) {
                    $files = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "*$($pattern.Name)*" }
                    
                    $results.TotalChecks++
                    
                    if ($files) {
                        foreach ($file in $files) {
                            $fileInfo = @{
                                Type = "SuspiciousFile"
                                Name = $file.Name
                                Path = $file.FullName
                                Description = $pattern.Description
                                RiskLevel = $pattern.RiskLevel
                                Size = $file.Length
                                LastModified = $file.LastWriteTime
                            }

                            try {
                                $fileInfo.Hash = (Get-FileHash -Path $file.FullName -ErrorAction Stop).Hash
                            }
                            catch {
                                $fileInfo.Hash = "Unknown"
                            }

                            try {
                                $fileInfo.Owner = (Get-Acl -Path $file.FullName -ErrorAction Stop).Owner
                            }
                            catch {
                                $fileInfo.Owner = "Unknown"
                            }

                            $results.SuspiciousActivities += $fileInfo
                            $results.WarningChecks++
                        }
                    }
                    else {
                        $results.PassedChecks++
                    }
                }
            }
        }

        # Check for recently modified files
        $recentFiles = Get-ChildItem -Path $searchPaths -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
        
        foreach ($file in $recentFiles) {
            $results.SuspiciousActivities += @{
                Type = "RecentlyModifiedFile"
                Name = $file.Name
                Path = $file.FullName
                Description = "File modified in the last 7 days"
                RiskLevel = "Medium"
                Size = $file.Length
                LastModified = $file.LastWriteTime
            }
            $results.WarningChecks++
        }

        # Add finding based on suspicious files
        if ($results.SuspiciousActivities.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Files" -Status "Warning" `
                -Details "Found $($results.SuspiciousActivities.Count) suspicious files" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    SuspiciousActivities = $results.SuspiciousActivities
                    TotalChecks = $results.TotalChecks
                    PassedChecks = $results.PassedChecks
                    FailedChecks = $results.FailedChecks
                    WarningChecks = $results.WarningChecks
                }
        }
        else {
            Add-Finding -CheckName "File Analysis" -Status "Pass" `
                -Details "No suspicious files found" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    TotalChecks = $results.TotalChecks
                    PassedChecks = $results.PassedChecks
                    FailedChecks = $results.FailedChecks
                    WarningChecks = $results.WarningChecks
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Suspicious File Analysis"
        Add-Finding -CheckName "File Analysis" -Status "Fail" `
            -Details "Failed to analyze files: $($_.Exception.Message)" -Category "ThreatHunting" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $results -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $results
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousFiles 