# -----------------------------------------------------------------------------
# Suspicious Registry Detection Module
# -----------------------------------------------------------------------------

function Test-SuspiciousRegistry {
    param (
        [string]$OutputPath = ".\suspicious_registry.json"
    )

    Write-SectionHeader "Suspicious Registry Analysis"
    Write-Output "Analyzing registry for suspicious entries..."

    # Initialize results object
    $results = @{
        SuspiciousActivities = @()
        TotalChecks = 0
        PassedChecks = 0
        FailedChecks = 0
        WarningChecks = 0
    }

    try {
        # Define suspicious registry patterns
        $suspiciousPatterns = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Description = "Startup programs"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                Description = "One-time startup programs"
                RiskLevel = "High"
            },
            @{
                Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Description = "User startup programs"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services"
                Description = "System services"
                RiskLevel = "Critical"
            }
        )

        foreach ($pattern in $suspiciousPatterns) {
            if (Test-Path $pattern.Path) {
                $entries = Get-ItemProperty -Path $pattern.Path -ErrorAction SilentlyContinue
                $results.TotalChecks++

                if ($entries) {
                    foreach ($entry in $entries.PSObject.Properties) {
                        if ($entry.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                            $entryInfo = @{
                                Type = "SuspiciousRegistry"
                                Path = $pattern.Path
                                Name = $entry.Name
                                Value = $entry.Value
                                Description = $pattern.Description
                                RiskLevel = $pattern.RiskLevel
                            }

                            try {
                                $entryInfo.LastModified = (Get-ItemProperty -Path $pattern.Path -ErrorAction Stop).PSObject.Properties['LastWriteTime'].Value
                            }
                            catch {
                                $entryInfo.LastModified = "Unknown"
                            }

                            $results.SuspiciousActivities += $entryInfo
                            $results.WarningChecks++
                        }
                    }
                }
                else {
                    $results.PassedChecks++
                }
            }
        }

        # Check for suspicious registry values
        $suspiciousValues = @(
            @{
                Value = "cmd.exe /c"
                Description = "Command execution"
                RiskLevel = "High"
            },
            @{
                Value = "powershell.exe -enc"
                Description = "Encoded PowerShell command"
                RiskLevel = "Critical"
            },
            @{
                Value = "mshta.exe"
                Description = "HTML Application execution"
                RiskLevel = "High"
            }
        )

        foreach ($value in $suspiciousValues) {
            $matches = Get-ChildItem -Path "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue |
                Get-ItemProperty | Where-Object { $_.PSObject.Properties.Value -like "*$($value.Value)*" }
            
            if ($matches) {
                foreach ($match in $matches) {
                    $results.SuspiciousActivities += @{
                        Type = "SuspiciousRegistryValue"
                        Path = $match.PSPath
                        Value = $value.Value
                        Description = $value.Description
                        RiskLevel = $value.RiskLevel
                    }
                    $results.WarningChecks++
                }
            }
            else {
                $results.PassedChecks++
            }
        }

        # Add finding based on suspicious registry entries
        if ($results.SuspiciousActivities.Count -gt 0) {
            Add-Finding -CheckName "Suspicious Registry" -Status "Warning" `
                -Details "Found $($results.SuspiciousActivities.Count) suspicious registry entries" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    SuspiciousActivities = $results.SuspiciousActivities
                    TotalChecks = $results.TotalChecks
                    PassedChecks = $results.PassedChecks
                    FailedChecks = $results.FailedChecks
                    WarningChecks = $results.WarningChecks
                }
        }
        else {
            Add-Finding -CheckName "Registry Analysis" -Status "Pass" `
                -Details "No suspicious registry entries found" -Category "ThreatHunting" `
                -AdditionalInfo @{
                    TotalChecks = $results.TotalChecks
                    PassedChecks = $results.PassedChecks
                    FailedChecks = $results.FailedChecks
                    WarningChecks = $results.WarningChecks
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Suspicious Registry Analysis"
        Add-Finding -CheckName "Registry Analysis" -Status "Fail" `
            -Details "Failed to analyze registry: $($_.Exception.Message)" -Category "ThreatHunting" `
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
Export-ModuleMember -Function Test-SuspiciousRegistry 