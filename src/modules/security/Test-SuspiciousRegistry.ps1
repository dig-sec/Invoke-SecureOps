# -----------------------------------------------------------------------------
# Suspicious Registry Detection Module
# -----------------------------------------------------------------------------

function Test-SuspiciousRegistry {
    param (
        [string]$OutputPath,
        [switch]$PrettyOutput,
        [string]$BaselinePath,
        [switch]$CollectEvidence,
        [hashtable]$CustomComparators
    )

    Write-SectionHeader "Suspicious Registry Analysis"
    Write-Output "Analyzing registry for suspicious entries..."

    # Initialize test result
    $testResult = Initialize-TestResult -Name "Test-SuspiciousRegistry"

    # Initialize results object for internal tracking
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
            Add-Finding -TestResult $testResult -FindingName "Suspicious Registry" -Status "Warning" `
                -Description "Found $($results.SuspiciousActivities.Count) suspicious registry entries" -RiskLevel "High" `
                -AdditionalInfo @{
                    SuspiciousActivities = $results.SuspiciousActivities
                    TotalChecks = $results.TotalChecks
                    PassedChecks = $results.PassedChecks
                    FailedChecks = $results.FailedChecks
                    WarningChecks = $results.WarningChecks
                    Recommendation = "Review and investigate these registry entries for potential security risks"
                }
        }
        else {
            Add-Finding -TestResult $testResult -FindingName "Registry Analysis" -Status "Pass" `
                -Description "No suspicious registry entries found" -RiskLevel "Info" `
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
        Add-Finding -TestResult $testResult -FindingName "Registry Analysis" -Status "Error" `
            -Description "Failed to analyze registry: $($_.Exception.Message)" -RiskLevel "High" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-TestResult -TestResult $testResult -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        Write-Output "Results exported to: $OutputPath"
    }

    return $testResult
}

# Export the function
Export-ModuleMember -Function Test-SuspiciousRegistry 