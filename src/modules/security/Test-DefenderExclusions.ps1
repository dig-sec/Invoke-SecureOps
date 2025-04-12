# -----------------------------------------------------------------------------
# Windows Defender Exclusions Analysis Module
# -----------------------------------------------------------------------------

function Test-DefenderExclusions {
    param (
        [string]$OutputPath = ".\defender_exclusions.json"
    )

    Write-SectionHeader "Windows Defender Exclusions Analysis"
    Write-Output "Analyzing Windows Defender exclusions..."

    # Initialize JSON output object using common function
    $exclusionsInfo = Initialize-JsonOutput -Category "DefenderExclusions" -RiskLevel "Medium" -ActionLevel "Review"
    $exclusionsInfo.TotalExclusions = 0
    $exclusionsInfo.ExclusionsByType = @{}

    # Get exclusions for different categories
    $exclusionTypes = @(
        @{
            Name = "Process"
            Command = "Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess"
            Description = "Process exclusions"
        },
        @{
            Name = "Path"
            Command = "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
            Description = "Path exclusions"
        },
        @{
            Name = "Extension"
            Command = "Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension"
            Description = "File extension exclusions"
        },
        @{
            Name = "IP"
            Command = "Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress"
            Description = "IP address exclusions"
        }
    )

    foreach ($type in $exclusionTypes) {
        $exclusions = Invoke-Expression $type.Command
        $exclusionsInfo.ExclusionsByType[$type.Name] = @{
            Count = ($exclusions | Measure-Object).Count
            Items = $exclusions
            Description = $type.Description
        }
        $exclusionsInfo.TotalExclusions += ($exclusions | Measure-Object).Count
    }

    # Check for suspicious exclusions
    $suspiciousExclusions = @()
    
    # Check for path exclusions in sensitive locations
    $sensitivePaths = @(
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Program Files",
        "C:\\Program Files (x86)"
    )
    
    if ($exclusionsInfo.ExclusionsByType.ContainsKey("Path")) {
        foreach ($path in $exclusionsInfo.ExclusionsByType["Path"].Items) {
            foreach ($sensitivePath in $sensitivePaths) {
                if ($path -like "$sensitivePath*") {
                    $suspiciousExclusions += @{
                        Type = "Path"
                        Value = $path
                        Reason = "Excludes sensitive system path"
                        RiskLevel = "High"
                    }
                }
            }
        }
    }
    
    # Check for process exclusions for system processes
    $systemProcesses = @(
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "winlogon.exe",
        "services.exe",
        "wininit.exe",
        "smss.exe",
        "explorer.exe"
    )
    
    if ($exclusionsInfo.ExclusionsByType.ContainsKey("Process")) {
        foreach ($process in $exclusionsInfo.ExclusionsByType["Process"].Items) {
            if ($systemProcesses -contains $process.ToLower()) {
                $suspiciousExclusions += @{
                    Type = "Process"
                    Value = $process
                    Reason = "Excludes system process"
                    RiskLevel = "High"
                }
            }
        }
    }
    
    # Check for extension exclusions for executable files
    $executableExtensions = @(
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js"
    )
    
    if ($exclusionsInfo.ExclusionsByType.ContainsKey("Extension")) {
        foreach ($extension in $exclusionsInfo.ExclusionsByType["Extension"].Items) {
            if ($executableExtensions -contains $extension.ToLower()) {
                $suspiciousExclusions += @{
                    Type = "Extension"
                    Value = $extension
                    Reason = "Excludes executable file extension"
                    RiskLevel = "High"
                }
            }
        }
    }
    
    $exclusionsInfo.SuspiciousExclusions = $suspiciousExclusions
    $exclusionsInfo.SuspiciousExclusionCount = $suspiciousExclusions.Count

    # Export results to JSON
    Export-ToJson -Data $exclusionsInfo -FilePath $OutputPath -Pretty

    # Add findings
    Add-Finding -CheckName "Windows Defender Exclusions" -Status "Info" -Details "Found $($exclusionsInfo.TotalExclusions) total exclusions" -Category "Defender"
    
    if ($exclusionsInfo.SuspiciousExclusionCount -gt 0) {
        Add-Finding -CheckName "Suspicious Windows Defender Exclusions" -Status "Warning" -Details "Found $($exclusionsInfo.SuspiciousExclusionCount) suspicious exclusions" -Category "Defender"
    }
    else {
        Add-Finding -CheckName "Suspicious Windows Defender Exclusions" -Status "Pass" -Details "No suspicious exclusions found" -Category "Defender"
    }

    return $exclusionsInfo
}

# Export the function
Export-ModuleMember -Function Test-DefenderExclusions 