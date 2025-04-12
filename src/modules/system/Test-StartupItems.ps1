# -----------------------------------------------------------------------------
# Startup Items Analysis Module
# -----------------------------------------------------------------------------

function Test-StartupItems {
    param (
        [string]$OutputPath = ".\startup_analysis.json"
    )

    Write-SectionHeader "Startup Items Analysis"
    Write-Output "Analyzing startup items..."

    # Initialize JSON output object
    $startupInfo = Initialize-JsonOutput -Category "StartupItems" -RiskLevel "Medium" -ActionLevel "Review"
    $startupInfo.TotalItems = 0
    $startupInfo.ItemsByLocation = @{}

    # Get startup items from different locations
    $startupLocations = @(
        @{
            Name = "CurrentUser"
            Command = "Get-CimInstance -ClassName Win32_StartupCommand -Filter ""SettingID like 'Startup%'"""
            Description = "Current user startup items"
        },
        @{
            Name = "AllUsers"
            Command = "Get-CimInstance -ClassName Win32_StartupCommand -Filter ""SettingID like 'Common Startup%'"""
            Description = "All users startup items"
        },
        @{
            Name = "Registry"
            Command = "Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'"
            Description = "Registry startup items"
        }
    )

    foreach ($location in $startupLocations) {
        $items = Invoke-Expression $location.Command
        $startupInfo.ItemsByLocation[$location.Name] = @{
            Count = ($items | Measure-Object).Count
            Items = $items
            Description = $location.Description
        }
        $startupInfo.TotalItems += $startupInfo.ItemsByLocation[$location.Name].Count
    }

    # Define suspicious patterns
    $suspiciousPatterns = @(
        @{
            Pattern = "\.exe.*http|\.exe.*ftp|\.exe.*download"
            Description = "Executable with network activity"
            RiskLevel = "High"
        },
        @{
            Pattern = "powershell.*-enc|cmd.*\/c"
            Description = "Encoded command execution"
            RiskLevel = "High"
        },
        @{
            Pattern = "\.vbs|\.js|\.bat|\.ps1"
            Description = "Script file execution"
            RiskLevel = "Medium"
        },
        @{
            Pattern = "\\temp\\|\\downloads\\"
            Description = "Temporary or downloads directory"
            RiskLevel = "Medium"
        }
    )

    # Check for suspicious items
    $suspiciousItems = @()
    foreach ($location in $startupInfo.ItemsByLocation.Keys) {
        foreach ($item in $startupInfo.ItemsByLocation[$location].Items) {
            foreach ($pattern in $suspiciousPatterns) {
                if ($item.Command -match $pattern.Pattern) {
                    $suspiciousItems += @{
                        Location = $location
                        Item = $item
                        Pattern = $pattern.Pattern
                        Description = $pattern.Description
                        RiskLevel = $pattern.RiskLevel
                    }
                }
            }
        }
    }

    # Output results
    if ($startupInfo.TotalItems -gt 0) {
        Write-Output "Found $($startupInfo.TotalItems) total startup items:"
        foreach ($location in $startupInfo.ItemsByLocation.Keys) {
            $count = $startupInfo.ItemsByLocation[$location].Count
            Write-Output "$location Items ($count):"
            $startupInfo.ItemsByLocation[$location].Items | ForEach-Object {
                Write-Output "  - $($_.Command)"
            }
        }

        if ($suspiciousItems.Count -gt 0) {
            Write-Output "`nSuspicious startup items found:"
            $suspiciousItems | ForEach-Object {
                Write-Output "Location: $($_.Location)"
                Write-Output "Item: $($_.Item.Command)"
                Write-Output "Risk: $($_.RiskLevel) - $($_.Description)"
                Write-Output "---"
            }

            Add-Finding -CheckName "Startup Items" -Status "Fail" `
                -Details "Found $($suspiciousItems.Count) suspicious startup items." -Category "Startup" `
                -AdditionalInfo @{
                    TotalItems = $startupInfo.TotalItems
                    SuspiciousItems = $suspiciousItems
                }
        }
        else {
            Add-Finding -CheckName "Startup Items" -Status "Pass" `
                -Details "No suspicious startup items detected." -Category "Startup" `
                -AdditionalInfo $startupInfo
        }
    }
    else {
        Write-Output "No startup items found."
        Add-Finding -CheckName "Startup Items" -Status "Pass" `
            -Details "No startup items configured." -Category "Startup" `
            -AdditionalInfo $startupInfo
    }

    # Export results to JSON if path specified
    if ($OutputPath) {
        Export-ToJson -Data $startupInfo -FilePath $OutputPath -Pretty
        Write-Output "Results exported to: $OutputPath"
    }
}

# Export the function
Export-ModuleMember -Function Test-StartupItems 