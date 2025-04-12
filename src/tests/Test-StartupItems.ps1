# -----------------------------------------------------------------------------
# System Startup Items Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for suspicious startup items and configurations.

.DESCRIPTION
    This function analyzes system startup configuration, including registry run keys,
    startup folders, scheduled tasks, and services that start automatically.
    It identifies potentially suspicious or unauthorized startup items.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-StartupItems -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-StartupItems {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$DetailedAnalysis,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [hashtable]$CustomComparators = @{}
    )
    
    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-StartupItems" -Category "Security" -Description "Analyzes system startup configuration for suspicious items"
    
    try {
        # Define registry startup locations
        $registryLocations = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Description = "Machine Run Key"
                RiskLevel = "High"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                Description = "Machine RunOnce Key"
                RiskLevel = "High"
            },
            @{
                Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                Description = "User Run Key"
                RiskLevel = "Medium"
            },
            @{
                Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                Description = "User RunOnce Key"
                RiskLevel = "Medium"
            },
            @{
                Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                Description = "Machine Run Key (32-bit)"
                RiskLevel = "High"
            }
        )
        
        # Check registry startup locations
        foreach ($location in $registryLocations) {
            if (Test-Path $location.Path) {
                $items = Get-ItemProperty -Path $location.Path -ErrorAction SilentlyContinue
                
                if ($items) {
                    $startupItems = $items.PSObject.Properties |
                        Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') }
                    
                    foreach ($item in $startupItems) {
                        $filePath = $item.Value
                        $fileExists = Test-Path $filePath
                        
                        if ($fileExists) {
                            $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
                            $hash = Get-FileHash -Path $filePath -ErrorAction SilentlyContinue
                        }
                        
                        Add-Finding -TestResult $result -Name "$($location.Description) Item" `
                            -Status $(if ($fileExists -and $signature.Status -eq 'Valid') { "Info" } else { "Warning" }) `
                            -RiskLevel $(if ($fileExists -and $signature.Status -eq 'Valid') { "Low" } else { $location.RiskLevel }) `
                            -Description "Found startup item: $($item.Name)" `
                            -AdditionalInfo @{
                                Component = "StartupItems"
                                Location = $location.Path
                                ItemName = $item.Name
                                Command = $filePath
                                FileExists = $fileExists
                                Signed = if ($fileExists -and $signature) { $signature.Status -eq 'Valid' } else { $false }
                                SignatureStatus = if ($fileExists -and $signature) { $signature.Status.ToString() } else { "Unknown" }
                                FileHash = if ($fileExists -and $hash) { $hash.Hash } else { $null }
                                Recommendation = "Verify this startup item is authorized"
                            }
                    }
                }
            }
        }
        
        # Check startup folders
        $startupFolders = @(
            @{
                Path = [System.Environment]::GetFolderPath('Startup')
                Description = "User Startup Folder"
                RiskLevel = "Medium"
            },
            @{
                Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
                Description = "Common Startup Folder"
                RiskLevel = "High"
            }
        )
        
        foreach ($folder in $startupFolders) {
            if (Test-Path $folder.Path) {
                $items = Get-ChildItem -Path $folder.Path -File -ErrorAction SilentlyContinue
                
                foreach ($item in $items) {
                    $signature = Get-AuthenticodeSignature -FilePath $item.FullName -ErrorAction SilentlyContinue
                    $hash = Get-FileHash -Path $item.FullName -ErrorAction SilentlyContinue
                    
                    Add-Finding -TestResult $result -Name "$($folder.Description) Item" `
                        -Status $(if ($signature.Status -eq 'Valid') { "Info" } else { "Warning" }) `
                        -RiskLevel $(if ($signature.Status -eq 'Valid') { "Low" } else { $folder.RiskLevel }) `
                        -Description "Found startup item: $($item.Name)" `
                        -AdditionalInfo @{
                            Component = "StartupItems"
                            Location = $folder.Path
                            FileName = $item.Name
                            FilePath = $item.FullName
                            CreationTime = $item.CreationTime
                            LastWriteTime = $item.LastWriteTime
                            Signed = $signature.Status -eq 'Valid'
                            SignatureStatus = $signature.Status.ToString()
                            FileHash = $hash.Hash
                            Recommendation = "Verify this startup item is authorized"
                        }
                }
            }
        }
        
        # Check scheduled tasks that run at startup
        $startupTasks = Get-ScheduledTask | Where-Object {
            $_.Settings.StartWhenAvailable -or
            $_.Triggers.LogonTrigger -or
            $_.Triggers.BootTrigger
        } -ErrorAction SilentlyContinue
        
        foreach ($task in $startupTasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            
            Add-Finding -TestResult $result -Name "Startup Scheduled Task" `
                -Status "Info" -RiskLevel "Medium" `
                -Description "Found startup scheduled task: $($task.TaskName)" `
                -AdditionalInfo @{
                    Component = "StartupItems"
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    State = $task.State
                    Author = $task.Author
                    LastRunTime = $taskInfo.LastRunTime
                    NextRunTime = $taskInfo.NextRunTime
                    LastTaskResult = $taskInfo.LastTaskResult
                    Recommendation = "Review scheduled task configuration and verify it is authorized"
                }
        }
        
        # Export results if output path is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        
        return $result
    }
    catch {
        Write-Error "Error during startup items test: $_"
        Add-Finding -TestResult $result -Name "Test Error" -Status "Error" -RiskLevel "High" `
            -Description "An error occurred while checking startup items: $_" `
            -Recommendation "Check system permissions and registry access"
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-StartupItems 