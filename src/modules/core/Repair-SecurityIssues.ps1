# -----------------------------------------------------------------------------
# Security Remediation Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Automatically fixes identified security issues based on findings.

.DESCRIPTION
    This function analyzes security findings and applies automated fixes where possible.
    It provides detailed reporting on what was fixed, what was skipped, and what failed.

.PARAMETER Findings
    A hashtable containing security findings to remediate. Must include a 'Findings' key
    with an array of finding objects.

.PARAMETER AutoFix
    Switch parameter to enable automatic fixing of issues. If not specified, only a report
    will be generated without applying changes.

.PARAMETER WhatIf
    Switch parameter to simulate the remediation process without applying changes.

.PARAMETER OutputPath
    Path to save the remediation report.

.OUTPUTS
    [hashtable] A hashtable containing remediation results, including fixed issues,
    skipped issues, and failed fixes.

.EXAMPLE
    $findings = @{
        Findings = @(
            @{
                CheckName = "PowerShell Execution Policy"
                Category = "PowerShellSecurity"
                Status = "Fail"
            }
        )
    }
    $results = Repair-SecurityIssues -Findings $findings -AutoFix -Verbose

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Repair-SecurityIssues {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$Findings,
        
        [Parameter(Mandatory = $false)]
        [switch]$AutoFix,
        
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\remediation_report.json",
        
        [Parameter(Mandatory = $false)]
        [switch]$Verbose
    )

    try {
        Write-SectionHeader "Security Remediation"
        Write-Output "Analyzing security findings for remediation..."

        # Initialize results object
        $remediationInfo = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            TotalFindings = 0
            FixedIssues = @()
            SkippedIssues = @()
            FailedFixes = @()
            RequiresReboot = $false
            StartTime = Get-Date
            EndTime = $null
            Duration = 0
        }

        # Check if findings is empty
        if (-not $Findings -or -not $Findings.ContainsKey("Findings") -or $Findings.Findings.Count -eq 0) {
            Write-Output "No findings to remediate."
            return $remediationInfo
        }

        $remediationInfo.TotalFindings = $Findings.Findings.Count

        # Process each finding
        foreach ($finding in $Findings.Findings) {
            # Skip passing findings
            if ($finding.Status -eq "Pass") {
                continue
            }

            $remediationResult = @{
                CheckName = $finding.CheckName
                Category = $finding.Category
                Status = $finding.Status
                Fixed = $false
                Skipped = $false
                Failed = $false
                Error = $null
                Details = @()
            }

            # Apply fixes based on category and check name
            switch ($finding.Category) {
                "PowerShellSecurity" {
                    switch ($finding.CheckName) {
                        "PowerShell Execution Policy" {
                            if ($AutoFix) {
                                try {
                                    if ($PSCmdlet.ShouldProcess("PowerShell Execution Policy", "Set to RemoteSigned")) {
                                        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
                                        $remediationResult.Fixed = $true
                                        $remediationResult.Details += "Set execution policy to RemoteSigned"
                                    }
                                    else {
                                        $remediationResult.Skipped = $true
                                        $remediationResult.Details += "Would set execution policy to RemoteSigned (WhatIf)"
                                    }
                                }
                                catch {
                                    $remediationResult.Failed = $true
                                    $remediationResult.Error = $_.Exception.Message
                                    $remediationResult.Details += "Failed to set execution policy: $($_.Exception.Message)"
                                }
                            }
                            else {
                                $remediationResult.Skipped = $true
                                $remediationResult.Details += "AutoFix not enabled"
                            }
                        }
                        "PowerShell Logging" {
                            if ($AutoFix) {
                                try {
                                    # Enable PowerShell transcription
                                    if ($PSCmdlet.ShouldProcess("PowerShell Transcription", "Enable")) {
                                        $transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
                                        if (-not (Test-Path $transcriptionPath)) {
                                            New-Item -Path $transcriptionPath -Force | Out-Null
                                        }
                                        Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1
                                        Set-ItemProperty -Path $transcriptionPath -Name "OutputDirectory" -Value "C:\Windows\Logs\PowerShell"
                                        $remediationResult.Details += "Enabled PowerShell transcription"
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable PowerShell transcription (WhatIf)"
                                    }

                                    # Enable module logging
                                    if ($PSCmdlet.ShouldProcess("PowerShell Module Logging", "Enable")) {
                                        $moduleLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
                                        if (-not (Test-Path $moduleLoggingPath)) {
                                            New-Item -Path $moduleLoggingPath -Force | Out-Null
                                        }
                                        Set-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -Value 1
                                        $remediationResult.Details += "Enabled PowerShell module logging"
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable PowerShell module logging (WhatIf)"
                                    }

                                    # Enable script block logging
                                    if ($PSCmdlet.ShouldProcess("PowerShell Script Block Logging", "Enable")) {
                                        $scriptBlockLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                                        if (-not (Test-Path $scriptBlockLoggingPath)) {
                                            New-Item -Path $scriptBlockLoggingPath -Force | Out-Null
                                        }
                                        Set-ItemProperty -Path $scriptBlockLoggingPath -Name "EnableScriptBlockLogging" -Value 1
                                        $remediationResult.Details += "Enabled PowerShell script block logging"
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable PowerShell script block logging (WhatIf)"
                                    }

                                    $remediationResult.Fixed = $true
                                }
                                catch {
                                    $remediationResult.Failed = $true
                                    $remediationResult.Error = $_.Exception.Message
                                    $remediationResult.Details += "Failed to enable PowerShell logging: $($_.Exception.Message)"
                                }
                            }
                            else {
                                $remediationResult.Skipped = $true
                                $remediationResult.Details += "AutoFix not enabled"
                            }
                        }
                    }
                }
                "Defender" {
                    switch ($finding.CheckName) {
                        "Windows Defender Status" {
                            if ($AutoFix) {
                                try {
                                    # Start Windows Defender service
                                    if ($PSCmdlet.ShouldProcess("Windows Defender Service", "Start")) {
                                        $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
                                        if ($service -and $service.Status -ne "Running") {
                                            Start-Service -Name "WinDefend"
                                            $remediationResult.Details += "Started Windows Defender service"
                                        }
                                        else {
                                            $remediationResult.Details += "Windows Defender service is already running"
                                        }
                                    }
                                    else {
                                        $remediationResult.Details += "Would start Windows Defender service (WhatIf)"
                                    }

                                    # Update virus definitions
                                    if ($PSCmdlet.ShouldProcess("Windows Defender Signatures", "Update")) {
                                        Update-MpSignature
                                        $remediationResult.Details += "Updated Windows Defender signatures"
                                    }
                                    else {
                                        $remediationResult.Details += "Would update Windows Defender signatures (WhatIf)"
                                    }

                                    # Enable real-time protection
                                    if ($PSCmdlet.ShouldProcess("Windows Defender Real-time Protection", "Enable")) {
                                        Set-MpPreference -DisableRealtimeMonitoring $false
                                        $remediationResult.Details += "Enabled Windows Defender real-time protection"
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable Windows Defender real-time protection (WhatIf)"
                                    }

                                    $remediationResult.Fixed = $true
                                }
                                catch {
                                    $remediationResult.Failed = $true
                                    $remediationResult.Error = $_.Exception.Message
                                    $remediationResult.Details += "Failed to configure Windows Defender: $($_.Exception.Message)"
                                }
                            }
                            else {
                                $remediationResult.Skipped = $true
                                $remediationResult.Details += "AutoFix not enabled"
                            }
                        }
                    }
                }
                "CredentialProtection" {
                    switch ($finding.CheckName) {
                        "Credential Guard" {
                            if ($AutoFix) {
                                try {
                                    # Enable Hyper-V feature
                                    if ($PSCmdlet.ShouldProcess("Hyper-V Feature", "Enable")) {
                                        $hypervFeature = Get-WindowsFeature -Name "Microsoft-Hyper-V-Management-PowerShell" -ErrorAction SilentlyContinue
                                        if (-not $hypervFeature.Installed) {
                                            Install-WindowsFeature -Name "Microsoft-Hyper-V-Management-PowerShell" -IncludeManagementTools
                                            $remediationResult.Details += "Installed Hyper-V Management PowerShell feature"
                                        }
                                        else {
                                            $remediationResult.Details += "Hyper-V Management PowerShell feature is already installed"
                                        }
                                    }
                                    else {
                                        $remediationResult.Details += "Would install Hyper-V Management PowerShell feature (WhatIf)"
                                    }

                                    # Enable LSA Protection
                                    if ($PSCmdlet.ShouldProcess("LSA Protection", "Enable")) {
                                        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                                        Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1
                                        $remediationResult.Details += "Enabled LSA Protection"
                                        $remediationInfo.RequiresReboot = $true
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable LSA Protection (WhatIf)"
                                    }

                                    $remediationResult.Fixed = $true
                                }
                                catch {
                                    $remediationResult.Failed = $true
                                    $remediationResult.Error = $_.Exception.Message
                                    $remediationResult.Details += "Failed to configure Credential Guard: $($_.Exception.Message)"
                                }
                            }
                            else {
                                $remediationResult.Skipped = $true
                                $remediationResult.Details += "AutoFix not enabled"
                            }
                        }
                    }
                }
                "Firewall" {
                    switch ($finding.CheckName) {
                        "Windows Firewall Status" {
                            if ($AutoFix) {
                                try {
                                    # Enable Windows Firewall for all profiles
                                    if ($PSCmdlet.ShouldProcess("Windows Firewall", "Enable for all profiles")) {
                                        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                                        $remediationResult.Details += "Enabled Windows Firewall for all profiles"
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable Windows Firewall for all profiles (WhatIf)"
                                    }

                                    # Enable logging
                                    if ($PSCmdlet.ShouldProcess("Windows Firewall Logging", "Enable")) {
                                        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
                                        $remediationResult.Details += "Enabled Windows Firewall logging"
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable Windows Firewall logging (WhatIf)"
                                    }

                                    $remediationResult.Fixed = $true
                                }
                                catch {
                                    $remediationResult.Failed = $true
                                    $remediationResult.Error = $_.Exception.Message
                                    $remediationResult.Details += "Failed to configure Windows Firewall: $($_.Exception.Message)"
                                }
                            }
                            else {
                                $remediationResult.Skipped = $true
                                $remediationResult.Details += "AutoFix not enabled"
                            }
                        }
                    }
                }
                "UAC" {
                    switch ($finding.CheckName) {
                        "UAC Status" {
                            if ($AutoFix) {
                                try {
                                    # Enable UAC
                                    if ($PSCmdlet.ShouldProcess("User Account Control", "Enable")) {
                                        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                                        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1
                                        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2
                                        $remediationResult.Details += "Enabled User Account Control"
                                        $remediationInfo.RequiresReboot = $true
                                    }
                                    else {
                                        $remediationResult.Details += "Would enable User Account Control (WhatIf)"
                                    }

                                    $remediationResult.Fixed = $true
                                }
                                catch {
                                    $remediationResult.Failed = $true
                                    $remediationResult.Error = $_.Exception.Message
                                    $remediationResult.Details += "Failed to configure User Account Control: $($_.Exception.Message)"
                                }
                            }
                            else {
                                $remediationResult.Skipped = $true
                                $remediationResult.Details += "AutoFix not enabled"
                            }
                        }
                    }
                }
                "Security" {
                    switch ($finding.CheckName) {
                        "Suspicious Processes" {
                            if ($AutoFix) {
                                try {
                                    # For suspicious processes, we can't automatically terminate them
                                    # as this could cause system instability. Instead, we'll log them
                                    # and provide guidance.
                                    $remediationResult.Skipped = $true
                                    $remediationResult.Details += "Suspicious processes require manual review and termination"
                                    $remediationResult.Details += "Please review the following processes:"
                                    
                                    if ($finding.AdditionalInfo -and $finding.AdditionalInfo.SuspiciousProcesses) {
                                        foreach ($process in $finding.AdditionalInfo.SuspiciousProcesses) {
                                            $remediationResult.Details += "- $($process.Name) (PID: $($process.Id))"
                                        }
                                    }
                                }
                                catch {
                                    $remediationResult.Failed = $true
                                    $remediationResult.Error = $_.Exception.Message
                                    $remediationResult.Details += "Failed to analyze suspicious processes: $($_.Exception.Message)"
                                }
                            }
                            else {
                                $remediationResult.Skipped = $true
                                $remediationResult.Details += "AutoFix not enabled"
                            }
                        }
                    }
                }
                default {
                    $remediationResult.Skipped = $true
                    $remediationResult.Details += "No automated remediation available for this finding"
                }
            }

            # Add the remediation result to the appropriate category
            if ($remediationResult.Fixed) {
                $remediationInfo.FixedIssues += $remediationResult
            }
            elseif ($remediationResult.Skipped) {
                $remediationInfo.SkippedIssues += $remediationResult
            }
            elseif ($remediationResult.Failed) {
                $remediationInfo.FailedFixes += $remediationResult
            }
        }

        # Calculate duration
        $remediationInfo.EndTime = Get-Date
        $remediationInfo.Duration = ($remediationInfo.EndTime - $remediationInfo.StartTime).TotalSeconds

        # Export results if output path is specified
        if ($OutputPath) {
            $remediationInfo | ConvertTo-Json -Depth 10 | Out-File $OutputPath
            Write-Output "Remediation report exported to $OutputPath"
        }

        # Output summary
        Write-Output "`nRemediation Summary:"
        Write-Output "- Total Findings Analyzed: $($remediationInfo.TotalFindings)"
        Write-Output "- Fixed Issues: $($remediationInfo.FixedIssues.Count)"
        Write-Output "- Skipped Issues: $($remediationInfo.SkippedIssues.Count)"
        Write-Output "- Failed Fixes: $($remediationInfo.FailedFixes.Count)"
        
        if ($remediationInfo.RequiresReboot) {
            Write-Output "`nWARNING: A system reboot is required to apply some changes."
        }

        return $remediationInfo
    }
    catch {
        Write-Error "Error during security remediation: $_"
        throw
    }
}

# Export the function
Export-ModuleMember -Function Repair-SecurityIssues 