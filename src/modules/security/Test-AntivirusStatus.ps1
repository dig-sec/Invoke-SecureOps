# -----------------------------------------------------------------------------
# Antivirus Status Analysis Module
# -----------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests for antivirus status and configuration.

.DESCRIPTION
    This function analyzes the system for installed antivirus software, their status,
    and configuration settings to ensure proper protection.

.PARAMETER OutputPath
    The path where the test results will be exported.

.PARAMETER PrettyOutput
    Switch parameter to format the output JSON with indentation.

.PARAMETER DetailedAnalysis
    Switch parameter to perform a more detailed analysis of antivirus settings.

.PARAMETER BaselinePath
    Path to a baseline file for comparison.

.PARAMETER CollectEvidence
    Switch parameter to collect evidence for findings.

.PARAMETER CustomComparators
    Hashtable of custom comparison functions.

.OUTPUTS
    [hashtable] A hashtable containing test results and findings.

.EXAMPLE
    Test-AntivirusStatus -OutputPath ".\results.json" -PrettyOutput

.NOTES
    Author: Security Team
    Version: 1.0
#>
function Test-AntivirusStatus {
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
        [hashtable]$CustomComparators
    )

    # Initialize test result
    $result = Initialize-TestResult -TestName "Test-AntivirusStatus" -Category "Security" -Description "Analysis of antivirus status and configuration"

    try {
        # Check if Windows Defender is available
        $defenderAvailable = $false
        $defenderStatus = $null
        
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $defenderAvailable = $true
            $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        }

        # Check for installed antivirus products using WMI
        $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction SilentlyContinue
        
        if (-not $antivirusProducts) {
            # Try alternative WMI namespace for older Windows versions
            $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter" -Class "AntiVirusProduct" -ErrorAction SilentlyContinue
        }

        # Check if any antivirus is installed
        if (-not $antivirusProducts -and -not $defenderAvailable) {
            Add-Finding -TestResult $result -FindingName "No Antivirus Installed" -Status "Critical" `
                -Description "No antivirus software detected on this system" -RiskLevel "Critical" `
                -AdditionalInfo @{
                    Component = "Antivirus"
                    Recommendation = "Install a supported antivirus solution"
                }
            return $result
        }

        # Process Windows Defender status if available
        if ($defenderAvailable) {
            $defenderInfo = @{
                Name = "Windows Defender"
                DisplayName = "Windows Defender"
                ProductState = $defenderStatus.ProductState
                AntivirusEnabled = $defenderStatus.AntivirusEnabled
                RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                AntivirusSignatureAge = $defenderStatus.AntivirusSignatureAge
                AntivirusSignatureVersion = $defenderStatus.AntivirusSignatureVersion
                NISEnabled = $defenderStatus.NISEnabled
                NISSignatureAge = $defenderStatus.NISSignatureAge
                NISSignatureVersion = $defenderStatus.NISSignatureVersion
                QuickScanEndTime = $defenderStatus.QuickScanEndTime
                FullScanEndTime = $defenderStatus.FullScanEndTime
                QuickScanSignatureVersion = $defenderStatus.QuickScanSignatureVersion
                FullScanSignatureVersion = $defenderStatus.FullScanSignatureVersion
                EngineVersion = $defenderStatus.EngineVersion
                AMServiceEnabled = $defenderStatus.AMServiceEnabled
                AntispywareEnabled = $defenderStatus.AntispywareEnabled
                AntispywareSignatureAge = $defenderStatus.AntispywareSignatureAge
                AntispywareSignatureVersion = $defenderStatus.AntispywareSignatureVersion
                BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
                IoavProtectionEnabled = $defenderStatus.IoavProtectionEnabled
                OnAccessProtectionEnabled = $defenderStatus.OnAccessProtectionEnabled
            }

            # Check if Windows Defender is enabled
            if (-not $defenderInfo.AntivirusEnabled) {
                Add-Finding -TestResult $result -FindingName "Windows Defender Disabled" -Status "Critical" `
                    -Description "Windows Defender antivirus is disabled" -RiskLevel "Critical" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Status = "Disabled"
                        Recommendation = "Enable Windows Defender antivirus"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Defender Status" -Status "Pass" `
                    -Description "Windows Defender antivirus is enabled" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Status = "Enabled"
                    }
            }

            # Check if real-time protection is enabled
            if (-not $defenderInfo.RealTimeProtectionEnabled) {
                Add-Finding -TestResult $result -FindingName "Windows Defender Real-time Protection Disabled" -Status "Critical" `
                    -Description "Windows Defender real-time protection is disabled" -RiskLevel "Critical" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Real-time Protection"
                        Status = "Disabled"
                        Recommendation = "Enable Windows Defender real-time protection"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Defender Real-time Protection" -Status "Pass" `
                    -Description "Windows Defender real-time protection is enabled" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Real-time Protection"
                        Status = "Enabled"
                    }
            }

            # Check antivirus signature age
            if ($defenderInfo.AntivirusSignatureAge -gt 7) {
                Add-Finding -TestResult $result -FindingName "Windows Defender Outdated Signatures" -Status "Warning" `
                    -Description "Windows Defender antivirus signatures are $($defenderInfo.AntivirusSignatureAge) days old" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Antivirus Signatures"
                        Age = $defenderInfo.AntivirusSignatureAge
                        Version = $defenderInfo.AntivirusSignatureVersion
                        Recommendation = "Update Windows Defender antivirus signatures"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Defender Signatures" -Status "Pass" `
                    -Description "Windows Defender antivirus signatures are up to date" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Antivirus Signatures"
                        Age = $defenderInfo.AntivirusSignatureAge
                        Version = $defenderInfo.AntivirusSignatureVersion
                    }
            }

            # Check if behavior monitoring is enabled
            if (-not $defenderInfo.BehaviorMonitorEnabled) {
                Add-Finding -TestResult $result -FindingName "Windows Defender Behavior Monitoring Disabled" -Status "Warning" `
                    -Description "Windows Defender behavior monitoring is disabled" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Behavior Monitoring"
                        Status = "Disabled"
                        Recommendation = "Enable Windows Defender behavior monitoring"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Defender Behavior Monitoring" -Status "Pass" `
                    -Description "Windows Defender behavior monitoring is enabled" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Behavior Monitoring"
                        Status = "Enabled"
                    }
            }

            # Check if IOAV protection is enabled
            if (-not $defenderInfo.IoavProtectionEnabled) {
                Add-Finding -TestResult $result -FindingName "Windows Defender IOAV Protection Disabled" -Status "Warning" `
                    -Description "Windows Defender IOAV protection is disabled" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "IOAV Protection"
                        Status = "Disabled"
                        Recommendation = "Enable Windows Defender IOAV protection"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Defender IOAV Protection" -Status "Pass" `
                    -Description "Windows Defender IOAV protection is enabled" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "IOAV Protection"
                        Status = "Enabled"
                    }
            }

            # Check if antispyware is enabled
            if (-not $defenderInfo.AntispywareEnabled) {
                Add-Finding -TestResult $result -FindingName "Windows Defender Antispyware Disabled" -Status "Warning" `
                    -Description "Windows Defender antispyware is disabled" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Antispyware"
                        Status = "Disabled"
                        Recommendation = "Enable Windows Defender antispyware"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Defender Antispyware" -Status "Pass" `
                    -Description "Windows Defender antispyware is enabled" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Antispyware"
                        Status = "Enabled"
                    }
            }

            # Check if Network Inspection System is enabled
            if (-not $defenderInfo.NISEnabled) {
                Add-Finding -TestResult $result -FindingName "Windows Defender NIS Disabled" -Status "Warning" `
                    -Description "Windows Defender Network Inspection System is disabled" -RiskLevel "High" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Network Inspection System"
                        Status = "Disabled"
                        Recommendation = "Enable Windows Defender Network Inspection System"
                    }
            }
            else {
                Add-Finding -TestResult $result -FindingName "Windows Defender NIS" -Status "Pass" `
                    -Description "Windows Defender Network Inspection System is enabled" -RiskLevel "Low" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Network Inspection System"
                        Status = "Enabled"
                    }
            }

            # Check last scan times
            $lastQuickScan = $defenderInfo.QuickScanEndTime
            $lastFullScan = $defenderInfo.FullScanEndTime
            
            if ($lastQuickScan -eq $null -or $lastQuickScan -eq [DateTime]::MinValue) {
                Add-Finding -TestResult $result -FindingName "Windows Defender No Quick Scans" -Status "Warning" `
                    -Description "No Windows Defender quick scans have been performed" -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Quick Scan"
                        Status = "Never Run"
                        Recommendation = "Run a Windows Defender quick scan"
                    }
            }
            else {
                $daysSinceQuickScan = (Get-Date) - $lastQuickScan
                if ($daysSinceQuickScan.Days -gt 30) {
                    Add-Finding -TestResult $result -FindingName "Windows Defender Old Quick Scan" -Status "Warning" `
                        -Description "Last Windows Defender quick scan was $($daysSinceQuickScan.Days) days ago" -RiskLevel "Medium" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = "Windows Defender"
                            Feature = "Quick Scan"
                            LastRun = $lastQuickScan
                            DaysAgo = $daysSinceQuickScan.Days
                            Recommendation = "Run a Windows Defender quick scan"
                        }
                }
                else {
                    Add-Finding -TestResult $result -FindingName "Windows Defender Quick Scan" -Status "Pass" `
                        -Description "Last Windows Defender quick scan was $($daysSinceQuickScan.Days) days ago" -RiskLevel "Low" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = "Windows Defender"
                            Feature = "Quick Scan"
                            LastRun = $lastQuickScan
                            DaysAgo = $daysSinceQuickScan.Days
                        }
                }
            }

            if ($lastFullScan -eq $null -or $lastFullScan -eq [DateTime]::MinValue) {
                Add-Finding -TestResult $result -FindingName "Windows Defender No Full Scans" -Status "Warning" `
                    -Description "No Windows Defender full scans have been performed" -RiskLevel "Medium" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Product = "Windows Defender"
                        Feature = "Full Scan"
                        Status = "Never Run"
                        Recommendation = "Run a Windows Defender full scan"
                    }
            }
            else {
                $daysSinceFullScan = (Get-Date) - $lastFullScan
                if ($daysSinceFullScan.Days -gt 90) {
                    Add-Finding -TestResult $result -FindingName "Windows Defender Old Full Scan" -Status "Warning" `
                        -Description "Last Windows Defender full scan was $($daysSinceFullScan.Days) days ago" -RiskLevel "Medium" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = "Windows Defender"
                            Feature = "Full Scan"
                            LastRun = $lastFullScan
                            DaysAgo = $daysSinceFullScan.Days
                            Recommendation = "Run a Windows Defender full scan"
                        }
                }
                else {
                    Add-Finding -TestResult $result -FindingName "Windows Defender Full Scan" -Status "Pass" `
                        -Description "Last Windows Defender full scan was $($daysSinceFullScan.Days) days ago" -RiskLevel "Low" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = "Windows Defender"
                            Feature = "Full Scan"
                            LastRun = $lastFullScan
                            DaysAgo = $daysSinceFullScan.Days
                        }
                }
            }
        }

        # Process third-party antivirus products
        if ($antivirusProducts) {
            foreach ($av in $antivirusProducts) {
                # Extract product state information
                $productState = $av.productState
                $stateBytes = [System.BitConverter]::GetBytes($productState)
                
                # Byte 1: Product state (0 = off, 1 = on, 2 = snoozed)
                $productStateValue = $stateBytes[1]
                
                # Byte 2: Signature status (0 = up to date, 1 = out of date)
                $signatureStatus = $stateBytes[2]
                
                # Byte 3: Product type (0 = antivirus, 1 = antispyware, 2 = firewall)
                $productType = $stateBytes[3]
                
                $avInfo = @{
                    Name = $av.displayName
                    ProductState = $productState
                    ProductStateValue = $productStateValue
                    SignatureStatus = $signatureStatus
                    ProductType = $productType
                    PathToSignedProductExe = $av.pathToSignedProductExe
                    PathToSignedReportingExe = $av.pathToSignedReportingExe
                }

                # Check if antivirus is enabled
                if ($productStateValue -eq 0) {
                    Add-Finding -TestResult $result -FindingName "$($avInfo.Name) Disabled" -Status "Critical" `
                        -Description "$($avInfo.Name) is disabled" -RiskLevel "Critical" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = $avInfo.Name
                            Status = "Disabled"
                            Recommendation = "Enable $($avInfo.Name)"
                        }
                }
                else {
                    Add-Finding -TestResult $result -FindingName "$($avInfo.Name) Status" -Status "Pass" `
                        -Description "$($avInfo.Name) is enabled" -RiskLevel "Low" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = $avInfo.Name
                            Status = "Enabled"
                        }
                }

                # Check if signatures are up to date
                if ($signatureStatus -eq 1) {
                    Add-Finding -TestResult $result -FindingName "$($avInfo.Name) Outdated Signatures" -Status "Warning" `
                        -Description "$($avInfo.Name) signatures are out of date" -RiskLevel "High" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = $avInfo.Name
                            Feature = "Signatures"
                            Status = "Out of Date"
                            Recommendation = "Update $($avInfo.Name) signatures"
                        }
                }
                else {
                    Add-Finding -TestResult $result -FindingName "$($avInfo.Name) Signatures" -Status "Pass" `
                        -Description "$($avInfo.Name) signatures are up to date" -RiskLevel "Low" `
                        -AdditionalInfo @{
                            Component = "Antivirus"
                            Product = $avInfo.Name
                            Feature = "Signatures"
                            Status = "Up to Date"
                        }
                }
            }
        }

        # Export results if OutputPath is specified
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Add-Finding -TestResult $result -FindingName "Test Error" -Status "Error" `
            -Description "Error during antivirus status analysis: $_" -RiskLevel "High"
        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }
        return $result
    }
}

# Export the function
Export-ModuleMember -Function Test-AntivirusStatus 