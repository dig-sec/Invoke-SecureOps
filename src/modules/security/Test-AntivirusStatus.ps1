# -----------------------------------------------------------------------------
# Antivirus Status Analysis Module
# -----------------------------------------------------------------------------

function Test-AntivirusStatus {
    param (
        [string]$OutputPath = ".\antivirus_status.json"
    )

    Write-SectionHeader "Antivirus Status Check"
    Write-Output "Checking antivirus status..."

    # Initialize JSON output object using common function
    $avInfo = Initialize-JsonOutput -Category "AntivirusStatus" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Get Windows Defender status
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        # Get registered antivirus products
        $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction SilentlyContinue
        
        $avInfo.WindowsDefender = @{
            AntivirusEnabled = $defender.AntivirusEnabled
            RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
            AntispywareEnabled = $defender.AntispywareEnabled
            AntivirusSignatureAge = $defender.AntivirusSignatureAge
            NISEnabled = $defender.NISEnabled
            NISSignatureAge = $defender.NISSignatureAge
        }
        $avInfo.RegisteredAV = @()

        # Check Windows Defender status
        if ($defender) {
            if (-not $defender.AntivirusEnabled) {
                Add-Finding -CheckName "Windows Defender" -Status "Warning" `
                    -Details "Windows Defender antivirus is disabled" -Category "AntivirusStatus" `
                    -AdditionalInfo @{
                        Component = "Antivirus"
                        Status = "Disabled"
                    }
            }
            if (-not $defender.RealTimeProtectionEnabled) {
                Add-Finding -CheckName "Windows Defender Real-time Protection" -Status "Warning" `
                    -Details "Real-time protection is disabled" -Category "AntivirusStatus" `
                    -AdditionalInfo @{
                        Component = "RealTimeProtection"
                        Status = "Disabled"
                    }
            }
            if ($defender.AntivirusSignatureAge -gt 7) {
                Add-Finding -CheckName "Windows Defender Signatures" -Status "Warning" `
                    -Details "Antivirus signatures are more than 7 days old" -Category "AntivirusStatus" `
                    -AdditionalInfo @{
                        Component = "Signatures"
                        Age = $defender.AntivirusSignatureAge
                        Threshold = 7
                    }
            }
        }
        else {
            Add-Finding -CheckName "Windows Defender" -Status "Info" `
                -Details "Windows Defender not found - checking for other antivirus products" -Category "AntivirusStatus" `
                -AdditionalInfo @{
                    Component = "WindowsDefender"
                    Status = "NotFound"
                }
        }

        # Check registered antivirus products
        if ($avProducts) {
            foreach ($av in $avProducts) {
                $avInfo.RegisteredAV += @{
                    DisplayName = $av.displayName
                    ProductState = $av.productState
                    Timestamp = $av.timestamp
                }
                
                # Convert product state to readable format
                $state = $av.productState
                $stateHex = [Convert]::ToString($state, 16).PadLeft(6, '0')
                $enabled = $stateHex.Substring(2, 2) -eq "00"
                $upToDate = $stateHex.Substring(4, 2) -eq "00"
                
                if (-not $enabled) {
                    Add-Finding -CheckName "Antivirus: $($av.displayName)" -Status "Warning" `
                        -Details "Antivirus is disabled" -Category "AntivirusStatus" `
                        -AdditionalInfo @{
                            Product = $av.displayName
                            Component = "Antivirus"
                            Status = "Disabled"
                        }
                }
                elseif (-not $upToDate) {
                    Add-Finding -CheckName "Antivirus: $($av.displayName)" -Status "Warning" `
                        -Details "Antivirus definitions are not up to date" -Category "AntivirusStatus" `
                        -AdditionalInfo @{
                            Product = $av.displayName
                            Component = "Definitions"
                            Status = "OutOfDate"
                        }
                }
                else {
                    Add-Finding -CheckName "Antivirus: $($av.displayName)" -Status "Pass" `
                        -Details "Antivirus is enabled and up to date" -Category "AntivirusStatus" `
                        -AdditionalInfo @{
                            Product = $av.displayName
                            Component = "Antivirus"
                            Status = "Enabled"
                            Definitions = "UpToDate"
                        }
                }
            }
        }
        else {
            Add-Finding -CheckName "Antivirus" -Status "Fail" `
                -Details "No antivirus products found" -Category "AntivirusStatus" `
                -AdditionalInfo @{
                    Component = "Antivirus"
                    Status = "NotFound"
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Antivirus Status Analysis"
        Add-Finding -CheckName "Antivirus Status" -Status "Error" `
            -Details "Failed to check antivirus status: $($_.Exception.Message)" -Category "AntivirusStatus" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $avInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $avInfo
}

# Export the function
Export-ModuleMember -Function Test-AntivirusStatus 