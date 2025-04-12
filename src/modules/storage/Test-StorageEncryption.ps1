# -----------------------------------------------------------------------------
# Storage Encryption Analysis Module
# -----------------------------------------------------------------------------

function Test-StorageEncryption {
    param (
        [string]$OutputPath = ".\storage_encryption.json"
    )

    Write-SectionHeader "Storage Encryption Check"
    Write-Output "Analyzing storage encryption status..."

    # Initialize JSON output object using common function
    $storageInfo = Initialize-JsonOutput -Category "StorageEncryption" -RiskLevel "High" -ActionLevel "Review"

    try {
        # Check BitLocker status
        $bitlocker = Get-BitLockerVolume
        
        # Check TPM status
        $tpm = Get-Tpm
        
        # Get disk information
        $disks = Get-Disk | Where-Object { $_.PartitionStyle -eq "GPT" }
        
        $storageInfo.BitLocker = @{
            Volumes = $bitlocker | ForEach-Object {
                @{
                    DriveLetter = $_.DriveLetter
                    ProtectionStatus = $_.ProtectionStatus
                    EncryptionMethod = $_.EncryptionMethod
                    VolumeStatus = $_.VolumeStatus
                }
            }
        }
        $storageInfo.TPM = @{
            Enabled = $tpm.TpmReady
            ManufacturerId = $tpm.ManufacturerId
            PhysicalPresenceVersionInfo = $tpm.PhysicalPresenceVersionInfo
        }
        $storageInfo.Disks = $disks | ForEach-Object {
            @{
                Number = $_.Number
                FriendlyName = $_.FriendlyName
                Size = $_.Size
                PartitionStyle = $_.PartitionStyle
            }
        }

        # Add findings based on storage encryption
        $encryptedCount = ($bitlocker | Where-Object { $_.ProtectionStatus -eq "On" }).Count
        $totalVolumes = $bitlocker.Count
        
        if ($encryptedCount -eq 0) {
            Add-Finding -CheckName "BitLocker Encryption" -Status "Fail" `
                -Details "No volumes are encrypted with BitLocker" -Category "StorageEncryption" `
                -AdditionalInfo @{
                    EncryptedCount = $encryptedCount
                    TotalVolumes = $totalVolumes
                }
        }
        elseif ($encryptedCount -lt $totalVolumes) {
            Add-Finding -CheckName "BitLocker Encryption" -Status "Warning" `
                -Details "Only $encryptedCount of $totalVolumes volumes are encrypted" -Category "StorageEncryption" `
                -AdditionalInfo @{
                    EncryptedCount = $encryptedCount
                    TotalVolumes = $totalVolumes
                }
        }
        else {
            Add-Finding -CheckName "BitLocker Encryption" -Status "Pass" `
                -Details "All volumes are encrypted with BitLocker" -Category "StorageEncryption" `
                -AdditionalInfo @{
                    EncryptedCount = $encryptedCount
                    TotalVolumes = $totalVolumes
                }
        }

        if (-not $tpm.TpmReady) {
            Add-Finding -CheckName "TPM Status" -Status "Warning" `
                -Details "TPM is not ready" -Category "StorageEncryption" `
                -AdditionalInfo @{
                    TpmReady = $tpm.TpmReady
                    ManufacturerId = $tpm.ManufacturerId
                }
        }
        else {
            Add-Finding -CheckName "TPM Status" -Status "Pass" `
                -Details "TPM is ready and enabled" -Category "StorageEncryption" `
                -AdditionalInfo @{
                    TpmReady = $tpm.TpmReady
                    ManufacturerId = $tpm.ManufacturerId
                }
        }

        # Check for unencrypted removable drives
        $removableDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
        $unencryptedRemovableCount = 0
        
        foreach ($drive in $removableDrives) {
            $bitlockerStatus = Get-BitLockerVolume -MountPoint $drive.DeviceID -ErrorAction SilentlyContinue
            if (-not $bitlockerStatus -or $bitlockerStatus.ProtectionStatus -ne "On") {
                $unencryptedRemovableCount++
                Add-Finding -CheckName "Removable Drive Encryption" -Status "Warning" `
                    -Details "Removable drive $($drive.DeviceID) is not encrypted" -Category "StorageEncryption" `
                    -AdditionalInfo @{
                        DriveLetter = $drive.DeviceID
                        DriveType = "Removable"
                        Size = $drive.Size
                        FreeSpace = $drive.FreeSpace
                    }
            }
        }
        
        if ($unencryptedRemovableCount -gt 0) {
            Add-Finding -CheckName "Removable Drive Encryption Summary" -Status "Warning" `
                -Details "Found $unencryptedRemovableCount unencrypted removable drives" -Category "StorageEncryption" `
                -AdditionalInfo @{
                    UnencryptedCount = $unencryptedRemovableCount
                    TotalRemovableDrives = $removableDrives.Count
                }
        }
    }
    catch {
        $errorInfo = Write-ErrorInfo -ErrorRecord $_ -Context "Storage Encryption Analysis"
        Add-Finding -CheckName "Storage Encryption" -Status "Fail" `
            -Details "Failed to check storage encryption: $($_.Exception.Message)" -Category "StorageEncryption" `
            -AdditionalInfo $errorInfo
    }

    # Export results using common function
    if ($OutputPath) {
        Export-ToJson -Data $storageInfo -FilePath $OutputPath
        Write-Output "Results exported to: $OutputPath"
    }

    return $storageInfo
}

# Export the function
Export-ModuleMember -Function Test-StorageEncryption 