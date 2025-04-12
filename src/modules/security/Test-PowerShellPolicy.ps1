# -----------------------------------------------------------------------------
# PowerShell Execution Policy Check
# -----------------------------------------------------------------------------

function Test-PowerShellPolicy {
    Write-SectionHeader "PowerShell Execution Policy Check"
    Write-Output "Checking PowerShell execution policy settings..."

    try {
        # Get current execution policy
        $currentPolicy = Get-ExecutionPolicy -ErrorAction Stop
        $currentPolicyList = Get-ExecutionPolicy -List -ErrorAction Stop

        # Check current execution policy
        switch ($currentPolicy) {
            "Restricted" {
                Add-Finding -CheckName "Current Execution Policy" -Status "Pass" -Details "Execution policy is set to Restricted (most secure)"
            }
            "AllSigned" {
                Add-Finding -CheckName "Current Execution Policy" -Status "Pass" -Details "Execution policy is set to AllSigned (requires scripts to be signed by a trusted publisher)"
            }
            "RemoteSigned" {
                Add-Finding -CheckName "Current Execution Policy" -Status "Warning" -Details "Execution policy is set to RemoteSigned (local scripts can run unsigned)"
            }
            "Unrestricted" {
                Add-Finding -CheckName "Current Execution Policy" -Status "Fail" -Details "Execution policy is set to Unrestricted (least secure)"
            }
            "Bypass" {
                Add-Finding -CheckName "Current Execution Policy" -Status "Fail" -Details "Execution policy is set to Bypass (no restrictions)"
            }
            default {
                Add-Finding -CheckName "Current Execution Policy" -Status "Warning" -Details "Unknown execution policy: ${currentPolicy}"
            }
        }

        # Check execution policy for different scopes
        foreach ($scope in $currentPolicyList) {
            $scopeName = $scope.Scope
            $scopePolicy = $scope.ExecutionPolicy

            switch ($scopePolicy) {
                "Restricted" {
                    Add-Finding -CheckName "Execution Policy - $scopeName" -Status "Pass" -Details "Execution policy for $scopeName is set to Restricted"
                }
                "AllSigned" {
                    Add-Finding -CheckName "Execution Policy - $scopeName" -Status "Pass" -Details "Execution policy for $scopeName is set to AllSigned"
                }
                "RemoteSigned" {
                    Add-Finding -CheckName "Execution Policy - $scopeName" -Status "Warning" -Details "Execution policy for $scopeName is set to RemoteSigned"
                }
                "Unrestricted" {
                    Add-Finding -CheckName "Execution Policy - $scopeName" -Status "Fail" -Details "Execution policy for $scopeName is set to Unrestricted"
                }
                "Bypass" {
                    Add-Finding -CheckName "Execution Policy - $scopeName" -Status "Fail" -Details "Execution policy for $scopeName is set to Bypass"
                }
                default {
                    Add-Finding -CheckName "Execution Policy - $scopeName" -Status "Warning" -Details "Unknown execution policy for $scopeName: ${scopePolicy}"
                }
            }
        }

        # Check for script block logging
        $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
            Add-Finding -CheckName "Script Block Logging" -Status "Pass" -Details "Script block logging is enabled"
        } else {
            Add-Finding -CheckName "Script Block Logging" -Status "Warning" -Details "Script block logging is not enabled"
        }

        # Check for transcription settings
        $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
        if ($transcription -and $transcription.EnableTranscripting -eq 1) {
            Add-Finding -CheckName "PowerShell Transcription" -Status "Pass" -Details "PowerShell transcription is enabled"
        } else {
            Add-Finding -CheckName "PowerShell Transcription" -Status "Warning" -Details "PowerShell transcription is not enabled"
        }
    }
    catch {
        Write-Error "Error checking PowerShell execution policy: $($_.Exception.Message)"
        Add-Finding -CheckName "PowerShell Policy" -Status "Error" -Details "Failed to check PowerShell execution policy: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function Test-PowerShellPolicy 