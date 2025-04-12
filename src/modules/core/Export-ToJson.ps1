# -----------------------------------------------------------------------------
# JSON Export Module
# -----------------------------------------------------------------------------

function Export-ToJson {
    param (
        [Parameter(Mandatory=$true)]
        [object]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [switch]$Pretty,
        
        [switch]$Append
    )

    try {
        # Convert data to JSON
        $jsonContent = if ($Pretty) {
            $Data | ConvertTo-Json -Depth 10 -Compress:$false
        }
        else {
            $Data | ConvertTo-Json -Depth 10 -Compress:$true
        }

        # Export to file
        if ($Append) {
            $jsonContent | Out-File -FilePath $FilePath -Append
        }
        else {
            $jsonContent | Out-File -FilePath $FilePath
        }

        Write-Output "Data exported to: $FilePath"
    }
    catch {
        Write-Error "Failed to export data to JSON: $_"
        throw
    }
}

# Export the function
Export-ModuleMember -Function Export-ToJson 