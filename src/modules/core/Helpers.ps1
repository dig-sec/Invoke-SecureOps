function Write-SectionHeader {
    param(
        [string]$Title,
        [string]$Subtitle = ""
    )
    
    Write-Host "`n# -----------------------------------------------------------------------------"
    Write-Host "# $Title"
    if ($Subtitle) {
        Write-Host "# $Subtitle"
    }
    Write-Host "# -----------------------------------------------------------------------------`n"
}

Export-ModuleMember -Function Write-SectionHeader 