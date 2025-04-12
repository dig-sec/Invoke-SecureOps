# -----------------------------------------------------------------------------
# Windows Security Assessment Module
# -----------------------------------------------------------------------------

# Import required modules
$modulePath = $PSScriptRoot
$srcPath = Join-Path $modulePath "src"

# Import core modules
Get-ChildItem -Path (Join-Path $srcPath "modules\core") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import security modules
Get-ChildItem -Path (Join-Path $srcPath "modules\security") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import system modules
Get-ChildItem -Path (Join-Path $srcPath "modules\system") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import network modules
Get-ChildItem -Path (Join-Path $srcPath "modules\network") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import PowerShell modules
Get-ChildItem -Path (Join-Path $srcPath "modules\powerShell") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import storage modules
Get-ChildItem -Path (Join-Path $srcPath "modules\storage") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import mitigations modules
Get-ChildItem -Path (Join-Path $srcPath "modules\mitigations") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import helper functions
Get-ChildItem -Path (Join-Path $modulePath "functions") -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Create aliases
Set-Alias -Name 'tsi' -Value 'Test-SecurityIntegration'
Set-Alias -Name 'rsi' -Value 'Repair-SecurityIssues'
Set-Alias -Name 'gsm' -Value 'Get-SecurityMitigations'

# Export functions
Export-ModuleMember -Function @(
    # Core functions
    'Test-Dependencies',
    'Test-SecurityIntegration',
    'Repair-SecurityIssues',
    
    # Security functions
    'Test-DefenderStatus',
    'Test-CredentialProtection',
    'Test-PowerShellSecurity',
    'Test-SuspiciousProcesses',
    
    # System functions
    'Test-OS_EOL',
    'Test-PatchManagement',
    'Test-TimeConfiguration',
    
    # Network functions
    'Test-NetworkConfiguration',
    'Test-AdvancedNetworkSecurity',
    
    # PowerShell functions
    'Test-PowerShellHistory',
    
    # Storage functions
    'Test-StorageEncryption',
    'Test-DirectoryPermissions',
    
    # Mitigation functions
    'Get-SecurityMitigations'
)

# Export variables
Export-ModuleMember -Variable @(
    'assessmentInfo',
    'findings'
)

# Export aliases
Export-ModuleMember -Alias @(
    'tsi',
    'rsi',
    'gsm'
)

# Initialize findings array
$script:Findings = @()

function Add-Finding {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CheckName,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Error')]
        [string]$Status,
        
        [Parameter(Mandatory=$false)]
        [string]$Details,
        
        [Parameter(Mandatory=$false)]
        [string]$Category = "Security",
        
        [Parameter(Mandatory=$false)]
        [object]$AdditionalInfo
    )
    
    $finding = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CheckName = $CheckName
        Status = $Status
        Details = $Details
        Category = $Category
        AdditionalInfo = $AdditionalInfo
    }
    
    $script:Findings += $finding
    
    # Output finding with color coding
    switch ($Status) {
        'Pass' { Write-Host "[PASS] $CheckName" -ForegroundColor Green }
        'Fail' { Write-Host "[FAIL] $CheckName" -ForegroundColor Red }
        'Warning' { Write-Host "[WARN] $CheckName" -ForegroundColor Yellow }
        'Info' { Write-Host "[INFO] $CheckName" -ForegroundColor Cyan }
        'Error' { Write-Host "[ERROR] $CheckName" -ForegroundColor Magenta }
    }
    
    if ($Details) {
        Write-Host "  $Details" -ForegroundColor Gray
    }
}

function Write-SectionHeader {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Title
    )
    
    Write-Output "`n============================================="
    Write-Output " $Title"
    Write-Output "=============================================`n"
}

function Start-SecurityAssessment {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = ".\security_assessment.json",
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeNetworkAnalysis = $true,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeProcessAnalysis = $true
    )
    
    Write-SectionHeader "Windows Security Assessment"
    Write-Output "Starting assessment on $env:COMPUTERNAME at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    
    # System Enumeration
    Get-SystemInformation
    
    # Security Checks
    Test-OS_EOL
    Test-AntivirusStatus
    Test-CredentialProtection
    Test-AuthenticationControls
    Test-PowerShellSecurity
    Test-PowerShellHistory
    Test-StorageEncryption
    Test-DirectoryPermissions
    
    if ($IncludeNetworkAnalysis) {
        Test-NetworkConfiguration
        Test-AdvancedNetworkSecurity
    }
    
    # Export findings
    $assessmentResults = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $env:COMPUTERNAME
        Findings = $script:Findings
    }
    
    $assessmentResults | ConvertTo-Json -Depth 10 | Out-File $OutputPath
    Write-Output "`nAssessment complete. Results exported to $OutputPath"
}

Export-ModuleMember -Function Start-SecurityAssessment, Add-Finding, Write-SectionHeader 