# Invoke-SecureOps Module
# Comprehensive Windows Security Assessment and Remediation Toolkit
# Version 2.0.0

# Import helper functions
. "$PSScriptRoot\src\modules\core\Helpers.ps1"

# Import core modules
. "$PSScriptRoot\src\modules\core\Test-BaseTemplate.ps1"
. "$PSScriptRoot\src\modules\core\Test-Dependencies.ps1"
. "$PSScriptRoot\src\modules\core\Test-SecurityIntegration.ps1"
. "$PSScriptRoot\src\modules\core\Optimize-Performance.ps1"
. "$PSScriptRoot\src\modules\core\Repair-SecurityIssues.ps1"

# Import system security modules
. "$PSScriptRoot\src\modules\system\Test-SystemSecurity.ps1"
. "$PSScriptRoot\src\modules\system\Test-OS_EOL.ps1"
. "$PSScriptRoot\src\modules\system\Test-PatchManagement.ps1"
. "$PSScriptRoot\src\modules\system\Test-TimeConfiguration.ps1"

# Import security modules
. "$PSScriptRoot\src\modules\security\Test-PowerShellSecurity.ps1"
. "$PSScriptRoot\src\modules\security\Test-DefenderStatus.ps1"
. "$PSScriptRoot\src\modules\security\Test-CredentialProtection.ps1"
. "$PSScriptRoot\src\modules\security\Test-SuspiciousProcesses.ps1"

# Import network modules
. "$PSScriptRoot\src\modules\network\Test-FirewallStatus.ps1"
. "$PSScriptRoot\src\modules\network\Test-NetworkSecurityProtocols.ps1"

# Import PowerShell modules
. "$PSScriptRoot\src\modules\powerShell\Test-PowerShellLogging.ps1"

# Import storage modules
. "$PSScriptRoot\src\modules\storage\Test-StorageEncryption.ps1"
. "$PSScriptRoot\src\modules\storage\Test-DirectoryPermissions.ps1"

# Define module-level variables
$script:ModuleVersion = '2.0.0'
$script:ModuleName = 'Invoke-SecureOps'
$script:ModulePath = $PSScriptRoot

# Initialize module state
$script:TestResults = @{}
$script:Findings = @()
$script:OptimizationSettings = @{
    EnableParallelProcessing = $true
    MaxConcurrentTests = 4
    CacheResults = $true
    VerboseOutput = $false
}

# Export functions
Export-ModuleMember -Function @(
    # Core Functions
    'Test-Dependencies',
    'Test-SecurityIntegration',
    'Initialize-OptimizationSettings',
    'Start-ParallelSecurityTests',
    'Clear-TestCache',
    'Optimize-FileOperations',
    'Repair-SecurityIssues',
    'Export-TestResult',
    'Initialize-TestResult',
    'Add-TestFinding',
    'Compare-BaselineData',
    'Add-Evidence',
    
    # System Security Functions
    'Test-SystemSecurity',
    'Test-OS_EOL',
    'Test-PatchManagement',
    'Test-TimeConfiguration',
    
    # Security Functions
    'Test-PowerShellSecurity',
    'Test-DefenderStatus',
    'Test-CredentialProtection',
    'Test-SuspiciousProcesses',
    'Test-AuthenticationControls',
    'Test-PowerShellLogging',
    
    # Network Functions
    'Test-FirewallStatus',
    'Test-NetworkSecurityProtocols',
    'Test-NetworkConfiguration',
    'Test-AdvancedNetworkSecurity',
    
    # Storage Functions
    'Test-StorageEncryption',
    'Test-DirectoryPermissions',

    # Helper Functions
    'Write-SectionHeader'
)

# Export aliases
Export-ModuleMember -Alias @(
    'iso',  # Invoke-SecurityOperations
    'rsi',  # Repair-SecurityIssues
    'gsm'   # Get-SecurityMitigations
)

# Export variables
Export-ModuleMember -Variable @(
    'ModuleVersion',
    'ModuleName',
    'ModulePath',
    'TestResults',
    'Findings',
    'OptimizationSettings'
)

# Set up aliases
if (-not (Get-Alias -Name 'iso' -ErrorAction SilentlyContinue)) {
    New-Alias -Name 'iso' -Value 'Invoke-SecurityOperations' -Scope Global
}
if (-not (Get-Alias -Name 'rsi' -ErrorAction SilentlyContinue)) {
    New-Alias -Name 'rsi' -Value 'Repair-SecurityIssues' -Scope Global
}
if (-not (Get-Alias -Name 'gsm' -ErrorAction SilentlyContinue)) {
    New-Alias -Name 'gsm' -Value 'Get-SecurityMitigations' -Scope Global
}

# Module initialization message
Write-Host "Invoke-SecureOps Module v$ModuleVersion loaded successfully."
Write-Host "Use 'iso' alias for quick access to security operations." 