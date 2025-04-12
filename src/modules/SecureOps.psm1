# -----------------------------------------------------------------------------
# SecureOps Module
# -----------------------------------------------------------------------------

# Import core functions
$corePath = Join-Path $PSScriptRoot "core"
$testPath = Join-Path $PSScriptRoot "..\tests"

# Import core modules
Get-ChildItem -Path $corePath -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import test modules
Get-ChildItem -Path $testPath -Filter "Test-*.ps1" | ForEach-Object {
    . $_.FullName
}

# Export functions
Export-ModuleMember -Function @(
    # Core Functions
    'Initialize-TestResult',
    'Add-Finding',
    'Add-Evidence',
    'Export-TestResult',
    'Write-Log',
    'Test-Dependencies',
    'Invoke-AllSecurityTests',
    
    # Test Functions
    'Test-AMSIBypass',
    'Test-AdvancedNetworkSecurity',
    'Test-AntivirusStatus',
    'Test-AuthenticationControls',
    'Test-CommandHistory',
    'Test-CredentialProtection',
    'Test-DefenderExclusions',
    'Test-DefenderStatus',
    'Test-DependencyManager',
    'Test-DirectoryPermissions',
    'Test-ExecutionManager',
    'Test-FirewallStatus',
    'Test-NetworkAdaptersAndFirewall',
    'Test-NetworkConfiguration',
    'Test-NetworkConnections',
    'Test-NetworkSecurity',
    'Test-NetworkSecurityProtocols',
    'Test-OS_EOL',
    'Test-PatchManagement',
    'Test-PatchStatus',
    'Test-PowerShellHistory',
    'Test-PowerShellLogging',
    'Test-PowerShellSecurity',
    'Test-ProcessConnections',
    'Test-Registry',
    'Test-ResultManager',
    'Test-SecurityIntegration',
    'Test-StartupItems',
    'Test-StorageEncryption',
    'Test-SuspiciousConnections',
    'Test-SuspiciousFiles',
    'Test-SuspiciousProcesses',
    'Test-SuspiciousRegistry',
    'Test-SystemProcesses',
    'Test-SystemSecurity',
    'Test-SystemServices',
    'Test-TimeConfiguration',
    'Test-UACStatus',
    'Test-WiFiSecurity',
    'Test-WindowsServices'
) 