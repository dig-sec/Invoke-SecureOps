@{
    RootModule = 'SecureOps.psm1'
    ModuleVersion = '1.0.0'
    GUID = '12345678-1234-1234-1234-123456789012'
    Author = 'SecureOps Team'
    CompanyName = 'SecureOps'
    Copyright = '(c) 2024 SecureOps. All rights reserved.'
    Description = 'Security testing and assessment framework'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
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
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Testing', 'Assessment')
            ProjectUri = 'https://github.com/SecureOps/Invoke-SecureOps'
        }
    }
} 