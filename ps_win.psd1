@{
    RootModule = 'ps_win.psm1'
    ModuleVersion = '1.1.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'Security Team'
    CompanyName = 'Your Company'
    Copyright = '(c) 2024 Your Company. All rights reserved.'
    Description = 'Windows Security Assessment and Remediation Toolkit'
    PowerShellVersion = '5.1'
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'src\modules\core\Test-Dependencies.ps1',
        'src\modules\core\Test-SecurityIntegration.ps1',
        'src\modules\core\Optimize-Performance.ps1',
        'src\modules\core\Repair-SecurityIssues.ps1',
        'src\modules\system\Test-SystemSecurity.ps1',
        'src\modules\security\Test-PowerShellSecurity.ps1',
        'src\modules\security\Test-DefenderStatus.ps1',
        'src\modules\security\Test-CredentialProtection.ps1',
        'src\modules\security\Test-SuspiciousProcesses.ps1',
        'src\modules\network\Test-FirewallStatus.ps1',
        'src\modules\network\Test-NetworkSecurityProtocols.ps1',
        'src\modules\powerShell\Test-PowerShellLogging.ps1',
        'src\modules\storage\Test-StorageEncryption.ps1'
    )
    
    # Functions to export from this module
    FunctionsToExport = @(
        # Core Functions
        'Test-Dependencies',
        'Test-SecurityIntegration',
        'Initialize-OptimizationSettings',
        'Start-ParallelSecurityTests',
        'Clear-TestCache',
        'Optimize-FileOperations',
        'Repair-SecurityIssues',
        
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
        'Test-DirectoryPermissions'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module
    AliasesToExport = @(
        'tsi',  # Test-SecurityIntegration
        'rsi'   # Repair-SecurityIssues
    )
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Assessment', 'Windows', 'Remediation', 'Integration')
            ProjectUri = 'https://github.com/yourusername/ps_win'
            ReleaseNotes = @'
Version 1.1.0:
- Added automated remediation capabilities
- Added performance optimization through parallel processing
- Added result caching mechanism
- Added comprehensive integration testing
- Improved error handling and reporting
- Added support for dependency management
'@
        }
    }
} 