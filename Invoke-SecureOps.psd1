@{
    RootModule = 'Invoke-SecureOps.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'Security Team'
    CompanyName = 'Security Team'
    Copyright = '(c) 2025 Security Team. All rights reserved.'
    Description = 'Windows security assessment and remediation toolkit'
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
        'Test-WindowsServices',
        'Test-Template'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module
    AliasesToExport = @('iso')
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Windows', 'Assessment', 'Remediation')
            ProjectUri = 'https://github.com/yourusername/Invoke-SecureOps'
        }
    }
    
    FileList = @(
        'tests\Test-Template.ps1',
        'tests\Test-WindowsServices.ps1'
    )
} 