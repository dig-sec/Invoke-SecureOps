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
        'src\modules\core\Helpers.ps1',
        'src\tests\Test-SuspiciousConnections.ps1',
        'src\tests\Test-AMSIBypass.ps1',
        'src\tests\Test-AuthenticationControls.ps1',
        'src\tests\SecureOpsTests.psm1'
    )
    
    # Functions to export from this module
    FunctionsToExport = @(
        'Test-SuspiciousConnections',
        'Test-AMSIBypass',
        'Test-AuthenticationControls',
        'Add-Finding',
        'Initialize-TestResult',
        'Export-TestResult'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Windows', 'Assessment', 'Remediation')
            ProjectUri = 'https://github.com/yourusername/Invoke-SecureOps'
        }
    }
    
    FileList = @(
        'src\tests\Test-SuspiciousConnections.ps1',
        'src\tests\Test-AMSIBypass.ps1',
        'src\tests\Test-AuthenticationControls.ps1',
        'src\tests\SecureOpsTests.psm1',
        'src\modules\core\Helpers.ps1'
    )
} 