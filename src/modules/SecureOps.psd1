@{
    RootModule = 'SecureOps.psm1'
    ModuleVersion = '1.0.0'
    GUID = '12345678-1234-1234-1234-123456789012'
    Author = 'Security Team'
    CompanyName = 'Security Operations'
    Copyright = '(c) 2025 Security Team. All rights reserved.'
    Description = 'Security Operations and Testing Framework'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Test-Dependencies',
        'Initialize-JsonOutput',
        'Add-Finding',
        'Write-SectionHeader',
        'Write-ErrorInfo',
        'Test-ProcessConnections',
        'Test-SuspiciousConnections',
        'Test-SuspiciousFiles',
        'Test-SuspiciousRegistry',
        'Test-UACStatus',
        'Test-WindowsServices',
        'Add-Evidence',
        'Export-TestResult',
        'Invoke-AllSecurityTests'
    )
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Testing', 'Operations')
            ProjectUri = 'https://github.com/yourusername/Invoke-SecureOps'
        }
    }
} 