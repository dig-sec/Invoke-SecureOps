# Import helper functions
. "$PSScriptRoot\core\Helpers.ps1"

# Import base template
. "$PSScriptRoot\tests\Test-BaseTemplate.ps1"

# Import test modules
. "$PSScriptRoot\core\Test-Dependencies.ps1"
. "$PSScriptRoot\tests\Test-SuspiciousConnections.ps1"
. "$PSScriptRoot\tests\Test-SuspiciousFiles.ps1"
. "$PSScriptRoot\tests\Test-UACStatus.ps1"

# Export all functions
Export-ModuleMember -Function @(
    'Test-Dependencies',
    'Initialize-JsonOutput',
    'Add-Finding',
    'Write-SectionHeader',
    'Write-ErrorInfo',
    'Test-SuspiciousConnections',
    'Test-SuspiciousFiles',
    'Test-UACStatus',
    'Add-Evidence',
    'Export-TestResult',
    'Compare-BaselineData'
) 