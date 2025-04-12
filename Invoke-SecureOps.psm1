# -----------------------------------------------------------------------------
# Invoke-SecureOps Module
# -----------------------------------------------------------------------------

# Import helper functions first
. "$PSScriptRoot\src\modules\core\Helpers.ps1"

# Import test framework
Import-Module "$PSScriptRoot\src\tests\SecureOpsTests.psm1" -Force

# Import all test modules
$testFiles = @(
    "$PSScriptRoot\src\tests\Test-SuspiciousConnections.ps1",
    "$PSScriptRoot\src\tests\Test-AMSIBypass.ps1",
    "$PSScriptRoot\src\tests\Test-AuthenticationControls.ps1"
)

foreach ($file in $testFiles) {
    if (Test-Path $file) {
        . $file
    }
    else {
        Write-Warning "Test file not found: $file"
    }
}

# Define module-level variables
$script:ModuleVersion = '2.0.0'
$script:ModuleName = 'Invoke-SecureOps'
$script:ModulePath = $PSScriptRoot

# Initialize module state
$script:TestResults = @{}
$script:Findings = @()

# Export functions
Export-ModuleMember -Function @(
    'Test-SuspiciousConnections',
    'Test-AMSIBypass',
    'Test-AuthenticationControls',
    'Add-Finding',
    'Initialize-TestResult',
    'Export-TestResult'
)

# Export variables
Export-ModuleMember -Variable @(
    'ModuleVersion',
    'ModuleName',
    'ModulePath',
    'TestResults',
    'Findings'
)

# Module initialization message
Write-Host "Invoke-SecureOps Module v$ModuleVersion loaded successfully." 