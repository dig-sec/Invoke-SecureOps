# -----------------------------------------------------------------------------
# Invoke-SecureOps Module
# -----------------------------------------------------------------------------

# Import all test modules from the tests directory
Get-ChildItem -Path $PSScriptRoot\tests -Filter "Test-*.ps1" | ForEach-Object {
    . $_.FullName
}

# Set up the iso alias for Invoke-SecurityOperations
Set-Alias -Name iso -Value Invoke-SecurityOperations

# Export all functions that start with "Test-"
Export-ModuleMember -Function Test-* -Alias iso

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

# Export variables
Export-ModuleMember -Variable @(
    'ModuleVersion',
    'ModuleName',
    'ModulePath',
    'TestResults',
    'Findings',
    'OptimizationSettings'
)

# Module initialization message
Write-Host "Invoke-SecureOps Module v$ModuleVersion loaded successfully."
Write-Host "Use 'iso' alias for quick access to security operations." 