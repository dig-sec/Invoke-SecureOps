# -----------------------------------------------------------------------------
# Invoke-SecureOps Module
# -----------------------------------------------------------------------------

# Import helper functions
$script:ModuleRoot = $PSScriptRoot
$script:HelpersPath = Join-Path $ModuleRoot "core\Helpers.ps1"
. $script:HelpersPath

# Define test files
$script:TestFiles = @(
    "Test-AdvancedNetworkSecurity.ps1",
    "Test-AMSIBypass.ps1",
    "Test-AntivirusStatus.ps1",
    "Test-AuthenticationControls.ps1",
    "Test-CommandHistory.ps1",
    "Test-CredentialProtection.ps1",
    "Test-DefenderExclusions.ps1",
    "Test-DefenderStatus.ps1",
    "Test-DependencyManager.ps1",
    "Test-DirectoryPermissions.ps1",
    "Test-ExecutionManager.ps1",
    "Test-FirewallStatus.ps1",
    "Test-NetworkAdaptersAndFirewall.ps1",
    "Test-NetworkConfiguration.ps1",
    "Test-NetworkConnections.ps1",
    "Test-NetworkSecurity.ps1",
    "Test-NetworkSecurityProtocols.ps1",
    "Test-OS_EOL.ps1",
    "Test-PatchManagement.ps1",
    "Test-PatchStatus.ps1",
    "Test-PowerShellHistory.ps1",
    "Test-PowerShellLogging.ps1",
    "Test-PowerShellSecurity.ps1",
    "Test-ProcessConnections.ps1",
    "Test-Registry.ps1",
    "Test-ResultManager.ps1",
    "Test-SecurityIntegration.ps1",
    "Test-StartupItems.ps1",
    "Test-StorageEncryption.ps1",
    "Test-SuspiciousConnections.ps1",
    "Test-SuspiciousFiles.ps1",
    "Test-SuspiciousProcesses.ps1",
    "Test-SuspiciousRegistry.ps1",
    "Test-SystemProcesses.ps1",
    "Test-SystemSecurity.ps1",
    "Test-SystemServices.ps1",
    "Test-TimeConfiguration.ps1",
    "Test-UACStatus.ps1",
    "Test-WiFiSecurity.ps1",
    "Test-WindowsServices.ps1"
)

# Initialize module state
$script:TestResults = @{}
$script:Findings = @{}

function Import-TestModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestFile
    )
    
    try {
        Write-Log -Message "Importing test module: $TestFile" -Level Debug
        
        # Update path to look in src/tests instead of src/modules/tests
        $testPath = Join-Path (Split-Path $ModuleRoot -Parent) "tests\$TestFile"
        Write-Log -Message "Test module path: $testPath" -Level Debug
        
        if (-not (Test-Path $testPath)) {
            throw "Test file not found: $testPath"
        }
        
        Write-Log -Message "Dot-sourcing test module: $testPath" -Level Debug
        
        # Create a new scope for the test module
        $script:TestModuleScope = New-Module -ScriptBlock {
            param($Path)
            . $Path
            Export-ModuleMember -Function *
        } -ArgumentList $testPath
        
        Import-Module $script:TestModuleScope -Force
        
        Write-Log -Message "Successfully imported test module: $TestFile" -Level Debug
    }
    catch {
        Write-Log -Message "Failed to import test module $TestFile : $_" -Level Error
        throw
    }
}

function Invoke-SecurityTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName,
        
        [Parameter()]
        [hashtable]$Parameters = @{}
    )
    
    try {
        Write-Log -Message "Starting security test: $TestName" -Level Info
        
        # Find and import the test module
        $testFile = $script:TestFiles | Where-Object { $_ -like "*$TestName*" }
        if (-not $testFile) {
            throw "Test module not found for: $TestName"
        }
        
        Import-TestModule -TestFile $testFile
        
        # Initialize test result
        $testResult = Initialize-TestResult -TestName $TestName
        
        # Invoke the test function
        $testFunction = "Test-$TestName"
        Write-Log -Message "Looking for test function: $testFunction" -Level Debug
        
        if (Get-Command $testFunction -ErrorAction SilentlyContinue) {
            Write-Log -Message "Found test function: $testFunction" -Level Debug
            # Add TestResult to the parameters hashtable
            $Parameters['TestResult'] = $testResult
            & $testFunction @Parameters
        }
        else {
            throw "Test function not found: $testFunction"
        }
        
        # Store the result
        $script:TestResults[$TestName] = $testResult
        
        Write-Log -Message "Completed security test: $TestName" -Level Info
        return $testResult
    }
    catch {
        Write-Log -Message "Error in security test $TestName : $_" -Level Error
        throw
    }
}

function Get-SecurityTestResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName
    )
    
    try {
        Write-Log -Message "Retrieving test result for: $TestName" -Level Debug
        
        if ($script:TestResults.ContainsKey($TestName)) {
            return $script:TestResults[$TestName]
        }
        else {
            throw "No test result found for: $TestName"
        }
    }
    catch {
        Write-Log -Message "Error retrieving test result: $_" -Level Error
        throw
    }
}

function Get-AllSecurityTestResults {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Message "Retrieving all test results" -Level Debug
        return $script:TestResults
    }
    catch {
        Write-Log -Message "Error retrieving all test results: $_" -Level Error
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Invoke-SecurityTest',
    'Get-SecurityTestResult',
    'Get-AllSecurityTestResults',
    'Test-StartupItems',
    'Test-AMSIBypass',
    'Test-AuthenticationControls',
    'Test-SuspiciousConnections'
) 