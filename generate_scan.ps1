# -----------------------------------------------------------------------------
# Scan Generator
# -----------------------------------------------------------------------------

param (
    [switch]$Verbose,
    [switch]$ConvertTests
)

# Get the script directory
$scriptDir = $PSScriptRoot

# Function to convert a test function to the standalone format
function Convert-TestToStandalone {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TestName,
        
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $false)]
        [string]$RiskLevel = "Medium",
        
        [Parameter(Mandatory = $false)]
        [string]$ActionLevel = "Review"
    )
    
    Write-Output "Converting test: $TestName"
    
    # Create the output directory if it doesn't exist
    $outputDir = Join-Path $scriptDir "src\modules\$Category"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    # Create the output file
    $outputFile = Join-Path $outputDir "$TestName.ps1"
    
    # Read the template
    $templatePath = Join-Path $scriptDir "src\modules\core\Test-StandardTemplate.ps1"
    $template = Get-Content -Path $templatePath -Raw
    
    # Replace the template function name with the actual test name
    $template = $template -replace "function Test-StandardTemplate", "function $TestName"
    $template = $template -replace "Test-StandardTemplate", $TestName
    $template = $template -replace "Category = `"Standard`"", "Category = `"$Category`""
    $template = $template -replace "RiskLevel = `"Medium`"", "RiskLevel = `"$RiskLevel`""
    $template = $template -replace "ActionLevel = `"Review`"", "ActionLevel = `"$ActionLevel`""
    
    # Write the template to the output file
    $template | Out-File -FilePath $outputFile -Force
    
    Write-Output "Created standalone test: $outputFile"
}

# Run the collection script
Write-Output "Running collection script..."
& "$scriptDir\collection.ps1" -OutputFile "$scriptDir\scan.ps1" -Verbose:$Verbose

# Check if the scan.ps1 file was created
if (Test-Path "$scriptDir\scan.ps1") {
    Write-Output "`nScan script generated successfully: $scriptDir\scan.ps1"
    Write-Output "You can now run the scan with: .\scan.ps1 -Verbose"
}
else {
    Write-Error "Failed to generate scan.ps1 file"
}

# Convert tests if requested
if ($ConvertTests) {
    Write-Output "`nConverting tests to standalone format..."
    
    # Define tests to convert
    $testsToConvert = @(
        @{Name = "Test-PowerShellSecurity"; Category = "PowerShell"; RiskLevel = "High"; ActionLevel = "Review"},
        @{Name = "Test-DefenderStatus"; Category = "Security"; RiskLevel = "High"; ActionLevel = "Review"},
        @{Name = "Test-CredentialProtection"; Category = "Security"; RiskLevel = "High"; ActionLevel = "Review"},
        @{Name = "Test-SuspiciousProcesses"; Category = "Security"; RiskLevel = "High"; ActionLevel = "Review"},
        @{Name = "Test-FirewallStatus"; Category = "Network"; RiskLevel = "High"; ActionLevel = "Review"},
        @{Name = "Test-UACStatus"; Category = "Security"; RiskLevel = "High"; ActionLevel = "Review"},
        @{Name = "Test-NetworkSecurityProtocols"; Category = "Network"; RiskLevel = "Medium"; ActionLevel = "Review"},
        @{Name = "Test-WindowsServices"; Category = "System"; RiskLevel = "Medium"; ActionLevel = "Review"}
    )
    
    foreach ($test in $testsToConvert) {
        Convert-TestToStandalone -TestName $test.Name -Category $test.Category -RiskLevel $test.RiskLevel -ActionLevel $test.ActionLevel
    }
    
    Write-Output "`nTest conversion complete. You can now update the individual test files with their specific implementation."
} 