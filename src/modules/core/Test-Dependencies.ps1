# -----------------------------------------------------------------------------
# Test Dependencies Module
# -----------------------------------------------------------------------------

function Test-Dependencies {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$RequiredModules = @(),
        
        [Parameter()]
        [string[]]$RequiredCommands = @(),
        
        [Parameter()]
        [string[]]$RequiredServices = @(),
        
        [Parameter()]
        [hashtable]$RequiredRegistryKeys = @{},
        
        [Parameter()]
        [hashtable]$RequiredFiles = @{},
        
        [Parameter()]
        [switch]$AutoInstall,
        
        [Parameter()]
        [switch]$SkipChecks
    )
    
    $testResult = Initialize-TestResult -TestName "Dependencies Check" `
                                      -Category "System" `
                                      -Description "Checks for required dependencies" `
                                      -RiskLevel "Info"
    
    try {
        Write-Log -Message "Checking test dependencies" -Level 'Info'
        
        # Check PowerShell modules
        foreach ($module in $RequiredModules) {
            $moduleInfo = Get-Module -ListAvailable -Name $module
            if (-not $moduleInfo) {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Missing Module: $module" `
                    -Status "Warning" `
                    -RiskLevel "Medium" `
                    -Description "Required PowerShell module '$module' is not installed" `
                    -TechnicalDetails @{
                        ModuleName = $module
                        AutoInstall = $AutoInstall
                    }
                
                if ($AutoInstall) {
                    try {
                        Install-Module -Name $module -Force -Scope CurrentUser
                        Write-Log -Message "Installed module: $module" -Level 'Info'
                    }
                    catch {
                        Write-Log -Message "Failed to install module $module`: $_" -Level 'Error'
                    }
                }
            }
            else {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Module Check: $module" `
                    -Status "Pass" `
                    -RiskLevel "Info" `
                    -Description "Required PowerShell module '$module' is installed" `
                    -TechnicalDetails @{
                        ModuleName = $module
                        Version = $moduleInfo.Version
                    }
            }
        }
        
        # Check PowerShell commands
        foreach ($command in $RequiredCommands) {
            $cmdInfo = Get-Command -Name $command -ErrorAction SilentlyContinue
            if (-not $cmdInfo) {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Missing Command: $command" `
                    -Status "Warning" `
                    -RiskLevel "Medium" `
                    -Description "Required PowerShell command '$command' is not available" `
                    -TechnicalDetails @{
                        CommandName = $command
                    }
            }
            else {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Command Check: $command" `
                    -Status "Pass" `
                    -RiskLevel "Info" `
                    -Description "Required PowerShell command '$command' is available" `
                    -TechnicalDetails @{
                        CommandName = $command
                        Source = $cmdInfo.Source
                    }
            }
        }
        
        # Check Windows services
        foreach ($service in $RequiredServices) {
            $svcInfo = Get-Service -Name $service -ErrorAction SilentlyContinue
            if (-not $svcInfo) {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Missing Service: $service" `
                    -Status "Warning" `
                    -RiskLevel "Medium" `
                    -Description "Required Windows service '$service' is not installed" `
                    -TechnicalDetails @{
                        ServiceName = $service
                    }
            }
            else {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Service Check: $service" `
                    -Status "Pass" `
                    -RiskLevel "Info" `
                    -Description "Required Windows service '$service' is installed" `
                    -TechnicalDetails @{
                        ServiceName = $service
                        Status = $svcInfo.Status
                        StartType = $svcInfo.StartType
                    }
            }
        }
        
        # Check registry keys
        foreach ($key in $RequiredRegistryKeys.Keys) {
            $keyExists = Test-Path -Path $key
            if (-not $keyExists) {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Missing Registry Key: $key" `
                    -Status "Warning" `
                    -RiskLevel "Medium" `
                    -Description "Required registry key '$key' does not exist" `
                    -TechnicalDetails @{
                        RegistryKey = $key
                        ExpectedValue = $RequiredRegistryKeys[$key]
                    }
            }
            else {
                $keyValue = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Registry Key Check: $key" `
                    -Status "Pass" `
                    -RiskLevel "Info" `
                    -Description "Required registry key '$key' exists" `
                    -TechnicalDetails @{
                        RegistryKey = $key
                        CurrentValue = $keyValue
                        ExpectedValue = $RequiredRegistryKeys[$key]
                    }
            }
        }
        
        # Check files
        foreach ($file in $RequiredFiles.Keys) {
            $fileExists = Test-Path -Path $file
            if (-not $fileExists) {
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "Missing File: $file" `
                    -Status "Warning" `
                    -RiskLevel "Medium" `
                    -Description "Required file '$file' does not exist" `
                    -TechnicalDetails @{
                        FilePath = $file
                        ExpectedHash = $RequiredFiles[$file]
                    }
            }
            else {
                $fileHash = Get-FileHash -Path $file -ErrorAction SilentlyContinue
                $testResult = Add-Finding -TestResult $testResult `
                    -FindingName "File Check: $file" `
                    -Status "Pass" `
                    -RiskLevel "Info" `
                    -Description "Required file '$file' exists" `
                    -TechnicalDetails @{
                        FilePath = $file
                        CurrentHash = $fileHash.Hash
                        ExpectedHash = $RequiredFiles[$file]
                    }
            }
        }
        
        return $testResult
    }
    catch {
        Write-Log -Message "Error checking dependencies: $_" -Level 'Error'
        Add-Finding -TestResult $testResult `
            -FindingName "Dependencies Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error checking dependencies: $_" `
            -TechnicalDetails @{
                ErrorMessage = $_.Exception.Message
                ErrorType = $_.Exception.GetType().FullName
                StackTrace = $_.ScriptStackTrace
            }
        return $testResult
    }
}

# Export the function
Export-ModuleMember -Function Test-Dependencies 