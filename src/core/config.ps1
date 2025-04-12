# -----------------------------------------------------------------------------
# Configuration Module
# -----------------------------------------------------------------------------

# Default configuration
$script:DefaultConfig = @{
    Logging = @{
        Level = "Info"
        LogFile = ".\logs\ps_win.log"
        Console = $true
        File = $true
    }
    Security = @{
        ScanPath = $env:SystemDrive
        MaxHistoryEntries = 50
        SeverityLevel = "All"
        IncludeNetworkAnalysis = $true
        IncludeProcessAnalysis = $true
        OutputPath = ".\threat_hunt_results.json"
    }
    Network = @{
        TimeoutSeconds = 30
        IncludePasswords = $false
        CheckWifiProfiles = $true
        CheckNetworkConnections = $true
    }
    Process = @{
        CheckUnsignedDrivers = $true
        CheckSuspiciousServices = $true
        CheckWMIEventSubscriptions = $true
        CheckPrefetchFiles = $true
    }
    System = @{
        CheckEnvironmentVariables = $true
        CheckScheduledTasks = $true
        CheckAMSI = $true
        CheckDLLs = $true
    }
}

# Current configuration
$script:Config = $script:DefaultConfig.Clone()

function Get-Config {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Section,
        
        [Parameter(Mandatory=$false)]
        [string]$Key
    )
    
    if ($Section -and $Key) {
        return $script:Config[$Section][$Key]
    }
    elseif ($Section) {
        return $script:Config[$Section]
    }
    else {
        return $script:Config
    }
}

function Set-Config {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Section,
        
        [Parameter(Mandatory=$true)]
        [string]$Key,
        
        [Parameter(Mandatory=$true)]
        [object]$Value
    )
    
    if (-not $script:Config.ContainsKey($Section)) {
        $script:Config[$Section] = @{}
    }
    
    $script:Config[$Section][$Key] = $Value
    Write-Log -Message "Configuration updated: $Section.$Key = $Value" -Level 'Info' -Category 'Configuration'
}

function Reset-Config {
    [CmdletBinding()]
    param()
    
    $script:Config = $script:DefaultConfig.Clone()
    Write-Log -Message "Configuration reset to defaults" -Level 'Info' -Category 'Configuration'
}

function Save-Config {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = ".\config\settings.json"
    )
    
    $configDir = Split-Path -Parent $Path
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    $script:Config | ConvertTo-Json -Depth 10 | Set-Content -Path $Path
    Write-Log -Message "Configuration saved to: $Path" -Level 'Info' -Category 'Configuration'
}

function Load-Config {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = ".\config\settings.json"
    )
    
    if (Test-Path $Path) {
        $loadedConfig = Get-Content -Path $Path | ConvertFrom-Json -AsHashtable
        $script:Config = $loadedConfig
        Write-Log -Message "Configuration loaded from: $Path" -Level 'Info' -Category 'Configuration'
    }
    else {
        Write-Log -Message "Configuration file not found: $Path" -Level 'Warning' -Category 'Configuration'
    }
}

# Export functions
Export-ModuleMember -Function Get-Config, Set-Config, Reset-Config, Save-Config, Load-Config 