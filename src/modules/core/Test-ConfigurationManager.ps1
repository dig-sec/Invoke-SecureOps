# -----------------------------------------------------------------------------
# Security Test Configuration Manager
# -----------------------------------------------------------------------------

# Default configuration
$script:DefaultConfig = @{
    # Test execution settings
    Execution = @{
        MaxParallelJobs = 5
        TimeoutSeconds = 300
        RetryCount = 3
        RetryDelaySeconds = 5
    }
    
    # Output settings
    Output = @{
        Path = ".\results"
        Format = "JSON"
        PrettyPrint = $true
        IncludeMetadata = $true
        TimestampFormat = "yyyy-MM-dd HH:mm:ss"
    }
    
    # Logging settings
    Logging = @{
        Enabled = $true
        Path = ".\logs"
        Level = "Info"
        MaxLogFiles = 10
        MaxLogSizeMB = 10
    }
    
    # Test categories
    Categories = @{
        PowerShellSecurity = @{
            Enabled = $true
            Tags = @("PowerShell", "Security")
            Dependencies = @()
        }
        Defender = @{
            Enabled = $true
            Tags = @("Defender", "Security")
            Dependencies = @()
        }
        CredentialProtection = @{
            Enabled = $true
            Tags = @("Credentials", "Security")
            Dependencies = @()
        }
        Firewall = @{
            Enabled = $true
            Tags = @("Firewall", "Security")
            Dependencies = @()
        }
        SystemSecurity = @{
            Enabled = $true
            Tags = @("System", "Security")
            Dependencies = @()
        }
        StorageSecurity = @{
            Enabled = $true
            Tags = @("Storage", "Security")
            Dependencies = @()
        }
    }
    
    # Risk levels
    RiskLevels = @{
        Critical = @{
            Score = 5
            Color = "Red"
            Description = "Immediate action required"
        }
        High = @{
            Score = 4
            Color = "Orange"
            Description = "Action required soon"
        }
        Medium = @{
            Score = 3
            Color = "Yellow"
            Description = "Action recommended"
        }
        Low = @{
            Score = 2
            Color = "Blue"
            Description = "Action optional"
        }
        Info = @{
            Score = 1
            Color = "Green"
            Description = "Informational only"
        }
    }
    
    # Compliance frameworks
    Compliance = @{
        CIS = @{
            Enabled = $true
            Version = "1.0.0"
            Mapping = @{}
        }
        NIST = @{
            Enabled = $true
            Version = "800-53"
            Mapping = @{}
        }
        ISO27001 = @{
            Enabled = $true
            Version = "2013"
            Mapping = @{}
        }
    }
}

# Function to get configuration
function Get-TestConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Path,
        
        [Parameter()]
        [switch]$Default
    )
    
    if ($Default) {
        return $script:DefaultConfig
    }
    
    if ($Path) {
        if (Test-Path $Path) {
            $config = Get-Content -Path $Path -Raw | ConvertFrom-Json -AsHashtable
            return $config
        }
        else {
            Write-Warning "Configuration file not found at: $Path"
            return $script:DefaultConfig
        }
    }
    
    return $script:DefaultConfig
}

# Function to set configuration
function Set-TestConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Configuration,
        
        [Parameter()]
        [string]$Path
    )
    
    # Merge with default configuration
    $mergedConfig = $script:DefaultConfig.Clone()
    foreach ($key in $Configuration.Keys) {
        if ($mergedConfig.ContainsKey($key)) {
            if ($mergedConfig[$key] -is [hashtable] -and $Configuration[$key] -is [hashtable]) {
                foreach ($subKey in $Configuration[$key].Keys) {
                    $mergedConfig[$key][$subKey] = $Configuration[$key][$subKey]
                }
            }
            else {
                $mergedConfig[$key] = $Configuration[$key]
            }
        }
        else {
            $mergedConfig[$key] = $Configuration[$key]
        }
    }
    
    # Save to file if path provided
    if ($Path) {
        $mergedConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $Path
    }
    
    return $mergedConfig
}

# Function to validate configuration
function Test-TestConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )
    
    $errors = @()
    
    # Validate execution settings
    if ($Configuration.Execution.MaxParallelJobs -lt 1) {
        $errors += "MaxParallelJobs must be greater than 0"
    }
    if ($Configuration.Execution.TimeoutSeconds -lt 1) {
        $errors += "TimeoutSeconds must be greater than 0"
    }
    if ($Configuration.Execution.RetryCount -lt 0) {
        $errors += "RetryCount must be greater than or equal to 0"
    }
    if ($Configuration.Execution.RetryDelaySeconds -lt 0) {
        $errors += "RetryDelaySeconds must be greater than or equal to 0"
    }
    
    # Validate output settings
    if (-not $Configuration.Output.Path) {
        $errors += "Output path must be specified"
    }
    if ($Configuration.Output.Format -notin @("JSON", "XML", "CSV")) {
        $errors += "Output format must be JSON, XML, or CSV"
    }
    
    # Validate logging settings
    if ($Configuration.Logging.Enabled) {
        if (-not $Configuration.Logging.Path) {
            $errors += "Log path must be specified when logging is enabled"
        }
        if ($Configuration.Logging.Level -notin @("Debug", "Info", "Warning", "Error")) {
            $errors += "Log level must be Debug, Info, Warning, or Error"
        }
        if ($Configuration.Logging.MaxLogFiles -lt 1) {
            $errors += "MaxLogFiles must be greater than 0"
        }
        if ($Configuration.Logging.MaxLogSizeMB -lt 1) {
            $errors += "MaxLogSizeMB must be greater than 0"
        }
    }
    
    # Validate categories
    foreach ($category in $Configuration.Categories.Keys) {
        if (-not $Configuration.Categories[$category].ContainsKey("Enabled")) {
            $errors += "Category $category must have Enabled property"
        }
        if (-not $Configuration.Categories[$category].ContainsKey("Tags")) {
            $errors += "Category $category must have Tags property"
        }
        if (-not $Configuration.Categories[$category].ContainsKey("Dependencies")) {
            $errors += "Category $category must have Dependencies property"
        }
    }
    
    # Validate risk levels
    foreach ($level in $Configuration.RiskLevels.Keys) {
        if (-not $Configuration.RiskLevels[$level].ContainsKey("Score")) {
            $errors += "Risk level $level must have Score property"
        }
        if (-not $Configuration.RiskLevels[$level].ContainsKey("Color")) {
            $errors += "Risk level $level must have Color property"
        }
        if (-not $Configuration.RiskLevels[$level].ContainsKey("Description")) {
            $errors += "Risk level $level must have Description property"
        }
    }
    
    # Validate compliance frameworks
    foreach ($framework in $Configuration.Compliance.Keys) {
        if (-not $Configuration.Compliance[$framework].ContainsKey("Enabled")) {
            $errors += "Compliance framework $framework must have Enabled property"
        }
        if (-not $Configuration.Compliance[$framework].ContainsKey("Version")) {
            $errors += "Compliance framework $framework must have Version property"
        }
        if (-not $Configuration.Compliance[$framework].ContainsKey("Mapping")) {
            $errors += "Compliance framework $framework must have Mapping property"
        }
    }
    
    return @{
        IsValid = $errors.Count -eq 0
        Errors = $errors
    }
}

# Function to reset configuration to defaults
function Reset-TestConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Path
    )
    
    if ($Path) {
        $script:DefaultConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $Path
    }
    
    return $script:DefaultConfig
}

# Export functions
Export-ModuleMember -Function Get-TestConfiguration,
                              Set-TestConfiguration,
                              Test-TestConfiguration,
                              Reset-TestConfiguration 