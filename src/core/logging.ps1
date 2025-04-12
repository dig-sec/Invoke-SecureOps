# -----------------------------------------------------------------------------
# Logging Module
# -----------------------------------------------------------------------------

# Initialize script-level variables
$script:LogLevel = "Info"
$script:LogFile = ".\logs\ps_win.log"
$script:LogToFile = $true
$script:LogToConsole = $true

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory=$false)]
        [string]$Category = "General",
        
        [Parameter(Mandatory=$false)]
        [object]$AdditionalInfo = $null
    )
    
    # Check if we should log this level
    $logLevels = @{
        'Debug' = 0
        'Info' = 1
        'Warning' = 2
        'Error' = 3
    }
    
    if ($logLevels[$Level] -lt $logLevels[$script:LogLevel]) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Category = $Category
        Message = $Message
        AdditionalInfo = $AdditionalInfo
    }
    
    # Format console output
    $consoleMessage = "[$timestamp] [$Level] [$Category] $Message"
    $consoleColor = switch($Level) {
        'Debug' { 'Gray' }
        'Info' { 'White' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        default { 'White' }
    }
    
    # Write to console if enabled
    if ($script:LogToConsole) {
        Write-Host $consoleMessage -ForegroundColor $consoleColor
    }
    
    # Write to file if enabled
    if ($script:LogToFile) {
        $logDir = Split-Path -Parent $script:LogFile
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        $logEntry | ConvertTo-Json -Compress | Add-Content -Path $script:LogFile
    }
    
    return $logEntry
}

function Set-LogLevel {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level
    )
    
    $script:LogLevel = $Level
    Write-Log -Message "Log level set to: $Level" -Level 'Info' -Category 'Logging'
}

function Set-LogFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    $script:LogFile = $Path
    Write-Log -Message "Log file set to: $Path" -Level 'Info' -Category 'Logging'
}

function Enable-Logging {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Console,
        
        [Parameter(Mandatory=$false)]
        [switch]$File
    )
    
    if ($Console) {
        $script:LogToConsole = $true
        Write-Log -Message "Console logging enabled" -Level 'Info' -Category 'Logging'
    }
    
    if ($File) {
        $script:LogToFile = $true
        Write-Log -Message "File logging enabled" -Level 'Info' -Category 'Logging'
    }
}

function Disable-Logging {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Console,
        
        [Parameter(Mandatory=$false)]
        [switch]$File
    )
    
    if ($Console) {
        $script:LogToConsole = $false
        Write-Log -Message "Console logging disabled" -Level 'Info' -Category 'Logging'
    }
    
    if ($File) {
        $script:LogToFile = $false
        Write-Log -Message "File logging disabled" -Level 'Info' -Category 'Logging'
    }
}

# Export functions
Export-ModuleMember -Function Write-Log, Set-LogLevel, Set-LogFile, Enable-Logging, Disable-Logging 