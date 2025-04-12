function Test-SuspiciousConnections {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput,
        
        [Parameter()]
        [switch]$DetailedAnalysis,
        
        [Parameter()]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$CollectEvidence
    )
    
    $result = Initialize-TestResult -TestName "Test-SuspiciousConnections" `
                                  -Category "Security" `
                                  -Description "Analyzes network connections for suspicious activity" `
                                  -Status "Info" `
                                  -RiskLevel "Info"
    
    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop
        $suspiciousPorts = @(4444, 666, 1337, 31337)
        $suspiciousConnections = $connections | Where-Object { $_.RemotePort -in $suspiciousPorts }

        foreach ($conn in $suspiciousConnections) {
            Add-Finding -TestResult $result `
                -FindingName "Suspicious Port Connection" `
                -Status "Warning" `
                -RiskLevel "Medium" `
                -Description "Connection detected on suspicious port $($conn.RemotePort)" `
                -TechnicalDetails @{
                    LocalAddress   = $conn.LocalAddress
                    LocalPort      = $conn.LocalPort
                    RemoteAddress  = $conn.RemoteAddress
                    RemotePort     = $conn.RemotePort
                    State          = $conn.State
                    ProcessId      = $conn.OwningProcess
                    Recommendation = "Investigate the process using this connection"
                }

            if ($CollectEvidence) {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($process) {
                    $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($process.Id)").CommandLine
                    Add-Evidence -TestResult $result `
                        -FindingName "Suspicious Port Connection" `
                        -EvidenceType "Process" `
                        -EvidenceData @{
                            ProcessName = $process.Name
                            ProcessId   = $process.Id
                            Path        = $process.Path
                            CommandLine = $cmdLine
                        } `
                        -Description "Process details for suspicious connection"
                }
            }
        }

        # Malicious IPs with optional CIDR support
        $maliciousIPs = @("185.147.128.0/24", "192.168.1.100")

        foreach ($conn in $connections) {
            foreach ($ip in $maliciousIPs) {
                if (Test-IpMatch -IPAddress $conn.RemoteAddress -CIDR $ip) {
                    Add-Finding -TestResult $result `
                        -FindingName "Malicious IP Connection" `
                        -Status "Critical" `
                        -RiskLevel "Critical" `
                        -Description "Connection detected to known malicious IP $($conn.RemoteAddress)" `
                        -TechnicalDetails @{
                            LocalAddress   = $conn.LocalAddress
                            LocalPort      = $conn.LocalPort
                            RemoteAddress  = $conn.RemoteAddress
                            RemotePort     = $conn.RemotePort
                            State          = $conn.State
                            ProcessId      = $conn.OwningProcess
                            Recommendation = "Immediately investigate and terminate this connection"
                        }
                    break
                }
            }
        }

        if ($OutputPath) {
            Export-TestResult -TestResult $result -OutputPath $OutputPath -PrettyOutput:$PrettyOutput
        }

        return $result
    }
    catch {
        Write-Error "Error during suspicious connections test: $_"
        Add-Finding -TestResult $result `
            -FindingName "Test Error" `
            -Status "Error" `
            -RiskLevel "High" `
            -Description "Error during suspicious connections test: $_" `
            -TechnicalDetails @{ Recommendation = "Check system permissions and network access" }
        return $result
    }
}

# Helper: Checks if an IP matches a CIDR block
function Test-IpMatch {
    param (
        [Parameter(Mandatory=$true)][string]$IPAddress,
        [Parameter(Mandatory=$true)][string]$CIDR
    )
    
    try {
        if ($CIDR -notmatch "/") {
            return $IPAddress -eq $CIDR
        }

        $parts = $CIDR.Split("/")
        $baseIP = [System.Net.IPAddress]::Parse($parts[0])
        $maskBits = [int]$parts[1]

        $ipBytes = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
        $baseBytes = $baseIP.GetAddressBytes()

        $bitCount = [Math]::Ceiling($maskBits / 8)
        for ($i = 0; $i -lt $bitCount; $i++) {
            $shift = 8 - [Math]::Min(8, $maskBits - ($i * 8))
            if (($ipBytes[$i] -bxor $baseBytes[$i]) -shr $shift) {
                return $false
            }
        }
        return $true
    }
    catch {
        return $false
    }
}

Export-ModuleMember -Function Test-SuspiciousConnections
