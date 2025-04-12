# -----------------------------------------------------------------------------
# WiFi Security Analysis Module
# -----------------------------------------------------------------------------

function Test-WiFiSecurity {
    param (
        [string]$OutputPath = ".\wifi_security.json"
    )

    Write-SectionHeader "WiFi Security Analysis"
    Write-Output "Analyzing WiFi security settings..."

    # Initialize JSON output object
    $wifiInfo = Initialize-JsonOutput -Category "WiFiSecurity" -RiskLevel "Medium" -ActionLevel "Review"
    $wifiInfo.TotalProfiles = 0
    $wifiInfo.SecureProfiles = 0
    $wifiInfo.InsecureProfiles = @()
    $wifiInfo.ConnectedNetworks = @()

    # Get all WiFi profiles
    $profiles = netsh wlan show profiles | Select-String "All User Profile\s+: (.*)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
    $wifiInfo.TotalProfiles = $profiles.Count

    # Analyze each profile
    foreach ($profile in $profiles) {
        $profileInfo = netsh wlan show profile name="$profile" key=clear | Select-String -Pattern "Authentication|Cipher|Key Content|SSID|Signal|Radio type|Channel|Network type|Security"
        
        $profileData = @{
            SSID = $profile
            Authentication = ($profileInfo | Where-Object { $_ -match "Authentication" }).ToString().Split(":")[1].Trim()
            Cipher = ($profileInfo | Where-Object { $_ -match "Cipher" }).ToString().Split(":")[1].Trim()
            Security = ($profileInfo | Where-Object { $_ -match "Security" }).ToString().Split(":")[1].Trim()
            Signal = ($profileInfo | Where-Object { $_ -match "Signal" }).ToString().Split(":")[1].Trim()
            Channel = ($profileInfo | Where-Object { $_ -match "Channel" }).ToString().Split(":")[1].Trim()
            NetworkType = ($profileInfo | Where-Object { $_ -match "Network type" }).ToString().Split(":")[1].Trim()
        }

        # Check security status
        $isSecure = $true
        $securityIssues = @()

        # Check authentication
        if ($profileData.Authentication -notmatch "WPA2|WPA3") {
            $isSecure = $false
            $securityIssues += "Weak authentication method: $($profileData.Authentication)"
        }

        # Check cipher
        if ($profileData.Cipher -notmatch "CCMP|GCMP") {
            $isSecure = $false
            $securityIssues += "Weak cipher: $($profileData.Cipher)"
        }

        # Check security
        if ($profileData.Security -notmatch "WPA2|WPA3") {
            $isSecure = $false
            $securityIssues += "Weak security protocol: $($profileData.Security)"
        }

        if ($isSecure) {
            $wifiInfo.SecureProfiles++
        }
        else {
            $wifiInfo.InsecureProfiles += @{
                SSID = $profile
                Issues = $securityIssues
                Details = $profileData
            }
        }

        # Check if currently connected
        $connected = netsh wlan show interfaces | Select-String "SSID\s+: $profile"
        if ($connected) {
            $wifiInfo.ConnectedNetworks += $profileData
        }
    }

    # Export results to JSON
    Export-ToJson -Data $wifiInfo -FilePath $OutputPath -Pretty

    # Add findings
    Add-Finding -CheckName "WiFi Security Analysis" -Status "Info" -Details "Analyzed $($wifiInfo.TotalProfiles) WiFi profiles" -Category "Network"
    
    if ($wifiInfo.InsecureProfiles.Count -gt 0) {
        Add-Finding -CheckName "Insecure WiFi Profiles" -Status "Warning" -Details "Found $($wifiInfo.InsecureProfiles.Count) insecure WiFi profiles" -Category "Network"
    }
    else {
        Add-Finding -CheckName "WiFi Security" -Status "Pass" -Details "All WiFi profiles are secure" -Category "Network"
    }

    if ($wifiInfo.ConnectedNetworks.Count -gt 0) {
        $insecureConnected = $wifiInfo.ConnectedNetworks | Where-Object { $_.SSID -in $wifiInfo.InsecureProfiles.SSID }
        if ($insecureConnected.Count -gt 0) {
            Add-Finding -CheckName "Connected to Insecure Network" -Status "Fail" -Details "Connected to $($insecureConnected.Count) insecure networks" -Category "Network"
        }
    }

    return $wifiInfo
}

# Export the function
Export-ModuleMember -Function Test-WiFiSecurity 