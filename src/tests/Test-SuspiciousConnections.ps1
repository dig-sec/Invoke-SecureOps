# ... existing code ...
                Add-Finding -TestResult $result -FindingName "Suspicious Port Connection" `
                    -Status "Warning" -RiskLevel "Medium" `
                    -Description "Found $($suspiciousConnections.Count) connections on port $($port.Port) ($($port.Description))" `
                    -AdditionalInfo @{
                        Component = "NetworkConnections"
                        Port = $port.Port
                        Description = $port.Description
                        ConnectionCount = $suspiciousConnections.Count
                        Connections = $connectionDetails
                        Recommendation = "Review these connections and verify they are authorized"
                    }
# ... existing code ...
                Add-Finding -TestResult $result -FindingName "Suspicious IP Range Connection" `
                    -Status "Warning" -RiskLevel $range.RiskLevel `
                    -Description "Found $($suspiciousConnections.Count) connections to $($range.Description)" `
                    -AdditionalInfo @{
                        Component = "NetworkConnections"
                        Range = $range.Range
                        Description = $range.Description
                        ConnectionCount = $suspiciousConnections.Count
                        Connections = $connectionDetails
                        Recommendation = "Review these connections and verify they are authorized"
                    }
# ... existing code ... 