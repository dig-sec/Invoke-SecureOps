# ... existing code ...
                        Add-Finding -TestResult $result -FindingName "$($location.Description) - $fileType Files" `
                            -Status "Warning" -RiskLevel $location.RiskLevel `
                            -Description "Found $($files.Count) $fileType files in $($location.Path)" `
                            -AdditionalInfo @{
                                Component = "FileSystem"
                                Location = $location.Path
                                FileType = $fileType
                                FileCount = $files.Count
                                Files = $fileDetails
                                Recommendation = "Review these files and verify they are authorized"
                            }
# ... existing code ...
                Add-Finding -TestResult $result -FindingName "$($location.Description) Access" `
                    -Status "Info" -RiskLevel "Low" `
                    -Description "Unable to access $($location.Path)" `
                    -AdditionalInfo @{
                        Recommendation = "Verify directory permissions and existence"
                    }
# ... existing code ...
                            Add-Finding -TestResult $result -FindingName "Suspicious Script Content" `
                                -Status "Warning" -RiskLevel $pattern.RiskLevel `
                                -Description "Found $($pattern.Description) pattern in $($script.Name)" `
                                -AdditionalInfo @{
                                    Component = "FileSystem"
                                    File = $script.FullName
                                    Pattern = $pattern.Pattern
                                    PatternDescription = $pattern.Description
                                    CreationTime = $script.CreationTime
                                    LastWriteTime = $script.LastWriteTime
                                    Recommendation = "Review script content and verify it is authorized"
                                }
# ... existing code ...
        Add-Finding -TestResult $result -FindingName "Test Error" `
            -Status "Error" -RiskLevel "High" `
            -Description "Error during suspicious files test: $_" `
            -AdditionalInfo @{
                Recommendation = "Check system permissions and file access"
            }
# ... existing code ... 