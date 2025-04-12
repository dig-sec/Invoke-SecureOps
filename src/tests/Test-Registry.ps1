# -----------------------------------------------------------------------------
# Security Test Registry Module
# -----------------------------------------------------------------------------

# Initialize test registry
$script:TestRegistry = @{
    Tests = @{}
    Categories = @{}
    Tags = @{}
    Dependencies = @{}
    BaselineFields = @{}
    VolatileFields = @{}
}

# Function to register a new security test
function Register-SecurityTest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [string]$Category,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [Parameter()]
        [string[]]$Tags = @(),
        
        [Parameter()]
        [string[]]$ComplianceReferences = @(),
        
        [Parameter()]
        [hashtable]$Parameters = @{},
        
        [Parameter()]
        [string[]]$Dependencies = @(),
        
        [Parameter()]
        [hashtable]$BaselineFields = @{},
        
        [Parameter()]
        [string[]]$VolatileFields = @(),
        
        [Parameter()]
        [string]$FunctionPath,
        
        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$DefaultRiskLevel = 'Medium'
    )
    
    # Validate test name
    if ($script:TestRegistry.Tests.ContainsKey($TestName)) {
        throw "Test '$TestName' is already registered"
    }
    
    # Create test metadata
    $testMetadata = @{
        Name = $TestName
        Category = $Category
        Description = $Description
        Tags = $Tags
        ComplianceReferences = $ComplianceReferences
        Parameters = $Parameters
        Dependencies = $Dependencies
        BaselineFields = $BaselineFields
        VolatileFields = $VolatileFields
        FunctionPath = $FunctionPath
        DefaultRiskLevel = $DefaultRiskLevel
        RegistrationTime = Get-Date
    }
    
    # Register test
    $script:TestRegistry.Tests[$TestName] = $testMetadata
    
    # Update category index
    if (-not $script:TestRegistry.Categories.ContainsKey($Category)) {
        $script:TestRegistry.Categories[$Category] = @()
    }
    $script:TestRegistry.Categories[$Category] += $TestName
    
    # Update tag index
    foreach ($tag in $Tags) {
        if (-not $script:TestRegistry.Tags.ContainsKey($tag)) {
            $script:TestRegistry.Tags[$tag] = @()
        }
        $script:TestRegistry.Tags[$tag] += $TestName
    }
    
    # Update dependency index
    foreach ($dependency in $Dependencies) {
        if (-not $script:TestRegistry.Dependencies.ContainsKey($dependency)) {
            $script:TestRegistry.Dependencies[$dependency] = @()
        }
        $script:TestRegistry.Dependencies[$dependency] += $TestName
    }
    
    Write-Verbose "Registered test '$TestName' in category '$Category'"
}

# Function to get test metadata
function Get-TestMetadata {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TestName
    )
    
    if (-not $script:TestRegistry.Tests.ContainsKey($TestName)) {
        throw "Test '$TestName' is not registered"
    }
    
    return $script:TestRegistry.Tests[$TestName]
}

# Function to get tests by category
function Get-TestsByCategory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Category
    )
    
    if (-not $script:TestRegistry.Categories.ContainsKey($Category)) {
        return @()
    }
    
    return $script:TestRegistry.Categories[$Category]
}

# Function to get tests by tag
function Get-TestsByTag {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Tag
    )
    
    if (-not $script:TestRegistry.Tags.ContainsKey($Tag)) {
        return @()
    }
    
    return $script:TestRegistry.Tags[$Tag]
}

# Function to get all registered tests
function Get-AllTests {
    [CmdletBinding()]
    param()
    
    return $script:TestRegistry.Tests.Values
}

# Function to get all categories
function Get-AllCategories {
    [CmdletBinding()]
    param()
    
    return $script:TestRegistry.Categories.Keys
}

# Function to get all tags
function Get-AllTags {
    [CmdletBinding()]
    param()
    
    return $script:TestRegistry.Tags.Keys
}

# Function to validate test dependencies
function Test-Dependencies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TestName
    )
    
    $metadata = Get-TestMetadata -TestName $TestName
    $missingDependencies = @()
    
    foreach ($dependency in $metadata.Dependencies) {
        if (-not $script:TestRegistry.Tests.ContainsKey($dependency)) {
            $missingDependencies += $dependency
        }
    }
    
    return @{
        TestName = $TestName
        Dependencies = $metadata.Dependencies
        MissingDependencies = $missingDependencies
        AllDependenciesMet = $missingDependencies.Count -eq 0
    }
}

# Function to export test registry
function Export-TestRegistry {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$PrettyOutput
    )
    
    $exportData = @{
        Tests = $script:TestRegistry.Tests
        Categories = $script:TestRegistry.Categories
        Tags = $script:TestRegistry.Tags
        Dependencies = $script:TestRegistry.Dependencies
        ExportTime = Get-Date
    }
    
    $json = $exportData | ConvertTo-Json -Depth 10
    if ($PrettyOutput) {
        $json = $json | ForEach-Object { [System.Web.HttpUtility]::JavaScriptStringEncode($_, $true) }
    }
    
    if ($OutputPath) {
        $json | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Output "Test registry exported to $OutputPath"
    }
    
    return $json
}

# Function to import test registry
function Import-TestRegistry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$InputPath
    )
    
    if (-not (Test-Path $InputPath)) {
        throw "Input file '$InputPath' does not exist"
    }
    
    $importData = Get-Content -Path $InputPath -Raw | ConvertFrom-Json
    
    # Clear existing registry
    $script:TestRegistry = @{
        Tests = @{}
        Categories = @{}
        Tags = @{}
        Dependencies = @{}
        BaselineFields = @{}
        VolatileFields = @{}
    }
    
    # Import tests
    foreach ($test in $importData.Tests.PSObject.Properties) {
        $script:TestRegistry.Tests[$test.Name] = $test.Value
    }
    
    # Import categories
    foreach ($category in $importData.Categories.PSObject.Properties) {
        $script:TestRegistry.Categories[$category.Name] = $category.Value
    }
    
    # Import tags
    foreach ($tag in $importData.Tags.PSObject.Properties) {
        $script:TestRegistry.Tags[$tag.Name] = $tag.Value
    }
    
    # Import dependencies
    if ($importData.PSObject.Properties.Name -contains 'Dependencies') {
        foreach ($dependency in $importData.Dependencies.PSObject.Properties) {
            $script:TestRegistry.Dependencies[$dependency.Name] = $dependency.Value
        }
    }
    
    Write-Output "Test registry imported from $InputPath"
}

# Export functions
Export-ModuleMember -Function Register-SecurityTest,
                              Get-TestMetadata,
                              Get-TestsByCategory,
                              Get-TestsByTag,
                              Get-AllTests,
                              Get-AllCategories,
                              Get-AllTags,
                              Test-Dependencies,
                              Export-TestRegistry,
                              Import-TestRegistry 