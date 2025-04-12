# -----------------------------------------------------------------------------
# Test Execution Planning Module
# -----------------------------------------------------------------------------

# Import the module registry
Import-Module "$PSScriptRoot\Register-SecurityTests.ps1" -Force

# Function to get tests to run based on categories or specific test names
function Get-TestsToRun {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Categories,
        
        [Parameter()]
        [string[]]$SpecificTests
    )
    
    # Get all registered tests
    $allTests = Get-RegisteredTests
    
    # Initialize result array
    $testsToRun = @()
    
    # If specific tests are provided, use those
    if ($SpecificTests) {
        foreach ($testName in $SpecificTests) {
            if ($allTests.ContainsKey($testName)) {
                $testsToRun += @{
                    Name = $testName
                    Category = $allTests[$testName].Category
                    Dependencies = $allTests[$testName].Dependencies
                    Prerequisites = $allTests[$testName].Prerequisites
                    ExecutionOrder = $allTests[$testName].ExecutionOrder
                }
            } else {
                Write-Warning "Test '$testName' is not registered. Skipping."
            }
        }
    }
    # If categories are provided, get all tests in those categories
    elseif ($Categories) {
        foreach ($category in $Categories) {
            $categoryTests = $allTests.GetEnumerator() | Where-Object { $_.Value.Category -eq $category }
            foreach ($test in $categoryTests) {
                $testsToRun += @{
                    Name = $test.Key
                    Category = $test.Value.Category
                    Dependencies = $test.Value.Dependencies
                    Prerequisites = $test.Value.Prerequisites
                    ExecutionOrder = $test.Value.ExecutionOrder
                }
            }
        }
    }
    # If neither is provided, get all tests
    else {
        foreach ($test in $allTests.GetEnumerator()) {
            $testsToRun += @{
                Name = $test.Key
                Category = $test.Value.Category
                Dependencies = $test.Value.Dependencies
                Prerequisites = $test.Value.Prerequisites
                ExecutionOrder = $test.Value.ExecutionOrder
            }
        }
    }
    
    return $testsToRun
}

# Function to validate environment against test prerequisites
function Test-EnvironmentPrerequisites {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Tests,
        
        [Parameter()]
        [hashtable]$Constraints = @{}
    )
    
    # Initialize result
    $result = @{
        IsValid = $true
        Failures = @()
        Warnings = @()
    }
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    # Check each test's prerequisites
    foreach ($test in $Tests) {
        # Check for administrator requirement
        if ($test.Prerequisites -contains "Administrator" -and -not $isAdmin) {
            $result.IsValid = $false
            $result.Failures += "Test '$($test.Name)' requires administrator privileges."
        }
        
        # Check for custom constraints
        foreach ($constraint in $Constraints.Keys) {
            if ($test.Prerequisites -contains $constraint -and -not $Constraints[$constraint]) {
                $result.IsValid = $false
                $result.Failures += "Test '$($test.Name)' requires '$constraint' which is not satisfied."
            }
        }
    }
    
    return $result
}

# Function to get the execution plan for tests
function Get-TestExecutionPlan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Tests
    )
    
    # Initialize result
    $result = @{
        OrderedTests = @()
        ModuleImports = @()
        Dependencies = @{}
    }
    
    # Create a dependency graph
    $dependencyGraph = @{}
    foreach ($test in $Tests) {
        $dependencyGraph[$test.Name] = @{
            Dependencies = $test.Dependencies
            ExecutionOrder = $test.ExecutionOrder
            Visited = $false
            InProgress = $false
        }
    }
    
    # Function to detect cycles in the dependency graph
    function Test-DependencyCycle {
        param (
            [string]$TestName,
            [hashtable]$Graph
        )
        
        if ($Graph[$TestName].InProgress) {
            return $true
        }
        
        if ($Graph[$TestName].Visited) {
            return $false
        }
        
        $Graph[$TestName].Visited = $true
        $Graph[$TestName].InProgress = $true
        
        foreach ($dependency in $Graph[$TestName].Dependencies) {
            if ($Graph.ContainsKey($dependency) -and (Test-DependencyCycle -TestName $dependency -Graph $Graph)) {
                return $true
            }
        }
        
        $Graph[$TestName].InProgress = $false
        return $false
    }
    
    # Check for cycles
    foreach ($testName in $dependencyGraph.Keys) {
        if (Test-DependencyCycle -TestName $testName -Graph $dependencyGraph) {
            Write-Error "Circular dependency detected in test '$testName'."
            return $null
        }
    }
    
    # Reset visited flag
    foreach ($testName in $dependencyGraph.Keys) {
        $dependencyGraph[$testName].Visited = $false
    }
    
    # Function to get module imports
    function Get-ModuleImports {
        param (
            [string]$TestName
        )
        
        # Determine the module path based on the test name
        $category = (Get-TestMetadata -TestName $TestName).Category
        
        # Map category to module path
        $categoryToPath = @{
            "Windows Defender" = "security"
            "Credential Protection" = "security"
            "Process Security" = "security"
            "PowerShell Security" = "powerShell"
            "Network Security" = "network"
            "Storage Security" = "storage"
        }
        
        $modulePath = $categoryToPath[$category]
        if (-not $modulePath) {
            $modulePath = "core"
        }
        
        return "Import-Module `"`$PSScriptRoot\..\modules\$modulePath\$TestName.ps1`" -Force"
    }
    
    # Function to sort tests by dependencies
    function Sort-TestsByDependencies {
        param (
            [hashtable]$Graph
        )
        
        $sorted = @()
        $visited = @{}
        
        function Visit {
            param (
                [string]$TestName
            )
                
            if ($visited[$TestName]) {
                return
            }
            
            $visited[$TestName] = $true
            
            foreach ($dependency in $Graph[$TestName].Dependencies) {
                if ($Graph.ContainsKey($dependency)) {
                    Visit -TestName $dependency
                }
            }
            
            $sorted += $TestName
        }
        
        foreach ($testName in $Graph.Keys) {
            if (-not $visited[$TestName]) {
                Visit -TestName $testName
            }
        }
        
        return $sorted
    }
    
    # Sort tests by dependencies
    $sortedTestNames = Sort-TestsByDependencies -Graph $dependencyGraph
    
    # Add tests to the result in the correct order
    foreach ($testName in $sortedTestNames) {
        $test = $Tests | Where-Object { $_.Name -eq $testName }
        if ($test) {
            $result.OrderedTests += $test
            $result.ModuleImports += Get-ModuleImports -TestName $testName
        }
    }
    
    # Add remaining tests that weren't in the dependency graph
    foreach ($test in $Tests) {
        if (-not ($sortedTestNames -contains $test.Name)) {
            $result.OrderedTests += $test
            $result.ModuleImports += Get-ModuleImports -TestName $test.Name
        }
    }
    
    # Sort by execution order
    $result.OrderedTests = $result.OrderedTests | Sort-Object -Property ExecutionOrder
    
    return $result
}

# Export functions
Export-ModuleMember -Function Get-TestsToRun, Test-EnvironmentPrerequisites, Get-TestExecutionPlan 