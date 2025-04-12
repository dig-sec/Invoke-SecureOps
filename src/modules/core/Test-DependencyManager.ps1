# -----------------------------------------------------------------------------
# Security Test Dependency Manager
# -----------------------------------------------------------------------------

# Function to validate test dependencies
function Test-Dependencies {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$TestNames,
        
        [Parameter()]
        [switch]$ThrowOnError
    )
    
    $errors = @()
    $validTests = @()
    
    foreach ($testName in $TestNames) {
        $metadata = Get-TestMetadata -TestName $testName
        if ($null -eq $metadata) {
            $errors += "Test '$testName' not found in registry"
            continue
        }
        
        foreach ($dependency in $metadata.Dependencies) {
            if (-not (Get-TestMetadata -TestName $dependency)) {
                $errors += "Test '$testName' depends on '$dependency' which is not registered"
            }
        }
        
        $validTests += $testName
    }
    
    if ($errors.Count -gt 0) {
        if ($ThrowOnError) {
            throw ($errors -join "`n")
        }
        Write-Warning ($errors -join "`n")
    }
    
    return $validTests
}

# Function to get test execution order
function Get-TestExecutionOrder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$TestNames
    )
    
    # Validate dependencies first
    $validTests = Test-Dependencies -TestNames $TestNames -ThrowOnError
    
    # Build dependency graph
    $graph = @{}
    $visited = @{}
    $order = @()
    
    foreach ($testName in $validTests) {
        if (-not $visited[$testName]) {
            $graph[$testName] = @()
            $metadata = Get-TestMetadata -TestName $testName
            foreach ($dependency in $metadata.Dependencies) {
                $graph[$testName] += $dependency
            }
        }
    }
    
    # Topological sort using DFS
    function Visit-Test {
        param (
            [string]$testName,
            [ref]$visited,
            [ref]$order
        )
        
        if ($visited.Value[$testName]) {
            return
        }
        
        $visited.Value[$testName] = $true
        
        foreach ($dependency in $graph[$testName]) {
            Visit-Test -testName $dependency -visited $visited -order $order
        }
        
        $order.Value = @($testName) + $order.Value
    }
    
    foreach ($testName in $validTests) {
        if (-not $visited[$testName]) {
            Visit-Test -testName $testName -visited ([ref]$visited) -order ([ref]$order)
        }
    }
    
    return $order
}

# Function to get test execution groups
function Get-TestExecutionGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$TestNames
    )
    
    $order = Get-TestExecutionOrder -TestNames $TestNames
    $groups = @()
    $currentGroup = @()
    $currentDependencies = @{}
    
    foreach ($testName in $order) {
        $metadata = Get-TestMetadata -TestName $testName
        $dependencies = $metadata.Dependencies
        
        # Check if all dependencies are satisfied
        $canRun = $true
        foreach ($dependency in $dependencies) {
            if (-not $currentDependencies.ContainsKey($dependency)) {
                $canRun = $false
                break
            }
        }
        
        if ($canRun) {
            $currentGroup += $testName
            $currentDependencies[$testName] = $true
        } else {
            if ($currentGroup.Count -gt 0) {
                $groups += ,@($currentGroup)
                $currentGroup = @()
            }
            $currentGroup += $testName
            $currentDependencies[$testName] = $true
        }
    }
    
    if ($currentGroup.Count -gt 0) {
        $groups += ,@($currentGroup)
    }
    
    return $groups
}

# Function to validate test execution order
function Test-ExecutionOrder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$ExecutionOrder
    )
    
    $errors = @()
    $visited = @{}
    
    foreach ($testName in $ExecutionOrder) {
        $metadata = Get-TestMetadata -TestName $testName
        if ($null -eq $metadata) {
            $errors += "Test '$testName' not found in registry"
            continue
        }
        
        foreach ($dependency in $metadata.Dependencies) {
            if (-not $visited.ContainsKey($dependency)) {
                $errors += "Test '$testName' depends on '$dependency' which hasn't been executed yet"
            }
        }
        
        $visited[$testName] = $true
    }
    
    if ($errors.Count -gt 0) {
        throw ($errors -join "`n")
    }
    
    return $true
}

# Export functions
Export-ModuleMember -Function Test-Dependencies,
                              Get-TestExecutionOrder,
                              Get-TestExecutionGroups,
                              Test-ExecutionOrder 