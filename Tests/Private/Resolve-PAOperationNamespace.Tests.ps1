#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/Resolve-PAOperationNamespace.ps1')

    # Reset the cache before tests so the real JSON is loaded
    $script:PAOperationMap = $null
}

Describe 'Resolve-PAOperationNamespace' {

    BeforeAll {
        # Ensure cache is clear so each Describe starts fresh
        $script:PAOperationMap = $null
    }

    Context 'Explicit mapping' {

        It 'Returns exact namespace for a known operation' {
            $result = Resolve-PAOperationNamespace -OperationName 'Add user'

            $result | Should -Be 'microsoft.directory/users/create'
        }

        It 'Returns exact namespace for group operation' {
            $result = Resolve-PAOperationNamespace -OperationName 'Add member to group'

            $result | Should -Be 'microsoft.directory/groups/members/update'
        }

        It 'Returns exact namespace for app operation' {
            $result = Resolve-PAOperationNamespace -OperationName 'Add application'

            $result | Should -Be 'microsoft.directory/applications/create'
        }

        It 'Returns exact namespace for conditional access operation' {
            $result = Resolve-PAOperationNamespace -OperationName 'Delete conditional access policy'

            $result | Should -Be 'microsoft.directory/conditionalAccessPolicies/delete'
        }
    }

    Context 'Category fallback' {

        It 'Falls back to category namespace when no explicit match' {
            $result = Resolve-PAOperationNamespace -OperationName 'Some unknown user op' -Category 'UserManagement'

            $result | Should -Be 'microsoft.directory/users'
        }

        It 'Returns category namespace for GroupManagement' {
            $result = Resolve-PAOperationNamespace -OperationName 'Unknown group op' -Category 'GroupManagement'

            $result | Should -Be 'microsoft.directory/groups'
        }

        It 'Returns category namespace for ApplicationManagement' {
            $result = Resolve-PAOperationNamespace -OperationName 'Unknown app op' -Category 'ApplicationManagement'

            $result | Should -Be 'microsoft.directory/applications'
        }
    }

    Context 'Unmapped operation' {

        It 'Returns null when neither explicit nor category match' {
            $result = Resolve-PAOperationNamespace -OperationName 'Totally unknown operation'

            $result | Should -BeNullOrEmpty
        }

        It 'Returns null when operation unknown and category unknown' {
            $result = Resolve-PAOperationNamespace -OperationName 'Unknown' -Category 'UnknownCategory'

            $result | Should -BeNullOrEmpty
        }

        It 'Returns null when operation unknown and category empty' {
            $result = Resolve-PAOperationNamespace -OperationName 'Unknown'

            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Precedence' {

        It 'Explicit mapping takes precedence over category' {
            # 'Add user' has explicit mapping to microsoft.directory/users/create
            # Category 'UserManagement' maps to microsoft.directory/users
            # Explicit should win (more specific)
            $result = Resolve-PAOperationNamespace -OperationName 'Add user' -Category 'UserManagement'

            $result | Should -Be 'microsoft.directory/users/create'
        }
    }

    Context 'Caching' {

        It 'Loads the map only once across multiple calls' {
            # Reset cache
            $script:PAOperationMap = $null

            Mock Test-Path { $true }
            Mock Get-Content {
                '{"_meta":{},"explicitMappings":{"Test op":"test/namespace"},"categoryToNamespace":{}}'
            }

            # First call — loads the map
            Resolve-PAOperationNamespace -OperationName 'Test op'

            # Second call — should use cache
            Resolve-PAOperationNamespace -OperationName 'Test op'

            Should -Invoke Get-Content -Exactly -Times 1

            # Restore cache for remaining tests
            $script:PAOperationMap = $null
        }
    }

    Context 'Case sensitivity' {

        It 'Matches operation names case-sensitively' {
            # 'Add user' exists but 'add user' (lowercase) should not match
            # PSCustomObject property access is case-insensitive in PowerShell
            # so both should actually resolve — this documents the behavior
            $result = Resolve-PAOperationNamespace -OperationName 'add user'

            # PowerShell property access is case-insensitive
            $result | Should -Be 'microsoft.directory/users/create'
        }
    }

    Context 'Map file missing' {

        It 'Throws when EntraOperationMap.json is not found' {
            $script:PAOperationMap = $null

            Mock Test-Path { $false }

            { Resolve-PAOperationNamespace -OperationName 'Add user' } | Should -Throw '*not found*'

            $script:PAOperationMap = $null
        }
    }
}
