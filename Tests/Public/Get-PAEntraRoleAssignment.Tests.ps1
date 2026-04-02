#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Get-PAEntraRoleAssignment.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PAGraphRequest.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAAssignment.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Resolve-PAPrincipal.ps1')

    # Stub for Invoke-MgGraphRequest (needed by Invoke-PAGraphRequest)
    function Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) }
}

Describe 'Get-PAEntraRoleAssignment' {

    BeforeAll {
        $mockSession = [PSCustomObject]@{
            PSTypeName  = 'PA.Session'
            TenantId    = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment = 'Global'
        }

        $mockRoleDefinitions = @(
            [PSCustomObject]@{
                id          = '<role-def-ga>'
                displayName = 'Global Administrator'
                isBuiltIn   = $true
            },
            [PSCustomObject]@{
                id          = '<role-def-ur>'
                displayName = 'User Administrator'
                isBuiltIn   = $true
            },
            [PSCustomObject]@{
                id          = '<role-def-custom>'
                displayName = 'Custom Helpdesk Role'
                isBuiltIn   = $false
            }
        )

        $mockAssignments = @(
            [PSCustomObject]@{
                id                = '<assignment-1>'
                principalId       = '<principal-user>'
                roleDefinitionId  = '<role-def-ga>'
                directoryScopeId  = '/'
                principal         = [PSCustomObject]@{
                    '@odata.type' = '#microsoft.graph.user'
                    id            = '<principal-user>'
                    displayName   = 'Alice Admin'
                }
            },
            [PSCustomObject]@{
                id                = '<assignment-2>'
                principalId       = '<principal-group>'
                roleDefinitionId  = '<role-def-ur>'
                directoryScopeId  = '/'
                principal         = [PSCustomObject]@{
                    '@odata.type' = '#microsoft.graph.group'
                    id            = '<principal-group>'
                    displayName   = 'Admin Group'
                }
            },
            [PSCustomObject]@{
                id                = '<assignment-3>'
                principalId       = '<principal-sp>'
                roleDefinitionId  = '<role-def-custom>'
                directoryScopeId  = '/administrativeUnits/<au-id>'
                principal         = [PSCustomObject]@{
                    '@odata.type' = '#microsoft.graph.servicePrincipal'
                    id            = '<principal-sp>'
                    displayName   = 'Automation App'
                }
            }
        )
    }

    Context 'Happy path' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $mockAssignments
            }
        }

        It 'Returns PA.CollectorResult type' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Status is Complete with clean data' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Status | Should -Be 'Complete'
        }

        It 'ItemCount matches raw assignment count' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.ItemCount | Should -Be 3
        }

        It 'Collector name is correct' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Collector | Should -Be 'Get-PAEntraRoleAssignment'
        }

        It 'Duration is populated' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Duration.TotalMilliseconds | Should -BeGreaterThan 0
        }

        It 'All items are PA.Assignment type' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.Assignment'
            }
        }
    }

    Context 'Principal type mapping' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $mockAssignments
            }
        }

        It 'Maps #microsoft.graph.user to User' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $userItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userItem.PrincipalType | Should -Be 'User'
        }

        It 'Maps #microsoft.graph.group to Group' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $groupItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-group>' }
            $groupItem.PrincipalType | Should -Be 'Group'
        }

        It 'Maps #microsoft.graph.servicePrincipal to ServicePrincipal' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $spItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-sp>' }
            $spItem.PrincipalType | Should -Be 'ServicePrincipal'
        }

        It 'Falls back to User for unknown @odata.type with warning' {
            $unknownTypeAssignment = @(
                [PSCustomObject]@{
                    id                = '<assignment-unknown>'
                    principalId       = '<principal-unknown>'
                    roleDefinitionId  = '<role-def-ga>'
                    directoryScopeId  = '/'
                    principal         = [PSCustomObject]@{
                        '@odata.type' = '#microsoft.graph.unknownType'
                        id            = '<principal-unknown>'
                        displayName   = 'Unknown Entity'
                    }
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $unknownTypeAssignment
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Items[0].PrincipalType | Should -Be 'User'
            $result.Status | Should -Be 'Partial'
            $result.Warnings | Should -Contain "Unknown principal type '#microsoft.graph.unknownType' for principal <principal-unknown>"
        }
    }

    Context 'Role definition enrichment' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $mockAssignments
            }
        }

        It 'Sets RoleName from role definition displayName' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $gaItem = $result.Items | Where-Object { $_.RoleDefinitionId -eq '<role-def-ga>' }
            $gaItem.RoleName | Should -Be 'Global Administrator'
        }

        It 'Sets RoleType to BuiltIn for built-in roles' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $gaItem = $result.Items | Where-Object { $_.RoleDefinitionId -eq '<role-def-ga>' }
            $gaItem.RoleType | Should -Be 'BuiltIn'
        }

        It 'Sets RoleType to Custom for custom roles' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $customItem = $result.Items | Where-Object { $_.RoleDefinitionId -eq '<role-def-custom>' }
            $customItem.RoleType | Should -Be 'Custom'
        }

        It 'Handles missing role definition with warning' {
            $missingRoleAssignment = @(
                [PSCustomObject]@{
                    id                = '<assignment-missing-role>'
                    principalId       = '<principal-user>'
                    roleDefinitionId  = '<role-def-nonexistent>'
                    directoryScopeId  = '/'
                    principal         = [PSCustomObject]@{
                        '@odata.type' = '#microsoft.graph.user'
                        id            = '<principal-user>'
                        displayName   = 'Alice Admin'
                    }
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $missingRoleAssignment
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Items[0].RoleName | Should -Be ''
            $result.Items[0].RoleType | Should -Be ''
            $result.Status | Should -Be 'Partial'
        }
    }

    Context 'Scope mapping' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $mockAssignments
            }
        }

        It 'Maps / to ScopeType Tenant' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $tenantItem = $result.Items | Where-Object { $_.Scope -eq '/' }
            $tenantItem[0].ScopeType | Should -Be 'Tenant'
        }

        It 'Maps /administrativeUnits/{id} to ScopeType AdministrativeUnit' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $auItem = $result.Items | Where-Object { $_.Scope -like '/administrativeUnits/*' }
            $auItem.ScopeType | Should -Be 'AdministrativeUnit'
        }

        It 'Preserves full directoryScopeId as Scope' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $auItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-sp>' }
            $auItem.Scope | Should -Be '/administrativeUnits/<au-id>'
        }
    }

    Context 'Fixed field values' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $mockAssignments
            }
        }

        It 'Source is always EntraRole' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Items | ForEach-Object { $_.Source | Should -Be 'EntraRole' }
        }

        It 'AssignmentType is always Direct' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Items | ForEach-Object { $_.AssignmentType | Should -Be 'Direct' }
        }

        It 'Status defaults to Active' {
            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Items | ForEach-Object { $_.Status | Should -Be 'Active' }
        }
    }

    Context 'Expand fallback' {

        It 'Falls back to Resolve-PAPrincipal when expand not available' {
            $noExpandAssignments = @(
                [PSCustomObject]@{
                    id                = '<assignment-noexpand>'
                    principalId       = '<principal-user>'
                    roleDefinitionId  = '<role-def-ga>'
                    directoryScopeId  = '/'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $noExpandAssignments
            }
            Mock Resolve-PAPrincipal {
                @{ '<principal-user>' = 'Fallback Name' }
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            Should -Invoke Resolve-PAPrincipal -Exactly -Times 1
        }

        It 'Defaults PrincipalType to User when expand unavailable' {
            $noExpandAssignments = @(
                [PSCustomObject]@{
                    id                = '<assignment-noexpand>'
                    principalId       = '<principal-user>'
                    roleDefinitionId  = '<role-def-ga>'
                    directoryScopeId  = '/'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $noExpandAssignments
            }
            Mock Resolve-PAPrincipal {
                @{ '<principal-user>' = 'Fallback Name' }
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Items[0].PrincipalType | Should -Be 'User'
        }

        It 'Populates display name from Resolve-PAPrincipal' {
            $noExpandAssignments = @(
                [PSCustomObject]@{
                    id                = '<assignment-noexpand>'
                    principalId       = '<principal-user>'
                    roleDefinitionId  = '<role-def-ga>'
                    directoryScopeId  = '/'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $noExpandAssignments
            }
            Mock Resolve-PAPrincipal {
                @{ '<principal-user>' = 'Fallback Name' }
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Items[0].PrincipalDisplayName | Should -Be 'Fallback Name'
        }

        It 'Adds warning when expand is not available' {
            $noExpandAssignments = @(
                [PSCustomObject]@{
                    id                = '<assignment-noexpand>'
                    principalId       = '<principal-user>'
                    roleDefinitionId  = '<role-def-ga>'
                    directoryScopeId  = '/'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $noExpandAssignments
            }
            Mock Resolve-PAPrincipal {
                @{ '<principal-user>' = 'Fallback Name' }
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Warnings | Should -Contain '$expand=principal not available; principal types will default to User'
            $result.Status | Should -Be 'Partial'
        }
    }

    Context 'Empty tenant' {

        It 'Returns Complete with 0 items for empty tenant' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                @()
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Status | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }

        It 'Does not call Resolve-PAPrincipal for empty result' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                @()
            }
            Mock Resolve-PAPrincipal {}

            Get-PAEntraRoleAssignment -Session $mockSession

            Should -Invoke Resolve-PAPrincipal -Exactly -Times 0
        }
    }

    Context 'Error handling' {

        It 'Returns Failed when roleAssignments call throws' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                throw 'Graph API error: 403 Forbidden'
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Status | Should -Be 'Failed'
            $result.Errors | Should -Contain 'Graph API error: 403 Forbidden'
            $result.ItemCount | Should -Be 0
        }

        It 'Returns Partial when roleDefinitions call fails' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                throw 'Role definitions unavailable'
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleAssignments*' } {
                $mockAssignments
            }

            $result = Get-PAEntraRoleAssignment -Session $mockSession

            $result.Status | Should -Be 'Partial'
            $result.ItemCount | Should -Be 3
            $result.Warnings | Where-Object { $_ -like '*role definitions*' } | Should -Not -BeNullOrEmpty
        }
    }
}
