#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/Resolve-PARoleAction.ps1')

    # Stub for Invoke-PAGraphRequest (tested separately)
    function Invoke-PAGraphRequest { param($Uri, $Select, $Filter, $ApiVersion, $MaxPages, $ConsistencyLevel, $HttpMethod) }

    # Stub for Get-AzRoleDefinition
    function Get-AzRoleDefinition { param($Scope, $Id, $ErrorAction) }
}

Describe 'Resolve-PARoleAction' {

    BeforeAll {
        $mockSession = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            WorkspaceId     = '<workspace-id>'
            SubscriptionIds = @('<sub-id-1>')
        }

        $mockEntraAssignment = [PSCustomObject]@{
            PSTypeName       = 'PA.Assignment'
            PrincipalId      = '<principal-user-1>'
            RoleDefinitionId = '<entra-role-def-1>'
            Source           = 'EntraRole'
            Scope            = '/'
        }

        $mockAzureAssignment = [PSCustomObject]@{
            PSTypeName       = 'PA.Assignment'
            PrincipalId      = '<principal-user-1>'
            RoleDefinitionId = '<rbac-role-def-1>'
            Source           = 'AzureRbac'
            Scope            = '/subscriptions/<sub-id-1>/resourceGroups/<rg-1>'
        }

        $mockAppPermAssignment = [PSCustomObject]@{
            PSTypeName       = 'PA.Assignment'
            PrincipalId      = '<principal-sp-1>'
            RoleDefinitionId = '<app-role-def-1>'
            Source           = 'AppPermission'
            Scope            = '/'
        }

        $mockEntraRoleDef = [PSCustomObject]@{
            id = '<entra-role-def-1>'
            rolePermissions = @(
                [PSCustomObject]@{
                    allowedResourceActions = @(
                        'microsoft.directory/users/basic/update',
                        'microsoft.directory/users/password/update',
                        'microsoft.directory/groups/members/update'
                    )
                }
            )
        }

        $mockAzureRoleDef = [PSCustomObject]@{
            Id             = '<rbac-role-def-1>'
            Name           = 'Virtual Machine Contributor'
            IsCustom       = $false
            Actions        = @('Microsoft.Compute/virtualMachines/*', 'Microsoft.Network/networkInterfaces/read')
            NotActions     = @()
            DataActions    = @('Microsoft.Compute/virtualMachines/login/action')
            NotDataActions = @()
        }
    }

    Context 'Empty assignments' {

        It 'Returns an empty hashtable when Assignments is empty' {
            Mock Invoke-PAGraphRequest { @() }
            Mock Get-AzRoleDefinition { $null }

            $result = Resolve-PARoleAction -Assignments @() -Session $mockSession

            $result | Should -BeOfType [hashtable]
            $result.Count | Should -Be 0
        }

        It 'Does not call Invoke-PAGraphRequest when Assignments is empty' {
            Mock Invoke-PAGraphRequest { @() }
            Mock Get-AzRoleDefinition { $null }

            Resolve-PARoleAction -Assignments @() -Session $mockSession

            Should -Invoke Invoke-PAGraphRequest -Exactly -Times 0
        }

        It 'Does not call Get-AzRoleDefinition when Assignments is empty' {
            Mock Invoke-PAGraphRequest { @() }
            Mock Get-AzRoleDefinition { $null }

            Resolve-PARoleAction -Assignments @() -Session $mockSession

            Should -Invoke Get-AzRoleDefinition -Exactly -Times 0
        }
    }

    Context 'Entra role resolution' {

        BeforeEach {
            Mock Invoke-PAGraphRequest {
                @($mockEntraRoleDef)
            }
        }

        It 'Returns a hashtable entry for the Entra role definition ID' {
            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment) -Session $mockSession

            $result.ContainsKey('<entra-role-def-1>') | Should -Be $true
        }

        It 'Maps allowedResourceActions from rolePermissions[0]' {
            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment) -Session $mockSession

            $result['<entra-role-def-1>'] | Should -HaveCount 3
            $result['<entra-role-def-1>'] | Should -Contain 'microsoft.directory/users/basic/update'
            $result['<entra-role-def-1>'] | Should -Contain 'microsoft.directory/users/password/update'
            $result['<entra-role-def-1>'] | Should -Contain 'microsoft.directory/groups/members/update'
        }

        It 'Calls Invoke-PAGraphRequest targeting the roleDefinitions endpoint' {
            Resolve-PARoleAction -Assignments @($mockEntraAssignment) -Session $mockSession

            Should -Invoke Invoke-PAGraphRequest -ParameterFilter {
                $Uri -like '*/roleManagement/directory/roleDefinitions*'
            }
        }
    }

    Context 'Entra role with multiple rolePermissions entries' {

        It 'Uses only the first rolePermissions entry (index 0)' {
            $roleDefMultiPermissions = [PSCustomObject]@{
                id = '<entra-role-def-1>'
                rolePermissions = @(
                    [PSCustomObject]@{
                        allowedResourceActions = @(
                            'microsoft.directory/users/basic/update'
                        )
                    },
                    [PSCustomObject]@{
                        allowedResourceActions = @(
                            'microsoft.directory/groups/create',
                            'microsoft.directory/groups/delete'
                        )
                    }
                )
            }

            Mock Invoke-PAGraphRequest { @($roleDefMultiPermissions) }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment) -Session $mockSession

            # Only the first entry's actions should be present
            $result['<entra-role-def-1>'] | Should -HaveCount 1
            $result['<entra-role-def-1>'] | Should -Contain 'microsoft.directory/users/basic/update'
            $result['<entra-role-def-1>'] | Should -Not -Contain 'microsoft.directory/groups/create'
        }
    }

    Context 'Azure RBAC role resolution' {

        BeforeEach {
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }
        }

        It 'Returns a hashtable entry for the Azure RBAC role definition ID' {
            $result = Resolve-PARoleAction -Assignments @($mockAzureAssignment) -Session $mockSession

            $result.ContainsKey('<rbac-role-def-1>') | Should -Be $true
        }

        It 'Includes Actions in the mapped action strings' {
            $result = Resolve-PARoleAction -Assignments @($mockAzureAssignment) -Session $mockSession

            $result['<rbac-role-def-1>'] | Should -Contain 'Microsoft.Compute/virtualMachines/*'
            $result['<rbac-role-def-1>'] | Should -Contain 'Microsoft.Network/networkInterfaces/read'
        }

        It 'Includes DataActions in the mapped action strings' {
            $result = Resolve-PARoleAction -Assignments @($mockAzureAssignment) -Session $mockSession

            $result['<rbac-role-def-1>'] | Should -Contain 'Microsoft.Compute/virtualMachines/login/action'
        }

        It 'Calls Get-AzRoleDefinition once per unique subscription scope' {
            Resolve-PARoleAction -Assignments @($mockAzureAssignment) -Session $mockSession

            Should -Invoke Get-AzRoleDefinition -Exactly -Times 1
        }
    }

    Context 'Azure RBAC wildcard filtering' {

        It 'Filters out actions that start with asterisk (bare wildcard provider)' {
            $ownerRoleDef = [PSCustomObject]@{
                Id             = '<rbac-role-def-owner>'
                Name           = 'Owner'
                IsCustom       = $false
                Actions        = @('*')
                NotActions     = @()
                DataActions    = @()
                NotDataActions = @()
            }

            $ownerAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<rbac-role-def-owner>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-1>'
            }

            Mock Get-AzRoleDefinition { $ownerRoleDef }

            $result = Resolve-PARoleAction -Assignments @($ownerAssignment) -Session $mockSession

            $result['<rbac-role-def-owner>'] | Should -Not -Contain '*'
        }

        It 'Filters out actions that start with asterisk like */read' {
            $readerRoleDef = [PSCustomObject]@{
                Id             = '<rbac-role-def-reader>'
                Name           = 'Reader'
                IsCustom       = $false
                Actions        = @('*/read')
                NotActions     = @()
                DataActions    = @()
                NotDataActions = @()
            }

            $readerAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<rbac-role-def-reader>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-1>'
            }

            Mock Get-AzRoleDefinition { $readerRoleDef }

            $result = Resolve-PARoleAction -Assignments @($readerAssignment) -Session $mockSession

            $result['<rbac-role-def-reader>'] | Should -Not -Contain '*/read'
        }
    }

    Context 'Azure RBAC specific-provider wildcards kept' {

        It 'Retains provider-specific wildcard actions that do not start with asterisk' {
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $result = Resolve-PARoleAction -Assignments @($mockAzureAssignment) -Session $mockSession

            # Microsoft.Compute/virtualMachines/* starts with 'M', not '*' — must be kept
            $result['<rbac-role-def-1>'] | Should -Contain 'Microsoft.Compute/virtualMachines/*'
        }
    }

    Context 'Mixed Entra and Azure RBAC sources' {

        It 'Resolves both Entra and Azure RBAC assignments in one call' {
            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession

            $result.ContainsKey('<entra-role-def-1>') | Should -Be $true
            $result.ContainsKey('<rbac-role-def-1>') | Should -Be $true
        }

        It 'Produces correct action lists for each source independently' {
            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession

            $result['<entra-role-def-1>'] | Should -Contain 'microsoft.directory/users/basic/update'
            $result['<rbac-role-def-1>'] | Should -Contain 'Microsoft.Compute/virtualMachines/*'
        }
    }

    Context 'Deduplication' {

        It 'Returns only one hashtable entry when the same RoleDefinitionId appears on multiple assignments' {
            $duplicateAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-2>'
                RoleDefinitionId = '<entra-role-def-1>'
                Source           = 'EntraRole'
                Scope            = '/'
            }

            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment, $duplicateAssignment) -Session $mockSession

            ($result.Keys | Where-Object { $_ -eq '<entra-role-def-1>' }).Count | Should -Be 1
        }

        It 'Queries Graph API only once per unique role definition despite duplicate assignments' {
            $duplicateAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-2>'
                RoleDefinitionId = '<entra-role-def-1>'
                Source           = 'EntraRole'
                Scope            = '/'
            }

            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }

            Resolve-PARoleAction -Assignments @($mockEntraAssignment, $duplicateAssignment) -Session $mockSession

            Should -Invoke Invoke-PAGraphRequest -Exactly -Times 1
        }
    }

    Context 'AppPermission source skipped' {

        It 'Produces no map entry for AppPermission assignments' {
            Mock Invoke-PAGraphRequest { @() }
            Mock Get-AzRoleDefinition { $null }

            $result = Resolve-PARoleAction -Assignments @($mockAppPermAssignment) -Session $mockSession

            $result.ContainsKey('<app-role-def-1>') | Should -Be $false
        }

        It 'Does not call any external API for AppPermission-only assignments' {
            Mock Invoke-PAGraphRequest { @() }
            Mock Get-AzRoleDefinition { $null }

            Resolve-PARoleAction -Assignments @($mockAppPermAssignment) -Session $mockSession

            Should -Invoke Invoke-PAGraphRequest -Exactly -Times 0
            Should -Invoke Get-AzRoleDefinition -Exactly -Times 0
        }
    }

    Context 'PIM sources' {

        It 'Resolves PimEntra assignments using Graph roleDefinitions endpoint' {
            $pimEntraAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<entra-role-def-1>'
                Source           = 'PimEntra'
                Scope            = '/'
            }

            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }

            $result = Resolve-PARoleAction -Assignments @($pimEntraAssignment) -Session $mockSession

            $result.ContainsKey('<entra-role-def-1>') | Should -Be $true
            $result['<entra-role-def-1>'] | Should -Contain 'microsoft.directory/users/basic/update'
        }

        It 'Resolves PimAzure assignments using Get-AzRoleDefinition' {
            $pimAzureAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<rbac-role-def-1>'
                Source           = 'PimAzure'
                Scope            = '/subscriptions/<sub-id-1>/resourceGroups/<rg-1>'
            }

            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $result = Resolve-PARoleAction -Assignments @($pimAzureAssignment) -Session $mockSession

            $result.ContainsKey('<rbac-role-def-1>') | Should -Be $true
            $result['<rbac-role-def-1>'] | Should -Contain 'Microsoft.Compute/virtualMachines/*'
        }

        It 'Treats PimEntra identically to EntraRole for action extraction' {
            $entraAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<entra-role-def-1>'
                Source           = 'EntraRole'
                Scope            = '/'
            }

            $pimEntraAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-2>'
                RoleDefinitionId = '<entra-role-def-1>'
                Source           = 'PimEntra'
                Scope            = '/'
            }

            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }

            $resultEntra = Resolve-PARoleAction -Assignments @($entraAssignment) -Session $mockSession
            $resultPim   = Resolve-PARoleAction -Assignments @($pimEntraAssignment) -Session $mockSession

            $resultEntra['<entra-role-def-1>'] | Should -Be $resultPim['<entra-role-def-1>']
        }

        It 'Treats PimAzure identically to AzureRbac for action extraction' {
            $azureAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<rbac-role-def-1>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-1>/resourceGroups/<rg-1>'
            }

            $pimAzureAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-2>'
                RoleDefinitionId = '<rbac-role-def-1>'
                Source           = 'PimAzure'
                Scope            = '/subscriptions/<sub-id-1>/resourceGroups/<rg-1>'
            }

            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $resultAzure  = Resolve-PARoleAction -Assignments @($azureAssignment) -Session $mockSession
            $resultPimAz  = Resolve-PARoleAction -Assignments @($pimAzureAssignment) -Session $mockSession

            $resultAzure['<rbac-role-def-1>'] | Should -Be $resultPimAz['<rbac-role-def-1>']
        }
    }

    Context 'Subscription scope extraction' {

        It 'Extracts subscription ID from assignment Scope to determine Get-AzRoleDefinition scope' {
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            Resolve-PARoleAction -Assignments @($mockAzureAssignment) -Session $mockSession

            Should -Invoke Get-AzRoleDefinition -ParameterFilter {
                $Scope -like '*<sub-id-1>*'
            }
        }

        It 'Queries Get-AzRoleDefinition once per unique subscription' {
            $assignmentSub1 = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<rbac-role-def-1>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-1>/resourceGroups/<rg-1>'
            }

            $assignmentSub2 = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-2>'
                RoleDefinitionId = '<rbac-role-def-2>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-2>/resourceGroups/<rg-2>'
            }

            $rbacRoleDef2 = [PSCustomObject]@{
                Id             = '<rbac-role-def-2>'
                Name           = 'Storage Blob Data Reader'
                IsCustom       = $false
                Actions        = @('Microsoft.Storage/storageAccounts/blobServices/containers/read')
                NotActions     = @()
                DataActions    = @('Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read')
                NotDataActions = @()
            }

            $script:subCallCount = 0
            Mock Get-AzRoleDefinition {
                $script:subCallCount++
                if ($Scope -like '*<sub-id-1>*') { $mockAzureRoleDef } else { $rbacRoleDef2 }
            }

            Resolve-PARoleAction -Assignments @($assignmentSub1, $assignmentSub2) -Session $mockSession

            Should -Invoke Get-AzRoleDefinition -Exactly -Times 2
        }

        It 'Does not issue duplicate subscription queries for multiple assignments in the same subscription' {
            $assignmentA = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<rbac-role-def-1>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-1>/resourceGroups/<rg-1>'
            }

            $assignmentB = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-2>'
                RoleDefinitionId = '<rbac-role-def-2>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-1>/resourceGroups/<rg-2>'
            }

            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            Resolve-PARoleAction -Assignments @($assignmentA, $assignmentB) -Session $mockSession

            Should -Invoke Get-AzRoleDefinition -Exactly -Times 1
        }
    }

    Context 'Entra resolution failure' {

        It 'Returns Azure RBAC results when Graph API throws' {
            Mock Invoke-PAGraphRequest { throw 'Graph API unavailable' }
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession

            $result.ContainsKey('<rbac-role-def-1>') | Should -Be $true
        }

        It 'Omits Entra entries from result when Graph API throws' {
            Mock Invoke-PAGraphRequest { throw 'Graph API unavailable' }
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession

            $result.ContainsKey('<entra-role-def-1>') | Should -Be $false
        }

        It 'Emits a warning when Entra resolution fails' {
            Mock Invoke-PAGraphRequest { throw 'Graph API unavailable' }
            Mock Get-AzRoleDefinition { $mockAzureRoleDef }

            $warnings = $null
            Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession -WarningVariable warnings

            $warnings | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Azure resolution failure' {

        It 'Returns Entra results when Get-AzRoleDefinition throws' {
            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }
            Mock Get-AzRoleDefinition { throw 'Az module unavailable' }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession

            $result.ContainsKey('<entra-role-def-1>') | Should -Be $true
        }

        It 'Omits Azure RBAC entries from result when Get-AzRoleDefinition throws' {
            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }
            Mock Get-AzRoleDefinition { throw 'Az module unavailable' }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession

            $result.ContainsKey('<rbac-role-def-1>') | Should -Be $false
        }

        It 'Emits a warning when Azure resolution fails' {
            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }
            Mock Get-AzRoleDefinition { throw 'Az module unavailable' }

            $warnings = $null
            Resolve-PARoleAction -Assignments @($mockEntraAssignment, $mockAzureAssignment) -Session $mockSession -WarningVariable warnings

            $warnings | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Role definition not found' {

        It 'Omits the role definition ID when Graph API returns no matching definition' {
            $orphanAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<entra-role-def-orphan>'
                Source           = 'EntraRole'
                Scope            = '/'
            }

            # Graph returns a definition for a different ID — not the one requested
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id = '<entra-role-def-other>'
                        rolePermissions = @(
                            [PSCustomObject]@{
                                allowedResourceActions = @('microsoft.directory/users/read')
                            }
                        )
                    }
                )
            }

            $result = Resolve-PARoleAction -Assignments @($orphanAssignment) -Session $mockSession

            $result.ContainsKey('<entra-role-def-orphan>') | Should -Be $false
        }

        It 'Omits the role definition ID when Get-AzRoleDefinition returns null' {
            $orphanAzureAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<rbac-role-def-orphan>'
                Source           = 'AzureRbac'
                Scope            = '/subscriptions/<sub-id-1>'
            }

            Mock Get-AzRoleDefinition { $null }

            $result = Resolve-PARoleAction -Assignments @($orphanAzureAssignment) -Session $mockSession

            $result.ContainsKey('<rbac-role-def-orphan>') | Should -Be $false
        }

        It 'Does not throw when a role definition ID is missing from fetched results' {
            $orphanAssignment = [PSCustomObject]@{
                PSTypeName       = 'PA.Assignment'
                PrincipalId      = '<principal-user-1>'
                RoleDefinitionId = '<entra-role-def-orphan>'
                Source           = 'EntraRole'
                Scope            = '/'
            }

            Mock Invoke-PAGraphRequest { @() }

            { Resolve-PARoleAction -Assignments @($orphanAssignment) -Session $mockSession } | Should -Not -Throw
        }
    }

    Context 'Return type' {

        It 'Always returns a hashtable' {
            Mock Invoke-PAGraphRequest { @($mockEntraRoleDef) }

            $result = Resolve-PARoleAction -Assignments @($mockEntraAssignment) -Session $mockSession

            $result | Should -BeOfType [hashtable]
        }
    }
}
