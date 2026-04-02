#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Get-PAAzureRbacAssignment.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAAssignment.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')

    # Stubs for external cmdlets
    function Get-AzRoleAssignment { param($Scope, $ErrorAction) }
    function Get-AzRoleDefinition { param($Scope, $ErrorAction) }
}

Describe 'Get-PAAzureRbacAssignment' {

    BeforeAll {
        $mockSession = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            SubscriptionIds = @('<sub-id-1>')
        }

        $mockSessionMultiSub = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            SubscriptionIds = @('<sub-id-1>', '<sub-id-2>')
        }

        $mockSessionNoSubs = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            SubscriptionIds = @()
        }

        $mockRoleDefinitions = @(
            [PSCustomObject]@{
                Id       = '<role-def-contributor>'
                Name     = 'Contributor'
                IsCustom = $false
            },
            [PSCustomObject]@{
                Id       = '<role-def-reader>'
                Name     = 'Reader'
                IsCustom = $false
            },
            [PSCustomObject]@{
                Id       = '<role-def-custom>'
                Name     = 'Custom Deploy Role'
                IsCustom = $true
            }
        )

        $mockAssignments = @(
            [PSCustomObject]@{
                RoleAssignmentId   = '/subscriptions/<sub-id-1>/providers/Microsoft.Authorization/roleAssignments/<ra-1>'
                RoleAssignmentName = '<ra-1>'
                Scope              = '/subscriptions/<sub-id-1>'
                DisplayName        = 'Alice Admin'
                SignInName         = 'alice@contoso.com'
                RoleDefinitionName = 'Contributor'
                RoleDefinitionId   = '<role-def-contributor>'
                ObjectId           = '<principal-user>'
                ObjectType         = 'User'
                CanDelegate        = $false
                Description        = ''
                Condition          = ''
                ConditionVersion   = ''
            },
            [PSCustomObject]@{
                RoleAssignmentId   = '/subscriptions/<sub-id-1>/providers/Microsoft.Authorization/roleAssignments/<ra-2>'
                RoleAssignmentName = '<ra-2>'
                Scope              = '/subscriptions/<sub-id-1>/resourceGroups/rg-prod'
                DisplayName        = 'DevOps Group'
                SignInName         = ''
                RoleDefinitionName = 'Custom Deploy Role'
                RoleDefinitionId   = '<role-def-custom>'
                ObjectId           = '<principal-group>'
                ObjectType         = 'Group'
                CanDelegate        = $false
                Description        = ''
                Condition          = ''
                ConditionVersion   = ''
            },
            [PSCustomObject]@{
                RoleAssignmentId   = '/subscriptions/<sub-id-1>/providers/Microsoft.Authorization/roleAssignments/<ra-3>'
                RoleAssignmentName = '<ra-3>'
                Scope              = '/subscriptions/<sub-id-1>/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/stprod'
                DisplayName        = 'Storage App'
                SignInName         = ''
                RoleDefinitionName = 'Reader'
                RoleDefinitionId   = '<role-def-reader>'
                ObjectId           = '<principal-sp>'
                ObjectType         = 'ServicePrincipal'
                CanDelegate        = $false
                Description        = ''
                Condition          = ''
                ConditionVersion   = ''
            }
        )
    }

    Context 'Happy path' {

        BeforeEach {
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { $mockAssignments }
        }

        It 'Returns PA.CollectorResult type' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Status is Complete with clean data' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Status | Should -Be 'Complete'
        }

        It 'ItemCount matches assignment count' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.ItemCount | Should -Be 3
        }

        It 'Collector name is correct' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Collector | Should -Be 'Get-PAAzureRbacAssignment'
        }

        It 'Duration is populated' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Duration.TotalMilliseconds | Should -BeGreaterThan 0
        }

        It 'All items are PA.Assignment type' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.Assignment'
            }
        }
    }

    Context 'Property mapping' {

        BeforeEach {
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { $mockAssignments }
        }

        It 'Maps ObjectId to PrincipalId' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $item | Should -Not -BeNullOrEmpty
        }

        It 'Maps ObjectType to PrincipalType' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $userItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userItem.PrincipalType | Should -Be 'User'

            $groupItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-group>' }
            $groupItem.PrincipalType | Should -Be 'Group'

            $spItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-sp>' }
            $spItem.PrincipalType | Should -Be 'ServicePrincipal'
        }

        It 'Sets PrincipalDisplayName from DisplayName' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $item.PrincipalDisplayName | Should -Be 'Alice Admin'
        }

        It 'Sets RoleName from RoleDefinitionName' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $item.RoleName | Should -Be 'Contributor'
        }

        It 'Sets RoleDefinitionId from cmdlet output' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $item.RoleDefinitionId | Should -Be '<role-def-contributor>'
        }

        It 'Preserves full Scope from cmdlet output' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-group>' }
            $item.Scope | Should -Be '/subscriptions/<sub-id-1>/resourceGroups/rg-prod'
        }
    }

    Context 'RoleType enrichment' {

        BeforeEach {
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { $mockAssignments }
        }

        It 'Sets RoleType to BuiltIn for built-in roles' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.RoleDefinitionId -eq '<role-def-contributor>' }
            $item.RoleType | Should -Be 'BuiltIn'
        }

        It 'Sets RoleType to Custom for custom roles' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.RoleDefinitionId -eq '<role-def-custom>' }
            $item.RoleType | Should -Be 'Custom'
        }

        It 'Sets RoleType to empty when role definition unavailable' {
            Mock Get-AzRoleDefinition { throw 'Access denied' }

            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Items | ForEach-Object { $_.RoleType | Should -Be '' }
            $result.Status | Should -Be 'Partial'
        }
    }

    Context 'ScopeType classification' {

        BeforeEach {
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { $mockAssignments }
        }

        It 'Maps subscription scope to Subscription' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.Scope -eq '/subscriptions/<sub-id-1>' }
            $item.ScopeType | Should -Be 'Subscription'
        }

        It 'Maps resource group scope to ResourceGroup' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.Scope -like '*/resourceGroups/rg-prod' }
            $item.ScopeType | Should -Be 'ResourceGroup'
        }

        It 'Maps resource scope to Resource' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $item = $result.Items | Where-Object { $_.Scope -like '*/storageAccounts/*' }
            $item.ScopeType | Should -Be 'Resource'
        }

        It 'Maps management group scope to ManagementGroup' {
            $mgAssignment = @(
                [PSCustomObject]@{
                    RoleAssignmentId   = '/providers/Microsoft.Management/managementGroups/mg-root/providers/Microsoft.Authorization/roleAssignments/<ra-mg>'
                    RoleAssignmentName = '<ra-mg>'
                    Scope              = '/providers/Microsoft.Management/managementGroups/mg-root'
                    DisplayName        = 'MG Admin'
                    SignInName         = ''
                    RoleDefinitionName = 'Reader'
                    RoleDefinitionId   = '<role-def-reader>'
                    ObjectId           = '<principal-mg>'
                    ObjectType         = 'User'
                    CanDelegate        = $false
                    Description        = ''
                    Condition          = ''
                    ConditionVersion   = ''
                }
            )
            Mock Get-AzRoleAssignment { $mgAssignment }

            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Items[0].ScopeType | Should -Be 'ManagementGroup'
        }
    }

    Context 'Fixed field values' {

        BeforeEach {
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { $mockAssignments }
        }

        It 'Source is always AzureRbac' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Items | ForEach-Object { $_.Source | Should -Be 'AzureRbac' }
        }

        It 'AssignmentType is always Direct' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Items | ForEach-Object { $_.AssignmentType | Should -Be 'Direct' }
        }

        It 'Status defaults to Active' {
            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Items | ForEach-Object { $_.Status | Should -Be 'Active' }
        }
    }

    Context 'Unknown ObjectType' {

        It 'Maps Unknown to User with warning' {
            $unknownAssignment = @(
                [PSCustomObject]@{
                    RoleAssignmentId   = '/subscriptions/<sub-id-1>/providers/Microsoft.Authorization/roleAssignments/<ra-unknown>'
                    RoleAssignmentName = '<ra-unknown>'
                    Scope              = '/subscriptions/<sub-id-1>'
                    DisplayName        = ''
                    SignInName         = ''
                    RoleDefinitionName = 'Reader'
                    RoleDefinitionId   = '<role-def-reader>'
                    ObjectId           = '<deleted-principal>'
                    ObjectType         = 'Unknown'
                    CanDelegate        = $false
                    Description        = ''
                    Condition          = ''
                    ConditionVersion   = ''
                }
            )
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { $unknownAssignment }

            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Items[0].PrincipalType | Should -Be 'User'
            $result.Status | Should -Be 'Partial'
            $result.Warnings | Where-Object { $_ -like '*Unknown ObjectType*' } | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Deduplication' {

        It 'Deduplicates inherited assignments across subscriptions' {
            $inheritedAssignment = [PSCustomObject]@{
                RoleAssignmentId   = '/providers/Microsoft.Management/managementGroups/mg-root/providers/Microsoft.Authorization/roleAssignments/<ra-inherited>'
                RoleAssignmentName = '<ra-inherited>'
                Scope              = '/providers/Microsoft.Management/managementGroups/mg-root'
                DisplayName        = 'MG Admin'
                SignInName         = ''
                RoleDefinitionName = 'Reader'
                RoleDefinitionId   = '<role-def-reader>'
                ObjectId           = '<principal-mg>'
                ObjectType         = 'User'
                CanDelegate        = $false
                Description        = ''
                Condition          = ''
                ConditionVersion   = ''
            }
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { @($inheritedAssignment) }

            $result = Get-PAAzureRbacAssignment -Session $mockSessionMultiSub

            $result.ItemCount | Should -Be 1
        }
    }

    Context 'Per-subscription error isolation' {

        It 'Continues when one subscription fails' {
            $callCount = 0
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment {
                $callCount++
                if ($Scope -like '*<sub-id-1>*') {
                    throw 'Access denied'
                }
                $mockAssignments
            }

            $result = Get-PAAzureRbacAssignment -Session $mockSessionMultiSub

            $result.Status | Should -Be 'Partial'
            $result.ItemCount | Should -BeGreaterThan 0
        }

        It 'Returns Failed when all subscriptions fail' {
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { throw 'Access denied' }

            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Status | Should -Be 'Failed'
            $result.ItemCount | Should -Be 0
        }
    }

    Context 'No subscriptions' {

        It 'Returns Complete with 0 items and warning' {
            $result = Get-PAAzureRbacAssignment -Session $mockSessionNoSubs

            $result.Status | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
            $result.Warnings | Should -Contain 'No subscriptions in scope'
        }

        It 'Does not call Azure cmdlets' {
            Mock Get-AzRoleAssignment {}
            Mock Get-AzRoleDefinition {}

            Get-PAAzureRbacAssignment -Session $mockSessionNoSubs

            Should -Invoke Get-AzRoleAssignment -Exactly -Times 0
            Should -Invoke Get-AzRoleDefinition -Exactly -Times 0
        }
    }

    Context 'Empty subscription' {

        It 'Returns Complete with 0 items when no assignments found' {
            Mock Get-AzRoleDefinition { $mockRoleDefinitions }
            Mock Get-AzRoleAssignment { @() }

            $result = Get-PAAzureRbacAssignment -Session $mockSession

            $result.Status | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }
    }
}
