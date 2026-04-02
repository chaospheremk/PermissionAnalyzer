#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Get-PAPimEligibility.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PAGraphRequest.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAAssignment.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Resolve-PAPrincipal.ps1')

    # Stubs for external cmdlets
    function Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) }
    function Get-AzRoleEligibilityScheduleInstance { param($Scope, $ErrorAction) }
}

Describe 'Get-PAPimEligibility' {

    BeforeAll {
        $mockSession = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            SubscriptionIds = @('<sub-id-1>')
        }

        $mockSessionNoSubs = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            SubscriptionIds = @()
        }

        $mockRoleDefinitions = @(
            [PSCustomObject]@{
                id          = '<role-def-ga>'
                displayName = 'Global Administrator'
                isBuiltIn   = $true
            },
            [PSCustomObject]@{
                id          = '<role-def-custom>'
                displayName = 'Custom Helpdesk Role'
                isBuiltIn   = $false
            }
        )

        $mockEntraEligibilities = @(
            [PSCustomObject]@{
                id                = '<elig-1>'
                principalId       = '<principal-user>'
                roleDefinitionId  = '<role-def-ga>'
                directoryScopeId  = '/'
                startDateTime     = '2026-01-01T00:00:00Z'
                endDateTime       = '2026-07-01T00:00:00Z'
                memberType        = 'Direct'
                principal         = [PSCustomObject]@{
                    '@odata.type' = '#microsoft.graph.user'
                    id            = '<principal-user>'
                    displayName   = 'Alice Admin'
                }
            },
            [PSCustomObject]@{
                id                = '<elig-2>'
                principalId       = '<principal-group>'
                roleDefinitionId  = '<role-def-custom>'
                directoryScopeId  = '/administrativeUnits/<au-id>'
                startDateTime     = '2026-03-01T00:00:00Z'
                endDateTime       = $null
                memberType        = 'Direct'
                principal         = [PSCustomObject]@{
                    '@odata.type' = '#microsoft.graph.group'
                    id            = '<principal-group>'
                    displayName   = 'Helpdesk Group'
                }
            }
        )

        $mockAzureEligibilities = @(
            [PSCustomObject]@{
                PrincipalId               = '<az-principal-user>'
                PrincipalType             = 'User'
                PrincipalDisplayName      = 'Bob Operator'
                RoleDefinitionId          = '/subscriptions/<sub-id-1>/providers/Microsoft.Authorization/roleDefinitions/<az-role-guid>'
                RoleDefinitionDisplayName = 'Contributor'
                RoleDefinitionType        = 'BuiltInRole'
                Scope                     = '/subscriptions/<sub-id-1>'
                ScopeType                 = 'subscription'
                StartDateTime             = [datetime]'2026-02-01T00:00:00Z'
                EndDateTime               = [datetime]'2026-08-01T00:00:00Z'
                Status                    = 'Provisioned'
                MemberType                = 'Direct'
            },
            [PSCustomObject]@{
                PrincipalId               = '<az-principal-sp>'
                PrincipalType             = 'ServicePrincipal'
                PrincipalDisplayName      = 'Deploy App'
                RoleDefinitionId          = '/subscriptions/<sub-id-1>/providers/Microsoft.Authorization/roleDefinitions/<az-custom-guid>'
                RoleDefinitionDisplayName = 'Custom Deploy Role'
                RoleDefinitionType        = 'CustomRole'
                Scope                     = '/subscriptions/<sub-id-1>/resourceGroups/rg-prod'
                ScopeType                 = 'resourcegroup'
                StartDateTime             = [datetime]'2026-01-15T00:00:00Z'
                EndDateTime               = $null
                Status                    = 'Provisioned'
                MemberType                = 'Direct'
            }
        )
    }

    Context 'Happy path — both sources' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                $mockEntraEligibilities
            }
            Mock Get-AzRoleEligibilityScheduleInstance { $mockAzureEligibilities }
        }

        It 'Returns PA.CollectorResult type' {
            $result = Get-PAPimEligibility -Session $mockSession

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Status is Complete with clean data' {
            $result = Get-PAPimEligibility -Session $mockSession

            $result.Status | Should -Be 'Complete'
        }

        It 'ItemCount includes both sources' {
            $result = Get-PAPimEligibility -Session $mockSession

            $result.ItemCount | Should -Be 4
        }

        It 'Collector name is correct' {
            $result = Get-PAPimEligibility -Session $mockSession

            $result.Collector | Should -Be 'Get-PAPimEligibility'
        }

        It 'Duration is populated' {
            $result = Get-PAPimEligibility -Session $mockSession

            $result.Duration.TotalMilliseconds | Should -BeGreaterThan 0
        }

        It 'All items are PA.Assignment type' {
            $result = Get-PAPimEligibility -Session $mockSession

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.Assignment'
            }
        }
    }

    Context 'Entra PIM mapping' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                $mockEntraEligibilities
            }
            Mock Get-AzRoleEligibilityScheduleInstance { @() }
        }

        It 'Maps principal type from @odata.type' {
            $result = Get-PAPimEligibility -Session $mockSession

            $userItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userItem.PrincipalType | Should -Be 'User'

            $groupItem = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-group>' }
            $groupItem.PrincipalType | Should -Be 'Group'
        }

        It 'Sets RoleName and RoleType from role definitions' {
            $result = Get-PAPimEligibility -Session $mockSession

            $gaItem = $result.Items | Where-Object { $_.RoleDefinitionId -eq '<role-def-ga>' }
            $gaItem.RoleName | Should -Be 'Global Administrator'
            $gaItem.RoleType | Should -Be 'BuiltIn'

            $customItem = $result.Items | Where-Object { $_.RoleDefinitionId -eq '<role-def-custom>' }
            $customItem.RoleName | Should -Be 'Custom Helpdesk Role'
            $customItem.RoleType | Should -Be 'Custom'
        }

        It 'Maps scope types correctly' {
            $result = Get-PAPimEligibility -Session $mockSession

            $tenantItem = $result.Items | Where-Object { $_.Scope -eq '/' }
            $tenantItem.ScopeType | Should -Be 'Tenant'

            $auItem = $result.Items | Where-Object { $_.Scope -like '/administrativeUnits/*' }
            $auItem.ScopeType | Should -Be 'AdministrativeUnit'
        }

        It 'Parses StartDateTime and EndDateTime' {
            $result = Get-PAPimEligibility -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $item.StartDateTime | Should -Not -BeNullOrEmpty
            $item.EndDateTime | Should -Not -BeNullOrEmpty
        }

        It 'Handles null EndDateTime for permanent eligibility' {
            $result = Get-PAPimEligibility -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-group>' }
            $item.EndDateTime | Should -BeNullOrEmpty
        }

        It 'Sets fixed fields for Entra PIM' {
            $result = Get-PAPimEligibility -Session $mockSession

            $entraItems = $result.Items | Where-Object { $_.Source -eq 'PimEntra' }
            $entraItems | Should -HaveCount 2
            $entraItems | ForEach-Object {
                $_.AssignmentType | Should -Be 'Eligible'
                $_.Status | Should -Be 'Eligible'
            }
        }
    }

    Context 'Azure PIM mapping' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                @()
            }
            Mock Get-AzRoleEligibilityScheduleInstance { $mockAzureEligibilities }
        }

        It 'Maps PrincipalType directly from cmdlet' {
            $result = Get-PAPimEligibility -Session $mockSession

            $userItem = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-user>' }
            $userItem.PrincipalType | Should -Be 'User'

            $spItem = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-sp>' }
            $spItem.PrincipalType | Should -Be 'ServicePrincipal'
        }

        It 'Sets PrincipalDisplayName from cmdlet' {
            $result = Get-PAPimEligibility -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-user>' }
            $item.PrincipalDisplayName | Should -Be 'Bob Operator'
        }

        It 'Sets RoleName from RoleDefinitionDisplayName' {
            $result = Get-PAPimEligibility -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-user>' }
            $item.RoleName | Should -Be 'Contributor'
        }

        It 'Maps RoleType from RoleDefinitionType' {
            $result = Get-PAPimEligibility -Session $mockSession

            $builtInItem = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-user>' }
            $builtInItem.RoleType | Should -Be 'BuiltIn'

            $customItem = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-sp>' }
            $customItem.RoleType | Should -Be 'Custom'
        }

        It 'Extracts GUID from ARM RoleDefinitionId' {
            $result = Get-PAPimEligibility -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-user>' }
            $item.RoleDefinitionId | Should -Be '<az-role-guid>'
        }

        It 'Maps ScopeType from cmdlet property' {
            $result = Get-PAPimEligibility -Session $mockSession

            $subItem = $result.Items | Where-Object { $_.Scope -eq '/subscriptions/<sub-id-1>' }
            $subItem.ScopeType | Should -Be 'Subscription'

            $rgItem = $result.Items | Where-Object { $_.Scope -like '*/resourceGroups/*' }
            $rgItem.ScopeType | Should -Be 'ResourceGroup'
        }

        It 'Sets fixed fields for Azure PIM' {
            $result = Get-PAPimEligibility -Session $mockSession

            $azItems = $result.Items | Where-Object { $_.Source -eq 'PimAzure' }
            $azItems | Should -HaveCount 2
            $azItems | ForEach-Object {
                $_.AssignmentType | Should -Be 'Eligible'
                $_.Status | Should -Be 'Eligible'
            }
        }

        It 'Preserves StartDateTime and EndDateTime' {
            $result = Get-PAPimEligibility -Session $mockSession

            $item = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-user>' }
            $item.StartDateTime | Should -Not -BeNullOrEmpty
            $item.EndDateTime | Should -Not -BeNullOrEmpty

            $permItem = $result.Items | Where-Object { $_.PrincipalId -eq '<az-principal-sp>' }
            $permItem.EndDateTime | Should -BeNullOrEmpty
        }
    }

    Context 'No subscriptions' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                $mockEntraEligibilities
            }
            Mock Get-AzRoleEligibilityScheduleInstance {}
        }

        It 'Collects only Entra PIM when no subscriptions' {
            $result = Get-PAPimEligibility -Session $mockSessionNoSubs

            $result.ItemCount | Should -Be 2
            $result.Items | ForEach-Object { $_.Source | Should -Be 'PimEntra' }
        }

        It 'Does not call Azure PIM cmdlet' {
            Get-PAPimEligibility -Session $mockSessionNoSubs

            Should -Invoke Get-AzRoleEligibilityScheduleInstance -Exactly -Times 0
        }

        It 'Status is Complete when Entra PIM succeeds' {
            $result = Get-PAPimEligibility -Session $mockSessionNoSubs

            $result.Status | Should -Be 'Complete'
        }
    }

    Context 'Expand fallback' {

        It 'Falls back to Resolve-PAPrincipal when expand not available' {
            $noExpandEligibilities = @(
                [PSCustomObject]@{
                    id                = '<elig-noexpand>'
                    principalId       = '<principal-user>'
                    roleDefinitionId  = '<role-def-ga>'
                    directoryScopeId  = '/'
                    startDateTime     = '2026-01-01T00:00:00Z'
                    endDateTime       = $null
                    memberType        = 'Direct'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                $noExpandEligibilities
            }
            Mock Get-AzRoleEligibilityScheduleInstance { @() }
            Mock Resolve-PAPrincipal {
                @{ '<principal-user>' = 'Resolved Name' }
            }

            $result = Get-PAPimEligibility -Session $mockSession

            Should -Invoke Resolve-PAPrincipal -Exactly -Times 1
            $result.Items[0].PrincipalDisplayName | Should -Be 'Resolved Name'
            $result.Items[0].PrincipalType | Should -Be 'User'
            $result.Status | Should -Be 'Partial'
        }
    }

    Context 'Graceful degradation' {

        It 'Returns Partial when Entra PIM fails but Azure succeeds' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                throw 'Graph API error: 403 Forbidden'
            }
            Mock Get-AzRoleEligibilityScheduleInstance { $mockAzureEligibilities }

            $result = Get-PAPimEligibility -Session $mockSession

            $result.Status | Should -Be 'Partial'
            $result.ItemCount | Should -Be 2
            $result.Items | ForEach-Object { $_.Source | Should -Be 'PimAzure' }
        }

        It 'Returns Partial when Azure PIM fails but Entra succeeds' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                $mockEntraEligibilities
            }
            Mock Get-AzRoleEligibilityScheduleInstance { throw 'Access denied' }

            $result = Get-PAPimEligibility -Session $mockSession

            $result.Status | Should -Be 'Partial'
            $result.ItemCount | Should -Be 2
            $result.Items | ForEach-Object { $_.Source | Should -Be 'PimEntra' }
        }

        It 'Returns Failed when both sources fail' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                throw 'Graph error'
            }
            Mock Get-AzRoleEligibilityScheduleInstance { throw 'ARM error' }

            $result = Get-PAPimEligibility -Session $mockSession

            $result.Status | Should -Be 'Failed'
            $result.ItemCount | Should -Be 0
        }

        It 'Returns Failed when Entra fails and no subscriptions' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                throw 'Graph error'
            }

            $result = Get-PAPimEligibility -Session $mockSessionNoSubs

            $result.Status | Should -Be 'Failed'
        }
    }

    Context 'Empty results' {

        It 'Returns Complete with 0 items when both sources empty' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                @()
            }
            Mock Get-AzRoleEligibilityScheduleInstance { @() }

            $result = Get-PAPimEligibility -Session $mockSession

            $result.Status | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }
    }

    Context 'Deduplication' {

        It 'Deduplicates Azure PIM eligibilities across subscriptions' {
            $mockSessionMultiSub = [PSCustomObject]@{
                PSTypeName      = 'PA.Session'
                TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                Environment     = 'Global'
                SubscriptionIds = @('<sub-id-1>', '<sub-id-2>')
            }

            # Same eligibility returned from both subscriptions
            $duplicateEligibility = [PSCustomObject]@{
                PrincipalId               = '<az-principal-user>'
                PrincipalType             = 'User'
                PrincipalDisplayName      = 'Bob Operator'
                RoleDefinitionId          = '/providers/Microsoft.Authorization/roleDefinitions/<mg-role-guid>'
                RoleDefinitionDisplayName = 'Reader'
                RoleDefinitionType        = 'BuiltInRole'
                Scope                     = '/providers/Microsoft.Management/managementGroups/mg-root'
                ScopeType                 = 'managementgroup'
                StartDateTime             = [datetime]'2026-01-01T00:00:00Z'
                EndDateTime               = $null
                Status                    = 'Provisioned'
                MemberType                = 'Inherited'
            }

            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                @()
            }
            Mock Get-AzRoleEligibilityScheduleInstance { @($duplicateEligibility) }

            $result = Get-PAPimEligibility -Session $mockSessionMultiSub

            $azItems = $result.Items | Where-Object { $_.Source -eq 'PimAzure' }
            $azItems | Should -HaveCount 1
        }
    }

    Context 'ForeignGroup principal type' {

        It 'Maps ForeignGroup to Group with warning' {
            $foreignGroupElig = @(
                [PSCustomObject]@{
                    PrincipalId               = '<az-foreign-group>'
                    PrincipalType             = 'ForeignGroup'
                    PrincipalDisplayName      = 'External Group'
                    RoleDefinitionId          = '/subscriptions/<sub-id-1>/providers/Microsoft.Authorization/roleDefinitions/<az-role-guid>'
                    RoleDefinitionDisplayName = 'Reader'
                    RoleDefinitionType        = 'BuiltInRole'
                    Scope                     = '/subscriptions/<sub-id-1>'
                    ScopeType                 = 'subscription'
                    StartDateTime             = [datetime]'2026-01-01T00:00:00Z'
                    EndDateTime               = $null
                    Status                    = 'Provisioned'
                    MemberType                = 'Direct'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleDefinitions*' } {
                $mockRoleDefinitions
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/roleEligibilityScheduleInstances*' } {
                @()
            }
            Mock Get-AzRoleEligibilityScheduleInstance { $foreignGroupElig }

            $result = Get-PAPimEligibility -Session $mockSession

            $result.Items[0].PrincipalType | Should -Be 'Group'
            $result.Status | Should -Be 'Partial'
            $result.Warnings | Where-Object { $_ -like '*ForeignGroup*' } | Should -Not -BeNullOrEmpty
        }
    }
}
