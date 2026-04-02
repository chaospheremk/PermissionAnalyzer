#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Get-PAAppPermission.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PAGraphRequest.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAAssignment.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')

    # Stub for Invoke-MgGraphRequest (needed by Invoke-PAGraphRequest)
    function Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) }
}

Describe 'Get-PAAppPermission' {

    BeforeAll {
        $mockSession = [PSCustomObject]@{
            PSTypeName  = 'PA.Session'
            TenantId    = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment = 'Global'
        }

        $mockServicePrincipals = @(
            [PSCustomObject]@{
                id          = '<sp-client-1>'
                displayName = 'My Client App'
                appId       = '<app-id-1>'
                appRoles    = @()
            },
            [PSCustomObject]@{
                id          = '<sp-resource-graph>'
                displayName = 'Microsoft Graph'
                appId       = '<graph-app-id>'
                appRoles    = @(
                    [PSCustomObject]@{ id = '<role-mail-read>'; value = 'Mail.Read' },
                    [PSCustomObject]@{ id = '<role-user-read-all>'; value = 'User.Read.All' }
                )
            }
        )

        $mockAppRoleAssignments = @(
            [PSCustomObject]@{
                id                   = '<ara-1>'
                appRoleId            = '<role-mail-read>'
                principalId          = '<sp-client-1>'
                principalDisplayName = 'My Client App'
                principalType        = 'ServicePrincipal'
                resourceId           = '<sp-resource-graph>'
                resourceDisplayName  = 'Microsoft Graph'
                createdDateTime      = '2026-01-15T10:30:00Z'
            }
        )

        $mockOAuth2Grants = @(
            [PSCustomObject]@{
                id          = '<grant-1>'
                clientId    = '<sp-client-1>'
                consentType = 'AllPrincipals'
                principalId = $null
                resourceId  = '<sp-resource-graph>'
                scope       = 'User.Read Group.ReadWrite.All'
            }
        )
    }

    Context 'Happy path' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                $mockServicePrincipals
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                if ($Uri -like "*<sp-client-1>*") { $mockAppRoleAssignments } else { @() }
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                $mockOAuth2Grants
            }
        }

        It 'Returns PA.CollectorResult type' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Status is Complete with clean data' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Status | Should -Be 'Complete'
        }

        It 'ItemCount includes both appRole and delegated assignments' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.ItemCount | Should -Be 2
        }

        It 'Collector name is correct' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Collector | Should -Be 'Get-PAAppPermission'
        }

        It 'Duration is populated' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Duration.TotalMilliseconds | Should -BeGreaterThan 0
        }

        It 'All items are PA.Assignment type' {
            $result = Get-PAAppPermission -Session $mockSession

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.Assignment'
            }
        }
    }

    Context 'appRoleAssignment mapping' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                $mockServicePrincipals
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                if ($Uri -like "*<sp-client-1>*") { $mockAppRoleAssignments } else { @() }
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                @()
            }
        }

        It 'Sets PrincipalId from principalId' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].PrincipalId | Should -Be '<sp-client-1>'
        }

        It 'Sets PrincipalDisplayName from inline principalDisplayName' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].PrincipalDisplayName | Should -Be 'My Client App'
        }

        It 'Maps PrincipalType from inline principalType' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].PrincipalType | Should -Be 'ServicePrincipal'
        }

        It 'Sets Scope and ResourceDisplayName from resourceDisplayName' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].Scope | Should -Be 'Microsoft Graph'
            $result.Items[0].ResourceDisplayName | Should -Be 'Microsoft Graph'
        }

        It 'Parses CreatedDateTime' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].CreatedDateTime | Should -Not -BeNullOrEmpty
        }

        It 'Sets fixed fields for appRole assignments' {
            $result = Get-PAAppPermission -Session $mockSession

            $item = $result.Items[0]
            $item.Source | Should -Be 'AppPermission'
            $item.AssignmentType | Should -Be 'AppRole'
            $item.RoleType | Should -Be 'AppRole'
            $item.ScopeType | Should -Be 'Application'
        }
    }

    Context 'appRoleId resolution' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                $mockServicePrincipals
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                @()
            }
        }

        It 'Resolves appRoleId to permission name' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                if ($Uri -like "*<sp-client-1>*") { $mockAppRoleAssignments } else { @() }
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].RoleName | Should -Be 'Mail.Read'
        }

        It 'Maps empty GUID to Default Access' {
            $defaultAccessAssignment = @(
                [PSCustomObject]@{
                    id                   = '<ara-default>'
                    appRoleId            = '00000000-0000-0000-0000-000000000000'
                    principalId          = '<sp-client-1>'
                    principalDisplayName = 'My Client App'
                    principalType        = 'ServicePrincipal'
                    resourceId           = '<sp-resource-graph>'
                    resourceDisplayName  = 'Microsoft Graph'
                    createdDateTime      = '2026-01-15T00:00:00Z'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                if ($Uri -like "*<sp-client-1>*") { $defaultAccessAssignment } else { @() }
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].RoleName | Should -Be 'Default Access'
        }

        It 'Falls back to raw appRoleId with warning when unresolvable' {
            $unknownRoleAssignment = @(
                [PSCustomObject]@{
                    id                   = '<ara-unknown>'
                    appRoleId            = '<unknown-role-id>'
                    principalId          = '<sp-client-1>'
                    principalDisplayName = 'My Client App'
                    principalType        = 'ServicePrincipal'
                    resourceId           = '<sp-unknown-resource>'
                    resourceDisplayName  = 'Unknown API'
                    createdDateTime      = '2026-01-15T00:00:00Z'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                if ($Uri -like "*<sp-client-1>*") { $unknownRoleAssignment } else { @() }
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].RoleName | Should -Be '<unknown-role-id>'
            $result.Status | Should -Be 'Partial'
            $result.Warnings | Where-Object { $_ -like '*Could not resolve appRoleId*' } | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Delegated grant mapping' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                $mockServicePrincipals
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                @()
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                $mockOAuth2Grants
            }
        }

        It 'Sets PrincipalId from clientId' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].PrincipalId | Should -Be '<sp-client-1>'
        }

        It 'Resolves PrincipalDisplayName from cache' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].PrincipalDisplayName | Should -Be 'My Client App'
        }

        It 'PrincipalType is always ServicePrincipal' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].PrincipalType | Should -Be 'ServicePrincipal'
        }

        It 'Sets RoleName to full scope string and Scope to resource name' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].RoleName | Should -Be 'User.Read Group.ReadWrite.All'
            $result.Items[0].Scope | Should -Be 'Microsoft Graph'
        }

        It 'Maps ConsentType correctly' {
            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].ConsentType | Should -Be 'AllPrincipals'
        }

        It 'Sets fixed fields for delegated grants' {
            $result = Get-PAAppPermission -Session $mockSession

            $item = $result.Items[0]
            $item.Source | Should -Be 'AppPermission'
            $item.AssignmentType | Should -Be 'DelegatedGrant'
            $item.RoleType | Should -Be 'DelegatedGrant'
            $item.ScopeType | Should -Be 'Application'
        }

        It 'Maps Principal consent type' {
            $userConsentGrant = @(
                [PSCustomObject]@{
                    id          = '<grant-user>'
                    clientId    = '<sp-client-1>'
                    consentType = 'Principal'
                    principalId = '<user-id>'
                    resourceId  = '<sp-resource-graph>'
                    scope       = 'User.Read'
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                $userConsentGrant
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Items[0].ConsentType | Should -Be 'Principal'
        }
    }

    Context 'Empty results' {

        It 'Returns Complete with 0 items when no permissions exist' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                $mockServicePrincipals
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                @()
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                @()
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Status | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }
    }

    Context 'SP listing failure' {

        It 'Returns Failed when SP listing throws' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                throw 'Graph API error: 403 Forbidden'
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Status | Should -Be 'Failed'
            $result.Errors | Should -Contain 'Graph API error: 403 Forbidden'
            $result.ItemCount | Should -Be 0
        }
    }

    Context 'oauth2PermissionGrants failure' {

        It 'Returns Partial when oauth2 fails but appRoles succeed' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                $mockServicePrincipals
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                if ($Uri -like "*<sp-client-1>*") { $mockAppRoleAssignments } else { @() }
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                throw 'oauth2 error'
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Status | Should -Be 'Partial'
            $result.ItemCount | Should -Be 1
            $result.Items[0].AssignmentType | Should -Be 'AppRole'
        }
    }

    Context 'Per-SP error isolation' {

        It 'Continues when one SP appRoleAssignment call fails' {
            $mockSPsMulti = @(
                [PSCustomObject]@{
                    id          = '<sp-fail>'
                    displayName = 'Failing App'
                    appId       = '<fail-app-id>'
                    appRoles    = @()
                },
                [PSCustomObject]@{
                    id          = '<sp-client-1>'
                    displayName = 'My Client App'
                    appId       = '<app-id-1>'
                    appRoles    = @()
                },
                [PSCustomObject]@{
                    id          = '<sp-resource-graph>'
                    displayName = 'Microsoft Graph'
                    appId       = '<graph-app-id>'
                    appRoles    = @(
                        [PSCustomObject]@{ id = '<role-mail-read>'; value = 'Mail.Read' }
                    )
                }
            )
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' -and $Uri -notlike '*appRoleAssignments*' } {
                $mockSPsMulti
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                if ($Uri -like '*<sp-fail>*') { throw 'Access denied' }
                if ($Uri -like '*<sp-client-1>*') { $mockAppRoleAssignments }
                @()
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*oauth2PermissionGrants*' } {
                @()
            }

            $result = Get-PAAppPermission -Session $mockSession

            $result.Status | Should -Be 'Partial'
            $result.ItemCount | Should -Be 1
            $result.Warnings | Where-Object { $_ -like '*<sp-fail>*' } | Should -Not -BeNullOrEmpty
        }
    }
}
