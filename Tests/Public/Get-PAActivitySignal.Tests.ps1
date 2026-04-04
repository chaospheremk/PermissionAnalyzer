#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Get-PAActivitySignal.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PAGraphRequest.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PALogAnalyticsQuery.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAActivityProfile.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Resolve-PAOperationNamespace.ps1')

    # Reset the Resolve-PAOperationNamespace cache so it loads the real map
    $script:PAOperationMap = $null

    # Stubs for external cmdlets
    function Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) }
    function Invoke-AzOperationalInsightsQuery { param($WorkspaceId, $Query, $Timespan, $ErrorAction) }
}

Describe 'Get-PAActivitySignal' {

    BeforeAll {
        $mockSessionLA = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            WorkspaceId     = '<workspace-id>'
            SubscriptionIds = @('<sub-id-1>')
        }

        $mockSessionGraph = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Environment     = 'Global'
            WorkspaceId     = ''
            SubscriptionIds = @('<sub-id-1>')
        }

        $mockAssignments = @(
            [PSCustomObject]@{
                PSTypeName           = 'PA.Assignment'
                PrincipalId          = '<principal-user>'
                PrincipalDisplayName = 'Alice Admin'
                PrincipalType        = 'User'
                Source               = 'EntraRole'
            },
            [PSCustomObject]@{
                PSTypeName           = 'PA.Assignment'
                PrincipalId          = '<principal-sp>'
                PrincipalDisplayName = 'Automation App'
                PrincipalType        = 'ServicePrincipal'
                Source               = 'EntraRole'
            },
            [PSCustomObject]@{
                PSTypeName           = 'PA.Assignment'
                PrincipalId          = '<principal-user>'
                PrincipalDisplayName = 'Alice Admin'
                PrincipalType        = 'User'
                Source               = 'AzureRbac'
            }
        )

        $mockSignInRows = @(
            [PSCustomObject]@{
                PrincipalId = '<principal-user>'
                LastSignIn  = '2026-03-25T10:00:00Z'
                SignInCount = '15'
            },
            [PSCustomObject]@{
                PrincipalId = '<principal-sp>'
                LastSignIn  = '2026-03-28T08:00:00Z'
                SignInCount = '42'
            }
        )

        $mockAuditRows = @(
            [PSCustomObject]@{
                PrincipalId   = '<principal-user>'
                LastActivity  = '2026-03-20T14:00:00Z'
                ActivityCount = '5'
            }
        )

        $mockAzActivityRows = @(
            [PSCustomObject]@{
                PrincipalId   = '<principal-user>'
                LastActivity  = '2026-03-22T16:00:00Z'
                ActivityCount = '3'
            }
        )
    }

    Context 'Log Analytics happy path' {

        BeforeEach {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                $mockSignInRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                $mockAuditRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                $mockAzActivityRows
            }
        }

        It 'Returns PA.CollectorResult type' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Status is Complete with clean data' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $result.Status | Should -Be 'Complete'
        }

        It 'Returns one profile per unique principal' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $result.ItemCount | Should -Be 2
        }

        It 'All items are PA.ActivityProfile type' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.ActivityProfile'
            }
        }

        It 'Sets DataSource to LogAnalytics' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $result.Items | ForEach-Object { $_.DataSource | Should -Be 'LogAnalytics' }
        }

        It 'Sets LookbackDays from parameter' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments -LookbackDays 180

            $result.Items | ForEach-Object { $_.LookbackDays | Should -Be 180 }
        }

        It 'Collector name is correct' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $result.Collector | Should -Be 'Get-PAActivitySignal'
        }
    }

    Context 'Log Analytics tier computation' {

        It 'Assigns Tier 0 when both sign-in and role activity exist' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                $mockSignInRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                $mockAuditRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                @()
            }

            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $userProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userProfile.ActivityTier | Should -Be 0
        }

        It 'Assigns Tier 1 when no sign-in exists' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                @()
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                $mockAuditRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                @()
            }

            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $userProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userProfile.ActivityTier | Should -Be 1
        }

        It 'Assigns Tier 2 when sign-in exists but no role activity' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                $mockSignInRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                @()
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                @()
            }

            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $spProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-sp>' }
            $spProfile.ActivityTier | Should -Be 2
        }
    }

    Context 'Log Analytics activity merge' {

        It 'Merges AuditLogs and AzureActivity for role activity' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                $mockSignInRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                $mockAuditRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                $mockAzActivityRows
            }

            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $userProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            # AuditLogs: 5 + AzureActivity: 3 = 8
            $userProfile.RoleActivityCount | Should -Be 8
            # AzureActivity has later date (2026-03-22 vs 2026-03-20)
            $userProfile.LastRoleActivityDateTime | Should -BeGreaterThan ([datetime]'2026-03-21T00:00:00Z')
        }
    }

    Context 'Graph API happy path' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } {
                @(
                    [PSCustomObject]@{
                        id              = '<principal-user>'
                        displayName     = 'Alice Admin'
                        signInActivity  = [PSCustomObject]@{
                            lastSuccessfulSignInDateTime = '2026-03-25T10:00:00Z'
                            lastSignInDateTime           = '2026-03-24T09:00:00Z'
                        }
                    }
                )
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } {
                @(
                    [PSCustomObject]@{
                        activityDateTime = '2026-03-20T14:00:00Z'
                        initiatedBy      = [PSCustomObject]@{
                            user = [PSCustomObject]@{ id = '<principal-user>' }
                            app  = $null
                        }
                    }
                )
            }
        }

        It 'Uses Graph API when WorkspaceId is empty' {
            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $result.Items | ForEach-Object { $_.DataSource | Should -Be 'GraphApi' }
        }

        It 'Caps LookbackDays at 30 for Graph path' {
            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments -LookbackDays 180

            $result.Items | ForEach-Object { $_.LookbackDays | Should -Be 30 }
            $result.Warnings | Where-Object { $_ -like '*capped*30*' } | Should -Not -BeNullOrEmpty
        }

        It 'Prefers lastSuccessfulSignInDateTime over lastSignInDateTime' {
            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $userProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userProfile.LastSignInDateTime | Should -Be ([datetime]'2026-03-25T10:00:00Z')
        }

        It 'Falls back to lastSignInDateTime when lastSuccessful is null' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } {
                @(
                    [PSCustomObject]@{
                        id              = '<principal-user>'
                        displayName     = 'Alice Admin'
                        signInActivity  = [PSCustomObject]@{
                            lastSuccessfulSignInDateTime = $null
                            lastSignInDateTime           = '2026-03-24T09:00:00Z'
                        }
                    }
                )
            }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $userProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userProfile.LastSignInDateTime | Should -Be ([datetime]'2026-03-24T09:00:00Z')
        }
    }

    Context 'Graph API SP sign-in limitation' {

        It 'SPs default to Tier 1 on Graph API path (no SP sign-in coverage)' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } { @() }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $spProfile = $result.Items.Where({ $_.PrincipalId -eq '<principal-sp>' })
            $spProfile[0].ActivityTier | Should -Be 1
        }

        It 'Warns about SP sign-in coverage limitation and recommends -WorkspaceId' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } { @() }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $result.Warnings.Where({ $_ -like '*SP/MI principals have no sign-in coverage*' }).Count | Should -BeGreaterThan 0
        }

        It 'Warning mentions Log Analytics as the solution' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } { @() }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $result.Warnings.Where({ $_ -like '*Log Analytics*WorkspaceId*' }).Count | Should -BeGreaterThan 0
        }
    }

    Context 'Empty assignments' {

        It 'Returns Complete with 0 items' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments @()

            $result.Status | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }
    }

    Context 'Log Analytics query failure' {

        It 'Returns Partial when sign-in query fails' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                throw 'Query timeout'
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                $mockAuditRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                @()
            }

            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $result.Status | Should -Be 'Partial'
            $result.ItemCount | Should -BeGreaterThan 0
        }

        It 'Returns Failed when both sign-in and audit fail' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                throw 'Query timeout'
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                throw 'Query error'
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                @()
            }

            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $result.Status | Should -Be 'Failed'
        }
    }

    Context 'Graph API failure' {

        It 'Returns Partial when user query fails but audits succeed' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } {
                throw 'Graph error'
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } {
                @()
            }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $result.Status | Should -Be 'Partial'
        }
    }

    Context 'Profile properties' {

        BeforeEach {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                $mockSignInRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                $mockAuditRows
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                @()
            }
        }

        It 'Populates PrincipalType from assignment data' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $userProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userProfile.PrincipalType | Should -Be 'User'

            $spProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-sp>' }
            $spProfile.PrincipalType | Should -Be 'ServicePrincipal'
        }

        It 'Populates SignInCount from query results' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignments

            $userProfile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $userProfile.SignInCount | Should -Be 15
        }
    }

    Context 'Tier 3 — GrantedActions from RoleActionMap (Log Analytics)' {

        BeforeAll {
            $mockRoleActionMap = @{
                '<entra-role-def-1>' = @(
                    'microsoft.directory/users/basic/update',
                    'microsoft.directory/users/password/update'
                )
                '<rbac-role-def-1>'  = @(
                    'Microsoft.Compute/virtualMachines/read',
                    'Microsoft.Compute/virtualMachines/write'
                )
            }

            $mockAssignmentsWithRoles = @(
                [PSCustomObject]@{
                    PSTypeName           = 'PA.Assignment'
                    PrincipalId          = '<principal-user>'
                    PrincipalDisplayName = 'Alice Admin'
                    PrincipalType        = 'User'
                    RoleDefinitionId     = '<entra-role-def-1>'
                    Source               = 'EntraRole'
                },
                [PSCustomObject]@{
                    PSTypeName           = 'PA.Assignment'
                    PrincipalId          = '<principal-user>'
                    PrincipalDisplayName = 'Alice Admin'
                    PrincipalType        = 'User'
                    RoleDefinitionId     = '<rbac-role-def-1>'
                    Source               = 'AzureRbac'
                }
            )
        }

        BeforeEach {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                @([PSCustomObject]@{
                    PrincipalId = '<principal-user>'
                    LastSignIn  = '2026-03-25T10:00:00Z'
                    SignInCount = '5'
                })
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' -and $Query -notlike '*OperationName*' } {
                @([PSCustomObject]@{
                    PrincipalId   = '<principal-user>'
                    LastActivity  = '2026-03-20T14:00:00Z'
                    ActivityCount = '3'
                })
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' -and $Query -notlike '*OperationNameValue*' } {
                @()
            }
            # Query D: Entra used actions
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' -and $Query -like '*OperationName*' } {
                @()
            }
            # Query E: Azure RBAC used actions
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' -and $Query -like '*OperationNameValue*' } {
                @()
            }
        }

        It 'Populates GrantedActions as union of all role actions for the principal' {
            $signalParams = @{
                Session      = $mockSessionLA
                Assignments  = $mockAssignmentsWithRoles
                RoleActionMap = $mockRoleActionMap
            }
            $result = Get-PAActivitySignal @signalParams

            $profile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $profile.GrantedActions | Should -HaveCount 4
            $profile.GrantedActions | Should -Contain 'microsoft.directory/users/basic/update'
            $profile.GrantedActions | Should -Contain 'Microsoft.Compute/virtualMachines/read'
        }

        It 'Leaves GrantedActions empty when RoleActionMap is not provided' {
            $result = Get-PAActivitySignal -Session $mockSessionLA -Assignments $mockAssignmentsWithRoles

            $profile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $profile.GrantedActions | Should -HaveCount 0
        }

        It 'Leaves GrantedActions empty when RoleActionMap has no matching role IDs' {
            $emptyMap = @{ '<unknown-role>' = @('some/action') }
            $signalParams = @{
                Session       = $mockSessionLA
                Assignments   = $mockAssignmentsWithRoles
                RoleActionMap = $emptyMap
            }
            $result = Get-PAActivitySignal @signalParams

            $profile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $profile.GrantedActions | Should -HaveCount 0
        }
    }

    Context 'Tier 3 — UsedActions from Log Analytics' {

        BeforeAll {
            $mockRoleActionMap = @{
                '<entra-role-def-1>' = @('microsoft.directory/users/basic/update')
            }

            $tier3Assignment = @(
                [PSCustomObject]@{
                    PSTypeName           = 'PA.Assignment'
                    PrincipalId          = '<principal-user>'
                    PrincipalDisplayName = 'Alice Admin'
                    PrincipalType        = 'User'
                    RoleDefinitionId     = '<entra-role-def-1>'
                    Source               = 'EntraRole'
                }
            )
        }

        It 'Populates UsedActions from Entra AuditLogs via Resolve-PAOperationNamespace' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                @([PSCustomObject]@{
                    PrincipalId = '<principal-user>'
                    LastSignIn  = '2026-03-25T10:00:00Z'
                    SignInCount = '5'
                })
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' -and $Query -notlike '*OperationName*' } {
                @([PSCustomObject]@{
                    PrincipalId   = '<principal-user>'
                    LastActivity  = '2026-03-20T14:00:00Z'
                    ActivityCount = '2'
                })
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' -and $Query -notlike '*OperationNameValue*' } {
                @()
            }
            # Query D: Entra used actions — returns operation name + category
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' -and $Query -like '*OperationName*' } {
                @(
                    [PSCustomObject]@{
                        PrincipalId   = '<principal-user>'
                        OperationName = 'Add user'
                        Category      = 'UserManagement'
                    },
                    [PSCustomObject]@{
                        PrincipalId   = '<principal-user>'
                        OperationName = 'Update user'
                        Category      = 'UserManagement'
                    }
                )
            }
            # Query E: Azure RBAC used actions
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' -and $Query -like '*OperationNameValue*' } {
                @()
            }

            $signalParams = @{
                Session       = $mockSessionLA
                Assignments   = $tier3Assignment
                RoleActionMap = $mockRoleActionMap
            }
            $result = Get-PAActivitySignal @signalParams

            $profile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $profile.UsedActions | Should -Not -BeNullOrEmpty
            # 'Add user' maps to microsoft.directory/users/create
            # 'Update user' maps to microsoft.directory/users/basic/update
            $profile.UsedActions | Should -Contain 'microsoft.directory/users/create'
            $profile.UsedActions | Should -Contain 'microsoft.directory/users/basic/update'
        }

        It 'Populates UsedActions from AzureActivity OperationNameValue' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                @([PSCustomObject]@{
                    PrincipalId = '<principal-user>'
                    LastSignIn  = '2026-03-25T10:00:00Z'
                    SignInCount = '5'
                })
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' -and $Query -notlike '*OperationName*' } {
                @([PSCustomObject]@{
                    PrincipalId   = '<principal-user>'
                    LastActivity  = '2026-03-20T14:00:00Z'
                    ActivityCount = '1'
                })
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' -and $Query -notlike '*OperationNameValue*' } {
                @()
            }
            # Query D: Entra used actions — empty
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' -and $Query -like '*OperationName*' } {
                @()
            }
            # Query E: Azure RBAC used actions
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' -and $Query -like '*OperationNameValue*' } {
                @(
                    [PSCustomObject]@{
                        PrincipalId        = '<principal-user>'
                        OperationNameValue = 'Microsoft.Compute/virtualMachines/write'
                    }
                )
            }

            $signalParams = @{
                Session       = $mockSessionLA
                Assignments   = $tier3Assignment
                RoleActionMap = $mockRoleActionMap
            }
            $result = Get-PAActivitySignal @signalParams

            $profile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $profile.UsedActions | Should -Contain 'Microsoft.Compute/virtualMachines/write'
        }

        It 'Does not run UsedActions queries when RoleActionMap is not provided' {
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*SigninLogs*' } {
                @([PSCustomObject]@{
                    PrincipalId = '<principal-user>'
                    LastSignIn  = '2026-03-25T10:00:00Z'
                    SignInCount = '5'
                })
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AuditLogs*' } {
                @()
            }
            Mock Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*AzureActivity*' } {
                @()
            }

            Get-PAActivitySignal -Session $mockSessionLA -Assignments $tier3Assignment

            # The UsedActions queries include 'OperationName' and 'OperationNameValue' in their KQL
            Should -Invoke Invoke-PALogAnalyticsQuery -ParameterFilter { $Query -like '*summarize by*OperationName*' } -Exactly -Times 0
        }
    }

    Context 'Tier 3 — Graph API UsedActions extraction' {

        It 'Extracts Entra UsedActions from directoryAudits activityDisplayName' {
            $mockRoleActionMap = @{
                '<entra-role-def-1>' = @('microsoft.directory/users/basic/update')
            }

            $graphAssignment = @(
                [PSCustomObject]@{
                    PSTypeName           = 'PA.Assignment'
                    PrincipalId          = '<principal-user>'
                    PrincipalDisplayName = 'Alice Admin'
                    PrincipalType        = 'User'
                    RoleDefinitionId     = '<entra-role-def-1>'
                    Source               = 'EntraRole'
                }
            )

            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } {
                @(
                    [PSCustomObject]@{
                        id              = '<principal-user>'
                        displayName     = 'Alice Admin'
                        signInActivity  = [PSCustomObject]@{
                            lastSuccessfulSignInDateTime = '2026-03-25T10:00:00Z'
                        }
                    }
                )
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } {
                @(
                    [PSCustomObject]@{
                        activityDateTime    = '2026-03-20T14:00:00Z'
                        activityDisplayName = 'Update user'
                        category            = 'UserManagement'
                        initiatedBy         = [PSCustomObject]@{
                            user = [PSCustomObject]@{ id = '<principal-user>' }
                            app  = $null
                        }
                    }
                )
            }

            $signalParams = @{
                Session       = $mockSessionGraph
                Assignments   = $graphAssignment
                RoleActionMap = $mockRoleActionMap
            }
            $result = Get-PAActivitySignal @signalParams

            $profile = $result.Items | Where-Object { $_.PrincipalId -eq '<principal-user>' }
            $profile.UsedActions | Should -Contain 'microsoft.directory/users/basic/update'
        }

        It 'Warns about Azure RBAC Tier 3 unavailability on Graph API path' {
            $mockRoleActionMap = @{
                '<entra-role-def-1>' = @('microsoft.directory/users/basic/update')
            }

            $graphAssignment = @(
                [PSCustomObject]@{
                    PSTypeName           = 'PA.Assignment'
                    PrincipalId          = '<principal-user>'
                    PrincipalDisplayName = 'Alice Admin'
                    PrincipalType        = 'User'
                    RoleDefinitionId     = '<entra-role-def-1>'
                    Source               = 'EntraRole'
                }
            )

            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } { @() }

            $signalParams = @{
                Session       = $mockSessionGraph
                Assignments   = $graphAssignment
                RoleActionMap = $mockRoleActionMap
            }
            $result = Get-PAActivitySignal @signalParams

            $result.Warnings.Where({ $_ -like '*Azure RBAC Tier 3*Log Analytics*' }).Count | Should -BeGreaterThan 0
        }
    }
}
