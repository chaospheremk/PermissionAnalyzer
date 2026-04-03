#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Get-PAActivitySignal.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PAGraphRequest.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PALogAnalyticsQuery.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAActivityProfile.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')

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
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/auditLogs/signIns*' } {
                @(
                    [PSCustomObject]@{
                        servicePrincipalId = '<principal-sp>'
                        createdDateTime    = '2026-03-28T08:00:00Z'
                        appId              = '<app-id>'
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

    Context 'Graph API SP sign-in coverage' {

        It 'Queries /auditLogs/signIns for SP sign-in data on Graph path' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/auditLogs/signIns*' } {
                @([PSCustomObject]@{
                    servicePrincipalId = '<principal-sp>'
                    createdDateTime    = '2026-03-28T08:00:00Z'
                    appId              = '<app-id>'
                })
            }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } { @() }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            # SP has sign-in data (not Tier 1) but no role activity → Tier 2
            $spProfile = $result.Items.Where({ $_.PrincipalId -eq '<principal-sp>' })
            $spProfile[0].ActivityTier | Should -Be 2
            $spProfile[0].DaysSinceLastSignIn | Should -Not -BeNull
        }

        It 'SP with no sign-in data defaults to Tier 1' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/auditLogs/signIns*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } { @() }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $spProfile = $result.Items.Where({ $_.PrincipalId -eq '<principal-sp>' })
            $spProfile[0].ActivityTier | Should -Be 1
        }

        It 'Warns when SP sign-in query fails' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/users*' } { @() }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/auditLogs/signIns*' } { throw 'Forbidden' }
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*directoryAudits*' } { @() }

            $result = Get-PAActivitySignal -Session $mockSessionGraph -Assignments $mockAssignments

            $result.Warnings.Where({ $_ -like '*SP sign-in query failed*' }).Count | Should -BeGreaterThan 0
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
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*/auditLogs/signIns*' } { @() }
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
}
