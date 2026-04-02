#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Find-PAUnusedAssignment.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAFinding.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')
}

Describe 'Find-PAUnusedAssignment' {

    BeforeAll {
        # --- Critical roles used to drive severity matrix ---
        $criticalRoleNames = @(
            'Global Administrator',
            'Privileged Role Administrator',
            'Privileged Authentication Administrator',
            'Application Administrator',
            'Cloud Application Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'Security Administrator',
            'User Access Administrator',
            'Owner',
            'Contributor'
        )

        # --- Helper: build a minimal PA.Assignment PSCustomObject ---
        function New-MockAssignment {
            [CmdletBinding()]
            param(
                [ValidateNotNullOrEmpty()]
                [string]$PrincipalId = '<principal-user-1>',

                [string]$PrincipalDisplayName = 'Alice Admin',
                [string]$PrincipalType = 'User',
                [string]$RoleDefinitionId = '<role-def-reader>',
                [string]$RoleName = 'Reader',
                [string]$RoleType = 'BuiltIn',
                [string]$Scope = '/subscriptions/<sub-id-1>',
                [string]$ScopeType = 'Subscription',
                [string]$Source = 'AzureRbac',
                [string]$AssignmentType = 'Direct'
            )
            [PSCustomObject]@{
                PSTypeName           = 'PA.Assignment'
                PrincipalId          = $PrincipalId
                PrincipalDisplayName = $PrincipalDisplayName
                PrincipalType        = $PrincipalType
                RoleDefinitionId     = $RoleDefinitionId
                RoleName             = $RoleName
                RoleType             = $RoleType
                Scope                = $Scope
                ScopeType            = $ScopeType
                Source               = $Source
                AssignmentType       = $AssignmentType
            }
        }

        # --- Helper: build a minimal PA.ActivityProfile PSCustomObject ---
        function New-MockProfile {
            [CmdletBinding()]
            param(
                [ValidateNotNullOrEmpty()]
                [string]$PrincipalId = '<principal-user-1>',

                [int]$ActivityTier = 0,
                [System.Nullable[int]]$DaysSinceLastSignIn = 10,
                [System.Nullable[int]]$DaysSinceLastRoleActivity = 5,
                [int]$LookbackDays = 90,
                [string]$DataSource = 'LogAnalytics'
            )
            [PSCustomObject]@{
                PSTypeName               = 'PA.ActivityProfile'
                PrincipalId              = $PrincipalId
                ActivityTier             = $ActivityTier
                DaysSinceLastSignIn      = $DaysSinceLastSignIn
                DaysSinceLastRoleActivity = $DaysSinceLastRoleActivity
                LookbackDays             = $LookbackDays
                DataSource               = $DataSource
            }
        }

        # Standard active profile (Tier 0, recent activity — should never produce a finding)
        $activeProfile = New-MockProfile -ActivityTier 0 -DaysSinceLastRoleActivity 5

        # Standard Tier 1 profile (no sign-in)
        $tier1Profile = New-MockProfile -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

        # Standard Tier 2 profile (sign-in but no role activity)
        $tier2Profile = New-MockProfile -ActivityTier 2 -DaysSinceLastSignIn 15 -DaysSinceLastRoleActivity $null

        # Tier 0 profile with stale role activity (exceeds default 90-day threshold)
        $staleTier0Profile = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity 100
    }

    # -------------------------------------------------------------------------
    Context 'Object shape' {

        It 'Returns a PA.CollectorResult' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Collector name is Find-PAUnusedAssignment' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Collector | Should -Be 'Find-PAUnusedAssignment'
        }

        It 'All items in result are PA.Finding objects' {
            $assignment = New-MockAssignment
            $profile    = $tier1Profile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.Finding'
            }
        }

        It 'ItemCount matches Items array length' {
            $assignments = @(
                (New-MockAssignment -PrincipalId '<principal-user-1>' -RoleDefinitionId '<role-def-reader>'),
                (New-MockAssignment -PrincipalId '<principal-user-1>' -RoleDefinitionId '<role-def-contrib>')
            )
            $profile = New-MockProfile -PrincipalId '<principal-user-1>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be $result.Items.Count
        }

        It 'Duration is populated' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Duration.TotalMilliseconds | Should -BeGreaterOrEqual 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Empty inputs' {

        It 'Empty Assignments returns Complete status with 0 items' {
            $profile = New-MockProfile

            $result = Find-PAUnusedAssignment -Assignments @() -ActivityProfiles @($profile)

            $result.Status    | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }

        It 'Empty ActivityProfiles returns Partial status' {
            $assignment = New-MockAssignment

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @()

            $result.Status | Should -Be 'Partial'
        }

        It 'Empty ActivityProfiles produces 0 findings' {
            $assignment = New-MockAssignment

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @()

            $result.ItemCount | Should -Be 0
        }

        It 'Empty ActivityProfiles emits at least one warning' {
            $assignment = New-MockAssignment

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @()

            $result.Warnings.Count | Should -BeGreaterThan 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Tier 1 severity matrix (NoSignIn)' {

        It 'Tier 1 + Critical role produces Critical severity' {
            $assignment = New-MockAssignment -RoleName 'Global Administrator' -RoleDefinitionId '<role-def-ga>' -RoleType 'BuiltIn'
            $profile    = New-MockProfile -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'Critical'
        }

        It 'Tier 1 + BuiltIn non-critical role produces High severity' {
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>' -RoleType 'BuiltIn'
            $profile    = New-MockProfile -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'High'
        }

        It 'Tier 1 + Custom role produces High severity' {
            $assignment = New-MockAssignment -RoleName 'Custom Ops Role' -RoleDefinitionId '<role-def-custom>' -RoleType 'Custom'
            $profile    = New-MockProfile -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'High'
        }

        It 'Tier 1 finding sets ActivityTier to 1' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].ActivityTier | Should -Be 1
        }

        It 'Tier 1 DaysSinceActive uses LookbackDays when DaysSinceLastSignIn is null' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null -LookbackDays 90

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].DaysSinceActive | Should -Be 90
        }

        It 'Tier 1 DaysSinceActive uses DaysSinceLastSignIn when available' {
            $assignment = New-MockAssignment
            # Tier 1 but has a DaysSinceLastSignIn value (edge case where sign-in data exists)
            $profile = New-MockProfile -ActivityTier 1 -DaysSinceLastSignIn 120 -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].DaysSinceActive | Should -Be 120
        }
    }

    # -------------------------------------------------------------------------
    Context 'Tier 2 severity matrix (NoRoleActivity)' {

        It 'Tier 2 + Critical role produces High severity' {
            $assignment = New-MockAssignment -RoleName 'Security Administrator' -RoleDefinitionId '<role-def-secadmin>' -RoleType 'BuiltIn'
            $profile    = New-MockProfile -ActivityTier 2 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'High'
        }

        It 'Tier 2 + BuiltIn non-critical role produces Medium severity' {
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>' -RoleType 'BuiltIn'
            $profile    = New-MockProfile -ActivityTier 2 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'Medium'
        }

        It 'Tier 2 + Custom role produces Medium severity' {
            $assignment = New-MockAssignment -RoleName 'Custom Ops Role' -RoleDefinitionId '<role-def-custom>' -RoleType 'Custom'
            $profile    = New-MockProfile -ActivityTier 2 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'Medium'
        }

        It 'Tier 2 finding sets ActivityTier to 2' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 2 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].ActivityTier | Should -Be 2
        }

        It 'Tier 2 DaysSinceActive uses LookbackDays when DaysSinceLastRoleActivity is null' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 2 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity $null -LookbackDays 90

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].DaysSinceActive | Should -Be 90
        }
    }

    # -------------------------------------------------------------------------
    Context 'Tier 0 threshold breach' {

        It 'Tier 0 + DaysSinceLastRoleActivity above threshold + Critical role produces Medium severity' {
            $assignment = New-MockAssignment -RoleName 'Owner' -RoleDefinitionId '<role-def-owner>' -RoleType 'BuiltIn'
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity 100

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 90

            $result.Items[0].Severity | Should -Be 'Medium'
        }

        It 'Tier 0 + DaysSinceLastRoleActivity above threshold + non-critical role produces Low severity' {
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>' -RoleType 'BuiltIn'
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity 100

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 90

            $result.Items[0].Severity | Should -Be 'Low'
        }

        It 'Tier 0 threshold finding sets DaysSinceActive from DaysSinceLastRoleActivity' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 20 -DaysSinceLastRoleActivity 100

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 90

            $result.Items[0].DaysSinceActive | Should -Be 100
        }
    }

    # -------------------------------------------------------------------------
    Context 'Active skip (Tier 0 recent activity)' {

        It 'Tier 0 with DaysSinceLastRoleActivity below threshold produces no finding' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 5 -DaysSinceLastRoleActivity 30

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 90

            $result.ItemCount | Should -Be 0
        }

        It 'Tier 0 active result is Complete status' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 5 -DaysSinceLastRoleActivity 30

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 90

            $result.Status | Should -Be 'Complete'
        }

        It 'Tier 0 with DaysSinceLastRoleActivity exactly at threshold produces no finding' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 5 -DaysSinceLastRoleActivity 90

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 90

            $result.ItemCount | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'RemediationAction selection' {

        It 'Eligible assignment produces ReviewEligible remediation action' {
            $assignment = New-MockAssignment -AssignmentType 'Eligible' -Source 'PimEntra'
            $profile    = $tier1Profile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].RemediationAction | Should -Be 'ReviewEligible'
        }

        It 'Direct assignment produces Remove remediation action' {
            $assignment = New-MockAssignment -AssignmentType 'Direct' -Source 'EntraRole'
            $profile    = $tier1Profile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].RemediationAction | Should -Be 'Remove'
        }

        It 'AppRole assignment produces Remove remediation action' {
            $assignment = New-MockAssignment -AssignmentType 'AppRole' -Source 'AppPermission' -RoleName 'Mail.Read' -RoleDefinitionId '<role-def-mailread>' -Scope 'Microsoft Graph' -ScopeType 'Application'
            $profile    = New-MockProfile -PrincipalId '<principal-user-1>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].RemediationAction | Should -Be 'Remove'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Missing activity profile' {

        It 'Assignment with no matching profile is skipped' {
            $assignment = New-MockAssignment -PrincipalId '<principal-user-1>'
            $profile    = New-MockProfile -PrincipalId '<principal-user-2>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be 0
        }

        It 'Missing profile emits a warning' {
            $assignment = New-MockAssignment -PrincipalId '<principal-user-1>'
            $profile    = New-MockProfile -PrincipalId '<principal-user-2>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Warnings.Count | Should -BeGreaterThan 0
        }

        It 'Missing profile for one principal does not prevent findings for others' {
            $assignment1 = New-MockAssignment -PrincipalId '<principal-user-1>'
            $assignment2 = New-MockAssignment -PrincipalId '<principal-user-2>'
            $profile2    = New-MockProfile -PrincipalId '<principal-user-2>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment1, $assignment2) -ActivityProfiles @($profile2)

            $result.ItemCount | Should -Be 1
            $result.Items[0].PrincipalId | Should -Be '<principal-user-2>'
        }

        It 'Result is Partial when at least one profile is missing' {
            $assignment1 = New-MockAssignment -PrincipalId '<principal-user-1>'
            $assignment2 = New-MockAssignment -PrincipalId '<principal-user-2>'
            $profile2    = New-MockProfile -PrincipalId '<principal-user-2>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment1, $assignment2) -ActivityProfiles @($profile2)

            $result.Status | Should -Be 'Partial'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Multiple assignments for same principal' {

        It 'Each assignment generates its own finding independently' {
            $assignments = @(
                (New-MockAssignment -PrincipalId '<principal-user-1>' -RoleDefinitionId '<role-def-reader>'  -RoleName 'Reader'),
                (New-MockAssignment -PrincipalId '<principal-user-1>' -RoleDefinitionId '<role-def-contrib>' -RoleName 'Contributor')
            )
            $profile = New-MockProfile -PrincipalId '<principal-user-1>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be 2
        }

        It 'Findings for same principal reference the correct role names' {
            $assignments = @(
                (New-MockAssignment -PrincipalId '<principal-user-1>' -RoleDefinitionId '<role-def-reader>'  -RoleName 'Reader'),
                (New-MockAssignment -PrincipalId '<principal-user-1>' -RoleDefinitionId '<role-def-contrib>' -RoleName 'Contributor')
            )
            $profile = New-MockProfile -PrincipalId '<principal-user-1>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles @($profile)

            $roleNames = $result.Items | Select-Object -ExpandProperty RoleName
            $roleNames | Should -Contain 'Reader'
            $roleNames | Should -Contain 'Contributor'
        }
    }

    # -------------------------------------------------------------------------
    Context 'InactivityThresholdDays parameter' {

        It 'Custom threshold of 30 days triggers finding at 31 days of inactivity' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 10 -DaysSinceLastRoleActivity 31

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 30

            $result.ItemCount | Should -Be 1
        }

        It 'Custom threshold of 30 days does not trigger finding at 29 days of inactivity' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 10 -DaysSinceLastRoleActivity 29

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 30

            $result.ItemCount | Should -Be 0
        }

        It 'Default threshold is 90 days' {
            # 89 days — no finding; 91 days — finding
            $assignment    = New-MockAssignment
            $profileActive = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 10 -DaysSinceLastRoleActivity 89
            $profileStale  = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 10 -DaysSinceLastRoleActivity 91

            $resultActive = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profileActive)
            $resultStale  = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profileStale)

            $resultActive.ItemCount | Should -Be 0
            $resultStale.ItemCount  | Should -Be 1
        }
    }

    # -------------------------------------------------------------------------
    Context 'Finding properties' {

        It 'Finding Title contains the principal display name' {
            $assignment = New-MockAssignment -PrincipalDisplayName 'Bob Builder'
            $profile    = $tier1Profile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Title | Should -Match 'Bob Builder'
        }

        It 'Finding Recommendation is not null or empty' {
            $assignment = New-MockAssignment
            $profile    = $tier1Profile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Recommendation | Should -Not -BeNullOrEmpty
        }

        It 'Finding Details is a hashtable' {
            $assignment = New-MockAssignment
            $profile    = $tier1Profile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details | Should -BeOfType [hashtable]
        }

        It 'Finding Category is UnusedAssignment' {
            $assignment = New-MockAssignment
            $profile    = $tier1Profile

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Category | Should -Be 'UnusedAssignment'
        }

        It 'Finding PrincipalId matches the assignment principal' {
            $assignment = New-MockAssignment -PrincipalId '<principal-user-1>'
            $profile    = New-MockProfile -PrincipalId '<principal-user-1>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].PrincipalId | Should -Be '<principal-user-1>'
        }
    }

    # -------------------------------------------------------------------------
    Context 'AppPermission source assignments' {

        It 'AppPermission assignment with Tier 1 profile produces a finding' {
            $assignment = New-MockAssignment `
                -Source 'AppPermission' `
                -AssignmentType 'AppRole' `
                -RoleName 'Mail.Read' `
                -RoleDefinitionId '<role-def-mailread>' `
                -RoleType 'AppRole' `
                -Scope 'Microsoft Graph' `
                -ScopeType 'Application' `
                -PrincipalType 'ServicePrincipal'
            $profile = New-MockProfile -PrincipalId '<principal-user-1>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be 1
        }

        It 'AppPermission finding Source matches the assignment Source' {
            $assignment = New-MockAssignment `
                -Source 'AppPermission' `
                -AssignmentType 'AppRole' `
                -RoleName 'User.Read.All' `
                -RoleDefinitionId '<role-def-userreadall>' `
                -RoleType 'AppRole' `
                -Scope 'Microsoft Graph' `
                -ScopeType 'Application' `
                -PrincipalType 'ServicePrincipal'
            $profile = New-MockProfile -PrincipalId '<principal-user-1>' -ActivityTier 1 -DaysSinceLastSignIn $null -DaysSinceLastRoleActivity $null

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Source | Should -Be 'AppPermission'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Null DaysSince values in Tier 0 threshold path' {

        It 'Tier 0 with null DaysSinceLastRoleActivity uses LookbackDays as DaysSinceActive when above threshold' {
            $assignment = New-MockAssignment
            # Tier 0 but no role activity data — LookbackDays (180) > threshold (90)
            $profile = New-MockProfile -ActivityTier 0 -DaysSinceLastSignIn 10 -DaysSinceLastRoleActivity $null -LookbackDays 180

            $result = Find-PAUnusedAssignment -Assignments @($assignment) -ActivityProfiles @($profile) -InactivityThresholdDays 90

            $result.Items[0].DaysSinceActive | Should -Be 180
        }
    }
}
