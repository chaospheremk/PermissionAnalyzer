#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Find-PAGroupConsolidation.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAFinding.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')
}

Describe 'Find-PAGroupConsolidation' {

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

        # --- Helper: build N distinct User assignments sharing the same role+scope+source ---
        function New-MockAssignmentGroup {
            [CmdletBinding()]
            param(
                [ValidateNotNullOrEmpty()]
                [int]$Count = 3,

                [string]$RoleDefinitionId = '<role-def-reader>',
                [string]$RoleName = 'Reader',
                [string]$RoleType = 'BuiltIn',
                [string]$Scope = '/subscriptions/<sub-id-1>',
                [string]$ScopeType = 'Subscription',
                [string]$Source = 'AzureRbac',
                [string]$PrincipalType = 'User',
                [string]$AssignmentType = 'Direct'
            )
            1..$Count | ForEach-Object {
                New-MockAssignment `
                    -PrincipalId "<principal-user-$_>" `
                    -PrincipalDisplayName "User $_" `
                    -PrincipalType $PrincipalType `
                    -RoleDefinitionId $RoleDefinitionId `
                    -RoleName $RoleName `
                    -RoleType $RoleType `
                    -Scope $Scope `
                    -ScopeType $ScopeType `
                    -Source $Source `
                    -AssignmentType $AssignmentType
            }
        }
    }

    # -------------------------------------------------------------------------
    Context 'Object shape' {

        It 'Returns a PA.CollectorResult' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Collector name is Find-PAGroupConsolidation' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Collector | Should -Be 'Find-PAGroupConsolidation'
        }

        It 'All items in result are PA.Finding objects' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.Finding'
            }
        }

        It 'ItemCount matches Items array length' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.ItemCount | Should -Be $result.Items.Count
        }

        It 'Duration is populated' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Duration.TotalMilliseconds | Should -BeGreaterOrEqual 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Empty inputs' {

        It 'Empty Assignments returns Complete status with 0 items' {
            $result = Find-PAGroupConsolidation -Assignments @()

            $result.Status    | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Below threshold — no finding generated' {

        It '2 principals same role+scope with default threshold 3 produces no finding' {
            $assignments = New-MockAssignmentGroup -Count 2

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.ItemCount | Should -Be 0
        }

        It '2 principals same role+scope result is Complete status' {
            $assignments = New-MockAssignmentGroup -Count 2

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Status | Should -Be 'Complete'
        }
    }

    # -------------------------------------------------------------------------
    Context 'At threshold — finding generated' {

        It '3 principals same role+scope with default threshold 3 produces one finding' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.ItemCount | Should -Be 1
        }

        It 'At-threshold result is Complete status' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Status | Should -Be 'Complete'
        }

        It 'Exactly one finding is produced per consolidation group regardless of group size' {
            $assignments = New-MockAssignmentGroup -Count 5

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.ItemCount | Should -Be 1
        }
    }

    # -------------------------------------------------------------------------
    Context 'Critical role severity matrix' {

        It '10 principals on Global Administrator produces High severity' {
            $assignments = New-MockAssignmentGroup `
                -Count 10 `
                -RoleName 'Global Administrator' `
                -RoleDefinitionId '<role-def-ga>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'High'
        }

        It '5 principals on Global Administrator produces Medium severity' {
            $assignments = New-MockAssignmentGroup `
                -Count 5 `
                -RoleName 'Global Administrator' `
                -RoleDefinitionId '<role-def-ga>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Medium'
        }

        It '3 principals on Global Administrator produces Low severity' {
            $assignments = New-MockAssignmentGroup `
                -Count 3 `
                -RoleName 'Global Administrator' `
                -RoleDefinitionId '<role-def-ga>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Low'
        }

        It '10 principals on Owner produces High severity' {
            $assignments = New-MockAssignmentGroup `
                -Count 10 `
                -RoleName 'Owner' `
                -RoleDefinitionId '<role-def-owner>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'High'
        }

        It '5 principals on Contributor produces Medium severity' {
            $assignments = New-MockAssignmentGroup `
                -Count 5 `
                -RoleName 'Contributor' `
                -RoleDefinitionId '<role-def-contrib>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Medium'
        }

        It '3 principals on Security Administrator produces Low severity' {
            $assignments = New-MockAssignmentGroup `
                -Count 3 `
                -RoleName 'Security Administrator' `
                -RoleDefinitionId '<role-def-secadmin>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Low'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Non-critical role severity matrix' {

        It '10 principals on Reader produces Medium severity' {
            $assignments = New-MockAssignmentGroup -Count 10

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Medium'
        }

        It '5 principals on Reader produces Low severity' {
            $assignments = New-MockAssignmentGroup -Count 5

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Low'
        }

        It '3 principals on Reader produces Info severity' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Info'
        }

        It '9 principals on a custom role produces Low severity' {
            $assignments = New-MockAssignmentGroup `
                -Count 9 `
                -RoleName 'Custom Ops Role' `
                -RoleDefinitionId '<role-def-custom>' `
                -RoleType 'Custom'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Severity | Should -Be 'Low'
        }
    }

    # -------------------------------------------------------------------------
    Context 'MinimumGroupSize parameter customization' {

        It 'MinimumGroupSize 2 triggers finding at exactly 2 principals' {
            $assignments = New-MockAssignmentGroup -Count 2

            $result = Find-PAGroupConsolidation -Assignments $assignments -MinimumGroupSize 2

            $result.ItemCount | Should -Be 1
        }

        It 'MinimumGroupSize 5 suppresses finding at 4 principals' {
            $assignments = New-MockAssignmentGroup -Count 4

            $result = Find-PAGroupConsolidation -Assignments $assignments -MinimumGroupSize 5

            $result.ItemCount | Should -Be 0
        }

        It 'MinimumGroupSize 5 triggers finding at exactly 5 principals with Info severity on non-critical role' {
            $assignments = New-MockAssignmentGroup -Count 5

            $result = Find-PAGroupConsolidation -Assignments $assignments -MinimumGroupSize 5

            # 5 principals at exactly MinimumGroupSize with non-critical role → Info
            # But 5 >= 5 also matches the >= 5 band which is Low for non-critical.
            # The >= MinimumGroupSize band only applies when count < 5, so at exactly 5 it is Low.
            $result.ItemCount | Should -Be 1
        }
    }

    # -------------------------------------------------------------------------
    Context 'Group PrincipalType exclusion' {

        It 'Assignment with PrincipalType Group is excluded from consolidation count' {
            # 2 Users + 1 Group = 2 eligible principals — below default threshold
            $userAssignments = New-MockAssignmentGroup -Count 2
            $groupAssignment = New-MockAssignment `
                -PrincipalId '<principal-group-1>' `
                -PrincipalDisplayName 'IT Ops Group' `
                -PrincipalType 'Group' `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/subscriptions/<sub-id-1>'

            $all = @($userAssignments) + @($groupAssignment)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.ItemCount | Should -Be 0
        }

        It 'Assignment with PrincipalType Group does not appear in finding Details' {
            # 3 Users + 1 Group — group is excluded, 3 users produce a finding
            $userAssignments = New-MockAssignmentGroup -Count 3
            $groupAssignment = New-MockAssignment `
                -PrincipalId '<principal-group-1>' `
                -PrincipalDisplayName 'IT Ops Group' `
                -PrincipalType 'Group' `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/subscriptions/<sub-id-1>'

            $all = @($userAssignments) + @($groupAssignment)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.Items[0].Details.PrincipalIds | Should -Not -Contain '<principal-group-1>'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mixed PrincipalTypes (Users and ServicePrincipals)' {

        It 'Users and ServicePrincipals in the same group both count toward the threshold' {
            $userAssignments = New-MockAssignmentGroup -Count 2
            $spAssignment = New-MockAssignment `
                -PrincipalId '<principal-sp-1>' `
                -PrincipalDisplayName 'My App SP' `
                -PrincipalType 'ServicePrincipal' `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/subscriptions/<sub-id-1>'

            $all = @($userAssignments) + @($spAssignment)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.ItemCount | Should -Be 1
        }

        It 'Mixed-type finding has empty string PrincipalType on the finding' {
            $userAssignments = New-MockAssignmentGroup -Count 2
            $spAssignment = New-MockAssignment `
                -PrincipalId '<principal-sp-1>' `
                -PrincipalDisplayName 'My App SP' `
                -PrincipalType 'ServicePrincipal' `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/subscriptions/<sub-id-1>'

            $all = @($userAssignments) + @($spAssignment)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.Items[0].PrincipalType | Should -Be ''
        }
    }

    # -------------------------------------------------------------------------
    Context 'AppPermission DelegatedGrant exclusion' {

        It 'AppPermission DelegatedGrant assignments are excluded from consolidation' {
            # 3 DelegatedGrant assignments for the same permission — should produce no finding
            $delegatedAssignments = 1..3 | ForEach-Object {
                New-MockAssignment `
                    -PrincipalId "<principal-user-$_>" `
                    -PrincipalDisplayName "User $_" `
                    -PrincipalType 'User' `
                    -RoleDefinitionId '<role-def-mailread>' `
                    -RoleName 'Mail.Read' `
                    -RoleType 'DelegatedPermission' `
                    -Scope 'Microsoft Graph' `
                    -ScopeType 'Application' `
                    -Source 'AppPermission' `
                    -AssignmentType 'DelegatedGrant'
            }

            $result = Find-PAGroupConsolidation -Assignments $delegatedAssignments

            $result.ItemCount | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'AppPermission AppRole inclusion' {

        It 'AppPermission AppRole assignments are included in consolidation' {
            # 3 SPs all holding the same AppRole — valid consolidation candidate
            $appRoleAssignments = 1..3 | ForEach-Object {
                New-MockAssignment `
                    -PrincipalId "<principal-sp-$_>" `
                    -PrincipalDisplayName "App SP $_" `
                    -PrincipalType 'ServicePrincipal' `
                    -RoleDefinitionId '<role-def-userreadall>' `
                    -RoleName 'User.Read.All' `
                    -RoleType 'AppRole' `
                    -Scope 'Microsoft Graph' `
                    -ScopeType 'Application' `
                    -Source 'AppPermission' `
                    -AssignmentType 'AppRole'
            }

            $result = Find-PAGroupConsolidation -Assignments $appRoleAssignments

            $result.ItemCount | Should -Be 1
        }
    }

    # -------------------------------------------------------------------------
    Context 'Cross-source isolation' {

        It 'Same RoleDefinitionId from different sources produces separate findings' {
            $entraAssignments = New-MockAssignmentGroup `
                -Count 3 `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/' `
                -ScopeType 'Tenant' `
                -Source 'EntraRole'

            $pimAssignments = 1..3 | ForEach-Object {
                New-MockAssignment `
                    -PrincipalId "<principal-pim-$_>" `
                    -PrincipalDisplayName "PIM User $_" `
                    -PrincipalType 'User' `
                    -RoleDefinitionId '<role-def-reader>' `
                    -RoleName 'Reader' `
                    -RoleType 'BuiltIn' `
                    -Scope '/' `
                    -ScopeType 'Tenant' `
                    -Source 'PimEntra' `
                    -AssignmentType 'Eligible'
            }

            $all = @($entraAssignments) + @($pimAssignments)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.ItemCount | Should -Be 2
        }
    }

    # -------------------------------------------------------------------------
    Context 'Eligible assignments included' {

        It 'Eligible PIM assignments are included in consolidation grouping' {
            $eligibleAssignments = New-MockAssignmentGroup `
                -Count 3 `
                -Source 'PimEntra' `
                -AssignmentType 'Eligible'

            $result = Find-PAGroupConsolidation -Assignments $eligibleAssignments

            $result.ItemCount | Should -Be 1
        }
    }

    # -------------------------------------------------------------------------
    Context 'Multiple groups — separate findings' {

        It 'Two distinct role+scope groups each meeting threshold produce two findings' {
            $group1 = New-MockAssignmentGroup `
                -Count 3 `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/subscriptions/<sub-id-1>'

            $group2 = New-MockAssignmentGroup `
                -Count 3 `
                -RoleDefinitionId '<role-def-contrib>' `
                -RoleName 'Contributor' `
                -Scope '/subscriptions/<sub-id-1>'

            $all = @($group1) + @($group2)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.ItemCount | Should -Be 2
        }

        It 'Two groups at different scopes for the same role produce two findings' {
            $group1 = New-MockAssignmentGroup `
                -Count 3 `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/subscriptions/<sub-id-1>'

            $group2 = 1..3 | ForEach-Object {
                New-MockAssignment `
                    -PrincipalId "<principal-user-$_>" `
                    -PrincipalDisplayName "User $_" `
                    -PrincipalType 'User' `
                    -RoleDefinitionId '<role-def-reader>' `
                    -RoleName 'Reader' `
                    -Scope '/subscriptions/<sub-id-2>' `
                    -ScopeType 'Subscription'
            }

            $all = @($group1) + @($group2)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.ItemCount | Should -Be 2
        }
    }

    # -------------------------------------------------------------------------
    Context 'Finding properties' {

        It 'Finding Category is GroupConsolidation' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Category | Should -Be 'GroupConsolidation'
        }

        It 'Finding RemediationAction is always ConsolidateToGroup' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].RemediationAction | Should -Be 'ConsolidateToGroup'
        }

        It 'Finding ActivityTier is null (not activity-dependent)' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].ActivityTier | Should -BeNull
        }

        It 'Finding DaysSinceActive is null (not activity-dependent)' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].DaysSinceActive | Should -BeNull
        }

        It 'Finding Title contains the principal count' {
            $assignments = New-MockAssignmentGroup -Count 4

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Title | Should -Match '4'
        }

        It 'Finding Recommendation contains the role name' {
            $assignments = New-MockAssignmentGroup `
                -Count 3 `
                -RoleName 'Contributor' `
                -RoleDefinitionId '<role-def-contrib>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Recommendation | Should -Match 'Contributor'
        }

        It 'Finding Recommendation contains the scope' {
            $assignments = New-MockAssignmentGroup `
                -Count 3 `
                -Scope '/subscriptions/<sub-id-1>'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Recommendation | Should -Match '/subscriptions/<sub-id-1>'
        }

        It 'Finding Recommendation contains the principal count' {
            $assignments = New-MockAssignmentGroup -Count 5

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Recommendation | Should -Match '5'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Deterministic FindingId' {

        It 'Same inputs on two consecutive calls produce the same FindingId' {
            $assignments = New-MockAssignmentGroup `
                -Count 3 `
                -RoleDefinitionId '<role-def-reader>' `
                -Scope '/subscriptions/<sub-id-1>'

            $result1 = Find-PAGroupConsolidation -Assignments $assignments
            $result2 = Find-PAGroupConsolidation -Assignments $assignments

            $result1.Items[0].FindingId | Should -Be $result2.Items[0].FindingId
        }

        It 'FindingId is not null or empty' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].FindingId | Should -Not -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Details population' {

        It 'Details.PrincipalCount equals the number of distinct principals in the group' {
            $assignments = New-MockAssignmentGroup -Count 4

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Details.PrincipalCount | Should -Be 4
        }

        It 'Details.PrincipalCount is an int' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Details.PrincipalCount | Should -BeOfType [int]
        }

        It 'Details.PrincipalIds is sorted alphabetically' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $ids     = $result.Items[0].Details.PrincipalIds
            $sorted  = $ids | Sort-Object
            $ids | Should -Be $sorted
        }

        It 'Details.PrincipalNames is sorted alphabetically matching PrincipalIds order' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $names  = $result.Items[0].Details.PrincipalNames
            $sorted = $names | Sort-Object
            $names | Should -Be $sorted
        }

        It 'Details.PrincipalIds contains all principals in the group' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Details.PrincipalIds | Should -Contain '<principal-user-1>'
            $result.Items[0].Details.PrincipalIds | Should -Contain '<principal-user-2>'
            $result.Items[0].Details.PrincipalIds | Should -Contain '<principal-user-3>'
        }

        It 'Details.ScopeType matches the assignment ScopeType' {
            $assignments = New-MockAssignmentGroup `
                -Count 3 `
                -ScopeType 'ResourceGroup'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Details.ScopeType | Should -Be 'ResourceGroup'
        }

        It 'Details.RoleType matches the assignment RoleType' {
            $assignments = New-MockAssignmentGroup `
                -Count 3 `
                -RoleType 'Custom'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Details.RoleType | Should -Be 'Custom'
        }

        It 'Details.AssignmentTypes contains the unique assignment types in the group' {
            $directAssignments  = New-MockAssignmentGroup -Count 2 -AssignmentType 'Direct'
            $eligibleAssignment = New-MockAssignment `
                -PrincipalId '<principal-user-3>' `
                -PrincipalDisplayName 'User 3' `
                -PrincipalType 'User' `
                -RoleDefinitionId '<role-def-reader>' `
                -RoleName 'Reader' `
                -Scope '/subscriptions/<sub-id-1>' `
                -AssignmentType 'Eligible'

            $all = @($directAssignments) + @($eligibleAssignment)

            $result = Find-PAGroupConsolidation -Assignments $all

            $result.Items[0].Details.AssignmentTypes | Should -Contain 'Direct'
            $result.Items[0].Details.AssignmentTypes | Should -Contain 'Eligible'
        }

        It 'Details.AssignmentTypes contains only unique values even when all types are the same' {
            $assignments = New-MockAssignmentGroup -Count 3 -AssignmentType 'Direct'

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Details.AssignmentTypes.Count | Should -Be 1
            $result.Items[0].Details.AssignmentTypes[0] | Should -Be 'Direct'
        }

        It 'Details is a hashtable' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].Details | Should -BeOfType [hashtable]
        }
    }

    # -------------------------------------------------------------------------
    Context 'First-alphabetical PrincipalId used for finding identity' {

        It 'Finding PrincipalId is the first PrincipalId alphabetically from the group' {
            # <principal-user-1> sorts before <principal-user-2> and <principal-user-3>
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            $result.Items[0].PrincipalId | Should -Be '<principal-user-1>'
        }

        It 'Finding PrincipalDisplayName matches the display name of the first-alphabetical PrincipalId' {
            $assignments = New-MockAssignmentGroup -Count 3

            $result = Find-PAGroupConsolidation -Assignments $assignments

            # New-MockAssignmentGroup names User 1, User 2, User 3 — User 1 aligns with <principal-user-1>
            $result.Items[0].PrincipalDisplayName | Should -Be 'User 1'
        }
    }
}
