#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Find-PALeastPrivilegeGap.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAFinding.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')
}

Describe 'Find-PALeastPrivilegeGap' {

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
                [string[]]$GrantedActions = @(),
                [string[]]$UsedActions = @(),
                [System.Nullable[int]]$DaysSinceLastRoleActivity = 5,
                [int]$LookbackDays = 90,
                [string]$DataSource = 'LogAnalytics'
            )
            [PSCustomObject]@{
                PSTypeName               = 'PA.ActivityProfile'
                PrincipalId              = $PrincipalId
                ActivityTier             = $ActivityTier
                GrantedActions           = $GrantedActions
                UsedActions              = $UsedActions
                DaysSinceLastRoleActivity = $DaysSinceLastRoleActivity
                LookbackDays             = $LookbackDays
                DataSource               = $DataSource
            }
        }

        # Four distinct Entra-style granted actions spanning four namespaces
        $grantedFour = @(
            'microsoft.directory/users/basic/update',
            'microsoft.directory/groups/members/update',
            'microsoft.directory/applications/credentials/update',
            'microsoft.directory/servicePrincipals/basic/update'
        )

        # One used action — only one of those four namespaces active (25% used = 75% gap)
        $usedOne = @(
            'microsoft.directory/users/basic/update'
        )

        # Active profile with high gap (3 of 4 namespaces unused → gap = 0.75)
        $highGapProfile = New-MockProfile `
            -ActivityTier 0 `
            -GrantedActions $grantedFour `
            -UsedActions $usedOne `
            -DaysSinceLastRoleActivity 5

        # Active profile with no gap (all granted also used)
        $noGapProfile = New-MockProfile `
            -ActivityTier 0 `
            -GrantedActions $grantedFour `
            -UsedActions $grantedFour `
            -DaysSinceLastRoleActivity 5

        # Tier 1 profile (no sign-in — should be skipped)
        $tier1Profile = New-MockProfile `
            -ActivityTier 1 `
            -GrantedActions $grantedFour `
            -UsedActions $usedOne `
            -DaysSinceLastRoleActivity $null
    }

    # -------------------------------------------------------------------------
    Context 'Object shape' {

        It 'Returns a PA.CollectorResult' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Collector name is Find-PALeastPrivilegeGap' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Collector | Should -Be 'Find-PALeastPrivilegeGap'
        }

        It 'All items in result are PA.Finding objects' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.Finding'
            }
        }

        It 'ItemCount matches Items array length' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be $result.Items.Count
        }

        It 'Duration is populated' {
            $assignment = New-MockAssignment
            $profile    = $noGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Duration.TotalMilliseconds | Should -BeGreaterOrEqual 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Empty inputs' {

        It 'Empty Assignments returns Complete status with 0 items' {
            $profile = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @() -ActivityProfiles @($profile)

            $result.Status    | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }

        It 'Empty ActivityProfiles returns Partial status' {
            $assignment = New-MockAssignment

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @()

            $result.Status | Should -Be 'Partial'
        }

        It 'Empty ActivityProfiles produces 0 findings' {
            $assignment = New-MockAssignment

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @()

            $result.ItemCount | Should -Be 0
        }

        It 'Empty ActivityProfiles emits at least one warning' {
            $assignment = New-MockAssignment

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @()

            $result.Warnings.Count | Should -BeGreaterThan 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'No action data skip' {

        It 'Profile with empty GrantedActions AND empty UsedActions produces no finding' {
            $assignment   = New-MockAssignment
            $emptyProfile = New-MockProfile -ActivityTier 0 -GrantedActions @() -UsedActions @()

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($emptyProfile)

            $result.ItemCount | Should -Be 0
        }

        It 'Profile with empty GrantedActions AND empty UsedActions emits a warning' {
            $assignment   = New-MockAssignment
            $emptyProfile = New-MockProfile -ActivityTier 0 -GrantedActions @() -UsedActions @()

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($emptyProfile)

            $result.Warnings.Count | Should -BeGreaterThan 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'UsedActions empty skip' {

        It 'Profile with GrantedActions populated but empty UsedActions produces no finding' {
            $assignment      = New-MockAssignment
            $noUsedProfile   = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions @()

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($noUsedProfile)

            $result.ItemCount | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Tier 1 skip' {

        It 'Tier 1 profile (NoSignIn) is skipped and produces no finding' {
            $assignment = New-MockAssignment

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($tier1Profile)

            $result.ItemCount | Should -Be 0
        }

        It 'Tier 1 skip still returns Complete status when no other issues exist' {
            $assignment = New-MockAssignment

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($tier1Profile)

            $result.Status | Should -Be 'Complete'
        }
    }

    # -------------------------------------------------------------------------
    Context 'AppPermission source skip' {

        It 'AppPermission source assignment produces no finding' {
            $appAssignment = New-MockAssignment `
                -Source 'AppPermission' `
                -AssignmentType 'AppRole' `
                -RoleName 'Mail.Read' `
                -RoleDefinitionId '<role-def-mailread>' `
                -RoleType 'AppRole' `
                -Scope 'Microsoft Graph' `
                -ScopeType 'Application' `
                -PrincipalType 'ServicePrincipal'
            $profile = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions $usedOne

            $result = Find-PALeastPrivilegeGap -Assignments @($appAssignment) -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be 0
        }

        It 'AppPermission skip emits a verbose message not a warning (no warning added to result)' {
            $appAssignment = New-MockAssignment `
                -Source 'AppPermission' `
                -AssignmentType 'AppRole' `
                -RoleName 'User.Read.All' `
                -RoleDefinitionId '<role-def-userreadall>' `
                -RoleType 'AppRole' `
                -Scope 'Microsoft Graph' `
                -ScopeType 'Application' `
                -PrincipalType 'ServicePrincipal'
            $profile = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions $usedOne

            $result = Find-PALeastPrivilegeGap -Assignments @($appAssignment) -ActivityProfiles @($profile)

            $result.Warnings.Count | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Namespace extraction' {

        It 'Entra-style action is truncated to first two segments' {
            # 'microsoft.directory/users/basic/update' → namespace 'microsoft.directory/users'
            $assignment = New-MockAssignment
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions @('microsoft.directory/users/basic/update', 'microsoft.directory/groups/members/update') `
                -UsedActions @('microsoft.directory/users/basic/update')

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            # Gap = 1 - (1/2) = 0.5 → should produce a finding (at default 0.5 threshold)
            $result.Items[0].Details.GrantedNamespaces | Should -Contain 'microsoft.directory/users'
            $result.Items[0].Details.GrantedNamespaces | Should -Contain 'microsoft.directory/groups'
        }

        It 'Azure RBAC-style action is truncated to first two segments' {
            # 'Microsoft.Compute/virtualMachines/read' → namespace 'Microsoft.Compute/virtualMachines'
            $assignment = New-MockAssignment
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions @(
                    'Microsoft.Compute/virtualMachines/read',
                    'Microsoft.Storage/storageAccounts/read',
                    'Microsoft.Network/virtualNetworks/read'
                ) `
                -UsedActions @('Microsoft.Compute/virtualMachines/read')

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.GrantedNamespaces | Should -Contain 'Microsoft.Compute/virtualMachines'
            $result.Items[0].Details.GrantedNamespaces | Should -Contain 'Microsoft.Storage/storageAccounts'
        }

        It 'UnusedNamespaces contains granted-but-not-used namespaces' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions @('microsoft.directory/users/basic/update', 'microsoft.directory/groups/members/update') `
                -UsedActions @('microsoft.directory/users/basic/update')

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.UnusedNamespaces | Should -Contain 'microsoft.directory/groups'
            $result.Items[0].Details.UnusedNamespaces | Should -Not -Contain 'microsoft.directory/users'
        }
    }

    # -------------------------------------------------------------------------
    Context 'High gap ratio severity matrix' {

        It 'Gap >= 0.9 + Critical role produces Critical severity' {
            # 10 granted namespaces, 1 used → gap = 0.9
            $tenGranted = @(
                'microsoft.directory/users/basic/update',
                'microsoft.directory/groups/members/update',
                'microsoft.directory/applications/credentials/update',
                'microsoft.directory/servicePrincipals/basic/update',
                'microsoft.directory/contacts/basic/update',
                'microsoft.directory/devices/basic/update',
                'microsoft.directory/domains/basic/update',
                'microsoft.directory/organization/basic/update',
                'microsoft.directory/policies/basic/update',
                'microsoft.directory/roleAssignments/allProperties/update'
            )
            $assignment = New-MockAssignment `
                -RoleName 'Global Administrator' `
                -RoleDefinitionId '<role-def-ga>'
            $profile = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $tenGranted `
                -UsedActions @('microsoft.directory/users/basic/update')

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'Critical'
        }

        It 'Gap >= 0.9 + non-critical role produces High severity' {
            $tenGranted = @(
                'Microsoft.Compute/virtualMachines/read',
                'Microsoft.Storage/storageAccounts/read',
                'Microsoft.Network/virtualNetworks/read',
                'Microsoft.KeyVault/vaults/read',
                'Microsoft.Sql/servers/read',
                'Microsoft.Web/sites/read',
                'Microsoft.Insights/components/read',
                'Microsoft.ContainerService/managedClusters/read',
                'Microsoft.ServiceBus/namespaces/read',
                'Microsoft.EventHub/namespaces/read'
            )
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>'
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $tenGranted `
                -UsedActions @('Microsoft.Compute/virtualMachines/read')

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'High'
        }

        It 'Gap >= 0.75 + Critical role produces High severity' {
            # 4 granted namespaces, 1 used → gap = 0.75
            $assignment = New-MockAssignment `
                -RoleName 'Security Administrator' `
                -RoleDefinitionId '<role-def-secadmin>'
            $profile    = $highGapProfile  # gap = 0.75

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'High'
        }

        It 'Gap >= 0.75 + non-critical role produces Medium severity' {
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>'
            $profile    = $highGapProfile  # gap = 0.75

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'Medium'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Medium gap ratio severity matrix' {

        It 'Gap >= 0.5 + Critical role produces High severity' {
            # 2 granted namespaces, 1 used → gap = 0.5
            $assignment = New-MockAssignment `
                -RoleName 'Owner' `
                -RoleDefinitionId '<role-def-owner>'
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions @('microsoft.directory/users/basic/update', 'microsoft.directory/groups/members/update') `
                -UsedActions @('microsoft.directory/users/basic/update')

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'High'
        }

        It 'Gap >= 0.5 + non-critical role produces Medium severity' {
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>'
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions @('microsoft.directory/users/basic/update', 'microsoft.directory/groups/members/update') `
                -UsedActions @('microsoft.directory/users/basic/update')

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Severity | Should -Be 'Medium'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Below threshold' {

        It 'Gap ratio below default 0.5 threshold produces no finding' {
            # 4 granted namespaces, 3 used → gap = 0.25
            $assignment = New-MockAssignment
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions @(
                    'microsoft.directory/users/basic/update',
                    'microsoft.directory/groups/members/update',
                    'microsoft.directory/applications/credentials/update'
                )

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be 0
        }

        It 'Gap ratio of exactly 0 (all namespaces used) produces no finding' {
            $assignment = New-MockAssignment
            $profile    = $noGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.ItemCount | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'GapThreshold parameter customization' {

        It 'Custom threshold of 0.3 triggers finding when gap = 0.5' {
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>'
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions @('microsoft.directory/users/basic/update', 'microsoft.directory/groups/members/update') `
                -UsedActions @('microsoft.directory/users/basic/update')

            $result = Find-PALeastPrivilegeGap `
                -Assignments @($assignment) `
                -ActivityProfiles @($profile) `
                -GapThreshold 0.3

            $result.ItemCount | Should -Be 1
        }

        It 'Custom threshold of 0.8 suppresses finding when gap = 0.75' {
            $assignment = New-MockAssignment -RoleName 'Reader' -RoleDefinitionId '<role-def-reader>'
            $profile    = $highGapProfile  # gap = 0.75

            $result = Find-PALeastPrivilegeGap `
                -Assignments @($assignment) `
                -ActivityProfiles @($profile) `
                -GapThreshold 0.8

            $result.ItemCount | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Details population' {

        It 'Finding Details contains GapRatio as a double' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.GapRatio | Should -BeOfType [double]
        }

        It 'Finding Details GapRatio is correct (3 unused of 4 granted = 0.75)' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.GapRatio | Should -Be 0.75
        }

        It 'Finding Details contains GrantedNamespaces as string array' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.GrantedNamespaces | Should -BeOfType [string]
            $result.Items[0].Details.GrantedNamespaces.Count | Should -Be 4
        }

        It 'Finding Details contains UsedNamespaces as string array' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.UsedNamespaces | Should -BeOfType [string]
            $result.Items[0].Details.UsedNamespaces.Count | Should -Be 1
        }

        It 'Finding Details contains UnusedNamespaces as string array' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.UnusedNamespaces | Should -BeOfType [string]
            $result.Items[0].Details.UnusedNamespaces.Count | Should -Be 3
        }

        It 'Finding Details contains LookbackDays from profile' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions $usedOne `
                -LookbackDays 60

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.LookbackDays | Should -Be 60
        }

        It 'Finding Details contains DataSource from profile' {
            $assignment = New-MockAssignment
            $profile    = New-MockProfile `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions $usedOne `
                -DataSource 'GraphApi'

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.DataSource | Should -Be 'GraphApi'
        }

        It 'Finding Details contains AssignmentType from assignment' {
            $assignment = New-MockAssignment -AssignmentType 'Eligible'
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.AssignmentType | Should -Be 'Eligible'
        }

        It 'Finding Details contains ScopeType from assignment' {
            $assignment = New-MockAssignment -ScopeType 'ResourceGroup'
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.ScopeType | Should -Be 'ResourceGroup'
        }

        It 'Finding Details contains RoleType from assignment' {
            $assignment = New-MockAssignment -RoleType 'Custom'
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Details.RoleType | Should -Be 'Custom'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Finding properties' {

        It 'Finding Category is OverPrivileged' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Category | Should -Be 'OverPrivileged'
        }

        It 'Finding ActivityTier is always 3' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].ActivityTier | Should -Be 3
        }

        It 'RemediationAction is always Downgrade' {
            $assignment = New-MockAssignment
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].RemediationAction | Should -Be 'Downgrade'
        }

        It 'Finding Recommendation contains the role name' {
            $assignment = New-MockAssignment -RoleName 'Contributor' -RoleDefinitionId '<role-def-contrib>'
            $profile    = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].Recommendation | Should -Match 'Contributor'
        }

        It 'Finding PrincipalId matches the assignment principal' {
            $assignment = New-MockAssignment -PrincipalId '<principal-user-2>'
            $profile    = New-MockProfile `
                -PrincipalId '<principal-user-2>' `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions $usedOne

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result.Items[0].PrincipalId | Should -Be '<principal-user-2>'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Finding deduplication' {

        It 'Same input on two consecutive calls produces the same FindingId' {
            $assignment = New-MockAssignment `
                -PrincipalId '<principal-user-1>' `
                -RoleDefinitionId '<role-def-reader>' `
                -Scope '/subscriptions/<sub-id-1>'
            $profile    = New-MockProfile `
                -PrincipalId '<principal-user-1>' `
                -ActivityTier 0 `
                -GrantedActions $grantedFour `
                -UsedActions $usedOne

            $result1 = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)
            $result2 = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            $result1.Items[0].FindingId | Should -Be $result2.Items[0].FindingId
        }
    }

    # -------------------------------------------------------------------------
    Context 'RoleActionMap — per-assignment granted actions' {

        It 'Uses per-assignment actions from RoleActionMap instead of profile GrantedActions' {
            # Profile has empty GrantedActions but RoleActionMap has actions for the role
            $assignment = New-MockAssignment `
                -RoleDefinitionId '<role-def-vm-contrib>' `
                -RoleName 'Virtual Machine Contributor'
            $profile = New-MockProfile `
                -GrantedActions @() `
                -UsedActions @('Microsoft.Compute/virtualMachines/write')

            $roleActionMap = @{
                '<role-def-vm-contrib>' = @(
                    'Microsoft.Compute/virtualMachines/read',
                    'Microsoft.Compute/virtualMachines/write',
                    'Microsoft.Network/networkInterfaces/read',
                    'Microsoft.Storage/storageAccounts/read'
                )
            }

            $gapParams = @{
                Assignments      = @($assignment)
                ActivityProfiles = @($profile)
                RoleActionMap    = $roleActionMap
            }
            $result = Find-PALeastPrivilegeGap @gapParams

            $result.Items | Should -HaveCount 1
            $result.Items[0].Details.GrantedNamespaces | Should -HaveCount 3
            $result.Items[0].Details.UsedNamespaces | Should -HaveCount 1
        }

        It 'Falls back to profile GrantedActions when RoleActionMap has no entry for the role' {
            $assignment = New-MockAssignment `
                -RoleDefinitionId '<role-def-unknown>'
            $profile = $highGapProfile

            $roleActionMap = @{
                '<some-other-role>' = @('some/action/path')
            }

            $gapParams = @{
                Assignments      = @($assignment)
                ActivityProfiles = @($profile)
                RoleActionMap    = $roleActionMap
            }
            $result = Find-PALeastPrivilegeGap @gapParams

            # Falls back to profile's GrantedActions which has 4 namespaces
            $result.Items | Should -HaveCount 1
            $result.Items[0].Details.GrantedNamespaces | Should -HaveCount 4
        }

        It 'Falls back to profile GrantedActions when RoleActionMap is not provided' {
            $assignment = New-MockAssignment
            $profile = $highGapProfile

            $result = Find-PALeastPrivilegeGap -Assignments @($assignment) -ActivityProfiles @($profile)

            # Same behavior as always — uses profile GrantedActions
            $result.Items | Should -HaveCount 1
            $result.Items[0].Details.GrantedNamespaces | Should -HaveCount 4
        }

        It 'Skips assignment when RoleActionMap entry is empty (wildcard-only role)' {
            $assignment = New-MockAssignment `
                -RoleDefinitionId '<role-def-owner>' `
                -RoleName 'Owner'
            # Profile has empty actions (no profile-level fallback either)
            $profile = New-MockProfile `
                -GrantedActions @() `
                -UsedActions @('Microsoft.Compute/virtualMachines/write')

            $roleActionMap = @{
                '<role-def-owner>' = @()  # Owner — all wildcards filtered
            }

            $gapParams = @{
                Assignments      = @($assignment)
                ActivityProfiles = @($profile)
                RoleActionMap    = $roleActionMap
            }
            $result = Find-PALeastPrivilegeGap @gapParams

            $result.Items | Should -HaveCount 0
        }
    }
}
