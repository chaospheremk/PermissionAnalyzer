#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Test-PAFindingAccuracy.ps1')
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PAGraphRequest.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PAValidationResult.ps1')
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')

    # Stubs for external cmdlets
    function Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) }
    function Get-AzRoleAssignment { param($Scope, $ErrorAction) }
    function Get-AzRoleEligibilityScheduleInstance { param($Scope, $ErrorAction) }
}

Describe 'Test-PAFindingAccuracy' {

    BeforeAll {
        $mockSession = [PSCustomObject]@{
            PSTypeName      = 'PA.Session'
            TenantId        = '<tenant-id>'
            Environment     = 'Global'
            WorkspaceId     = ''
            SubscriptionIds = @('<sub-id-1>')
        }

        # --- Helper: build a minimal PA.Finding PSCustomObject ---
        function New-MockFinding {
            [CmdletBinding()]
            param(
                [ValidateNotNullOrEmpty()]
                [string]$FindingId = 'abcd1234abcd1234',

                [string]$Category = 'UnusedAssignment',
                [string]$Severity = 'High',
                [string]$PrincipalId = '<principal-user>',
                [string]$RoleDefinitionId = '<role-def-ga>',
                [string]$RoleName = 'Global Administrator',
                [string]$Scope = '/',
                [string]$Source = 'EntraRole'
            )
            [PSCustomObject]@{
                PSTypeName       = 'PA.Finding'
                FindingId        = $FindingId
                Category         = $Category
                Severity         = $Severity
                PrincipalId      = $PrincipalId
                RoleDefinitionId = $RoleDefinitionId
                RoleName         = $RoleName
                Scope            = $Scope
                Source           = $Source
            }
        }
    }

    # -------------------------------------------------------------------------
    Context 'PA.CollectorResult shape' {

        BeforeEach {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        principalId      = '<principal-user>'
                        roleDefinitionId = '<role-def-ga>'
                    }
                )
            }
        }

        It 'Returns PA.CollectorResult type' {
            $finding = New-MockFinding
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Collector name is Test-PAFindingAccuracy' {
            $finding = New-MockFinding
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Collector | Should -Be 'Test-PAFindingAccuracy'
        }

        It 'All items in result are PA.ValidationResult type' {
            $finding = New-MockFinding
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            foreach ($item in $result.Items) {
                $item.PSObject.TypeNames[0] | Should -Be 'PA.ValidationResult'
            }
        }

        It 'ItemCount matches finding count' {
            $findings = @(
                (New-MockFinding -FindingId 'aaa1' -PrincipalId '<principal-user>'  -RoleDefinitionId '<role-def-ga>'),
                (New-MockFinding -FindingId 'bbb2' -PrincipalId '<principal-user-2>' -RoleDefinitionId '<role-def-reader>')
            )
            $result = Test-PAFindingAccuracy -Findings $findings -Session $mockSession

            $result.ItemCount | Should -Be $result.Items.Count
        }

        It 'Duration is populated' {
            $finding = New-MockFinding
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Duration.TotalMilliseconds | Should -BeGreaterOrEqual 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'EntraRole — assignment exists (Confirmed)' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                @(
                    [PSCustomObject]@{
                        principalId      = '<principal-user>'
                        roleDefinitionId = '<role-def-ga>'
                    }
                )
            }
        }

        It 'IsStillValid is $true when principalId and roleDefinitionId match' {
            $finding = New-MockFinding -Source 'EntraRole' -PrincipalId '<principal-user>' -RoleDefinitionId '<role-def-ga>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $true
        }

        It 'CurrentState contains "still exists" when assignment is confirmed' {
            $finding = New-MockFinding -Source 'EntraRole' -PrincipalId '<principal-user>' -RoleDefinitionId '<role-def-ga>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].CurrentState | Should -Match 'still exists'
        }
    }

    # -------------------------------------------------------------------------
    Context 'EntraRole — assignment removed (Stale)' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                @(
                    [PSCustomObject]@{
                        principalId      = '<principal-other>'
                        roleDefinitionId = '<role-def-reader>'
                    }
                )
            }
        }

        It 'IsStillValid is $false when no matching assignment exists' {
            $finding = New-MockFinding -Source 'EntraRole' -PrincipalId '<principal-user>' -RoleDefinitionId '<role-def-ga>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $false
        }

        It 'CurrentState contains "no longer exists" when assignment is gone' {
            $finding = New-MockFinding -Source 'EntraRole' -PrincipalId '<principal-user>' -RoleDefinitionId '<role-def-ga>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].CurrentState | Should -Match 'no longer exists'
        }
    }

    # -------------------------------------------------------------------------
    Context 'AzureRbac — assignment exists' {

        BeforeEach {
            Mock Get-AzRoleAssignment {
                @(
                    [PSCustomObject]@{
                        ObjectId           = '<principal-user>'
                        RoleDefinitionName = 'Contributor'
                        Scope              = '/subscriptions/<sub-id-1>'
                    }
                )
            }
        }

        It 'IsStillValid is $true when ObjectId, RoleDefinitionName, and Scope all match' {
            $finding = New-MockFinding `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Contributor' `
                -RoleDefinitionId '<role-def-contributor>' `
                -Scope            '/subscriptions/<sub-id-1>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $true
        }

        It 'CurrentState contains "still exists" for confirmed RBAC assignment' {
            $finding = New-MockFinding `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Contributor' `
                -RoleDefinitionId '<role-def-contributor>' `
                -Scope            '/subscriptions/<sub-id-1>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].CurrentState | Should -Match 'still exists'
        }
    }

    # -------------------------------------------------------------------------
    Context 'AzureRbac — assignment removed' {

        BeforeEach {
            Mock Get-AzRoleAssignment { @() }
        }

        It 'IsStillValid is $false when Get-AzRoleAssignment returns empty' {
            $finding = New-MockFinding `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Contributor' `
                -RoleDefinitionId '<role-def-contributor>' `
                -Scope            '/subscriptions/<sub-id-1>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $false
        }

        It 'CurrentState contains "no longer exists" for removed RBAC assignment' {
            $finding = New-MockFinding `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Contributor' `
                -RoleDefinitionId '<role-def-contributor>' `
                -Scope            '/subscriptions/<sub-id-1>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].CurrentState | Should -Match 'no longer exists'
        }
    }

    # -------------------------------------------------------------------------
    Context 'AppPermission — assignment exists' {

        BeforeEach {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                @(
                    [PSCustomObject]@{
                        principalId = '<principal-sp>'
                        appRoleId   = '<app-role-id>'
                    }
                )
            }
        }

        It 'IsStillValid is $true when principalId and appRoleId match' {
            $finding = New-MockFinding `
                -Source           'AppPermission' `
                -PrincipalId      '<principal-sp>' `
                -RoleDefinitionId '<app-role-id>' `
                -Scope            'Microsoft Graph'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $true
        }

        It 'CurrentState contains "still exists" for confirmed app role assignment' {
            $finding = New-MockFinding `
                -Source           'AppPermission' `
                -PrincipalId      '<principal-sp>' `
                -RoleDefinitionId '<app-role-id>' `
                -Scope            'Microsoft Graph'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].CurrentState | Should -Match 'still exists'
        }
    }

    # -------------------------------------------------------------------------
    Context 'AppPermission — assignment removed' {

        It 'IsStillValid is $false when appRoleAssignments returns empty' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } { @() }

            $finding = New-MockFinding `
                -Source           'AppPermission' `
                -PrincipalId      '<principal-sp>' `
                -RoleDefinitionId '<app-role-id>' `
                -Scope            'Microsoft Graph'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $false
        }
    }

    # -------------------------------------------------------------------------
    Context 'PimEntra — eligibility exists' {

        It 'IsStillValid is $true when roleEligibilityScheduleInstances returns matching entry' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleEligibilityScheduleInstances*' } {
                @(
                    [PSCustomObject]@{
                        principalId      = '<principal-user>'
                        roleDefinitionId = '<role-def-ga>'
                    }
                )
            }

            $finding = New-MockFinding `
                -Source  'PimEntra' `
                -PrincipalId      '<principal-user>' `
                -RoleDefinitionId '<role-def-ga>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $true
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mixed sources' {

        It 'EntraRole confirmed and AzureRbac stale findings are resolved independently' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                @(
                    [PSCustomObject]@{
                        principalId      = '<principal-user>'
                        roleDefinitionId = '<role-def-ga>'
                    }
                )
            }
            Mock Get-AzRoleAssignment { @() }

            $entraFinding = New-MockFinding `
                -FindingId        'entra001' `
                -Source           'EntraRole' `
                -PrincipalId      '<principal-user>' `
                -RoleDefinitionId '<role-def-ga>'
            $rbacFinding = New-MockFinding `
                -FindingId        'rbac001' `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Reader' `
                -RoleDefinitionId '<role-def-reader>' `
                -Scope            '/subscriptions/<sub-id-1>'

            $result = Test-PAFindingAccuracy -Findings @($entraFinding, $rbacFinding) -Session $mockSession

            $entraResult = $result.Items | Where-Object { $_.FindingId -eq 'entra001' }
            $rbacResult  = $result.Items | Where-Object { $_.FindingId -eq 'rbac001' }

            $entraResult.IsStillValid | Should -Be $true
            $rbacResult.IsStillValid  | Should -Be $false
        }

        It 'FindingId is preserved on each PA.ValidationResult item' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                @(
                    [PSCustomObject]@{
                        principalId      = '<principal-user>'
                        roleDefinitionId = '<role-def-ga>'
                    }
                )
            }
            Mock Get-AzRoleAssignment { @() }

            $entraFinding = New-MockFinding -FindingId 'entra001' -Source 'EntraRole'
            $rbacFinding  = New-MockFinding `
                -FindingId        'rbac001' `
                -Source           'AzureRbac' `
                -RoleName         'Reader' `
                -RoleDefinitionId '<role-def-reader>' `
                -Scope            '/subscriptions/<sub-id-1>'

            $result = Test-PAFindingAccuracy -Findings @($entraFinding, $rbacFinding) -Session $mockSession

            $findingIds = $result.Items | Select-Object -ExpandProperty FindingId
            $findingIds | Should -Contain 'entra001'
            $findingIds | Should -Contain 'rbac001'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Pre-fetch failure isolation' {

        It 'AzureRbac findings still validate when Graph pre-fetch throws for EntraRole source' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                throw 'Graph API error: Forbidden'
            }
            Mock Get-AzRoleAssignment {
                @(
                    [PSCustomObject]@{
                        ObjectId           = '<principal-user>'
                        RoleDefinitionName = 'Reader'
                        Scope              = '/subscriptions/<sub-id-1>'
                    }
                )
            }

            $entraFinding = New-MockFinding -FindingId 'entra001' -Source 'EntraRole'
            $rbacFinding  = New-MockFinding `
                -FindingId        'rbac001' `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Reader' `
                -RoleDefinitionId '<role-def-reader>' `
                -Scope            '/subscriptions/<sub-id-1>'

            $result = Test-PAFindingAccuracy -Findings @($entraFinding, $rbacFinding) -Session $mockSession

            $rbacResult = $result.Items | Where-Object { $_.FindingId -eq 'rbac001' }
            $rbacResult.IsStillValid | Should -Be $true
        }

        It 'EntraRole findings get IsStillValid=$false with Notes containing the error when Graph pre-fetch throws' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                throw 'Graph API error: Forbidden'
            }

            $finding = New-MockFinding -Source 'EntraRole' -PrincipalId '<principal-user>' -RoleDefinitionId '<role-def-ga>'
            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid | Should -Be $false
            $result.Items[0].Notes | Should -Not -BeNullOrEmpty
        }

        It 'Result status is Partial when one source pre-fetch fails but others succeed' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                throw 'Graph API error: Forbidden'
            }
            Mock Get-AzRoleAssignment {
                @(
                    [PSCustomObject]@{
                        ObjectId           = '<principal-user>'
                        RoleDefinitionName = 'Reader'
                        Scope              = '/subscriptions/<sub-id-1>'
                    }
                )
            }

            $entraFinding = New-MockFinding -FindingId 'entra001' -Source 'EntraRole'
            $rbacFinding  = New-MockFinding `
                -FindingId        'rbac001' `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Reader' `
                -RoleDefinitionId '<role-def-reader>' `
                -Scope            '/subscriptions/<sub-id-1>'

            $result = Test-PAFindingAccuracy -Findings @($entraFinding, $rbacFinding) -Session $mockSession

            $result.Status | Should -Be 'Partial'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Per-finding error isolation' {

        It 'A failed individual finding does not prevent other findings from succeeding' {
            # First call (pre-fetch) succeeds; second individual call throws
            $callCount = 0
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                $callCount++
                if ($callCount -gt 1) { throw 'Unexpected Graph error' }
                @(
                    [PSCustomObject]@{
                        principalId = '<principal-sp-2>'
                        appRoleId   = '<app-role-id>'
                    }
                )
            }

            $finding1 = New-MockFinding `
                -FindingId        'app001' `
                -Source           'AppPermission' `
                -PrincipalId      '<principal-sp-1>' `
                -RoleDefinitionId '<app-role-id>'
            $finding2 = New-MockFinding `
                -FindingId        'app002' `
                -Source           'AppPermission' `
                -PrincipalId      '<principal-sp-2>' `
                -RoleDefinitionId '<app-role-id>'

            $result = Test-PAFindingAccuracy -Findings @($finding1, $finding2) -Session $mockSession

            $successResult = $result.Items | Where-Object { $_.FindingId -eq 'app002' }
            $successResult | Should -Not -BeNullOrEmpty
        }

        It 'Failed individual finding gets IsStillValid=$false and CurrentState of Validation error' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*appRoleAssignments*' } {
                throw 'Transient service error'
            }

            $finding = New-MockFinding `
                -Source           'AppPermission' `
                -PrincipalId      '<principal-sp>' `
                -RoleDefinitionId '<app-role-id>'

            $result = Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            $result.Items[0].IsStillValid  | Should -Be $false
            $result.Items[0].CurrentState  | Should -Be 'Validation error'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Empty findings' {

        It 'Returns Complete status with ItemCount 0 when Findings is empty' {
            $result = Test-PAFindingAccuracy -Findings @() -Session $mockSession

            $result.Status    | Should -Be 'Complete'
            $result.ItemCount | Should -Be 0
        }

        It 'No external calls are made when Findings is empty' {
            Mock Invoke-PAGraphRequest { }
            Mock Get-AzRoleAssignment { }
            Mock Get-AzRoleEligibilityScheduleInstance { }

            Test-PAFindingAccuracy -Findings @() -Session $mockSession

            Should -Invoke Invoke-PAGraphRequest          -Exactly -Times 0
            Should -Invoke Get-AzRoleAssignment           -Exactly -Times 0
            Should -Invoke Get-AzRoleEligibilityScheduleInstance -Exactly -Times 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Conditional pre-fetch' {

        It 'Get-AzRoleAssignment is not called when only EntraRole findings are present' {
            Mock Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } {
                @(
                    [PSCustomObject]@{
                        principalId      = '<principal-user>'
                        roleDefinitionId = '<role-def-ga>'
                    }
                )
            }
            Mock Get-AzRoleAssignment { }

            $finding = New-MockFinding -Source 'EntraRole'
            Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            Should -Invoke Get-AzRoleAssignment -Exactly -Times 0
        }

        It 'Invoke-PAGraphRequest for roleAssignments is not called when only AzureRbac findings are present' {
            Mock Get-AzRoleAssignment {
                @(
                    [PSCustomObject]@{
                        ObjectId           = '<principal-user>'
                        RoleDefinitionName = 'Reader'
                        Scope              = '/subscriptions/<sub-id-1>'
                    }
                )
            }
            Mock Invoke-PAGraphRequest { }

            $finding = New-MockFinding `
                -Source           'AzureRbac' `
                -PrincipalId      '<principal-user>' `
                -RoleName         'Reader' `
                -RoleDefinitionId '<role-def-reader>' `
                -Scope            '/subscriptions/<sub-id-1>'
            Test-PAFindingAccuracy -Findings @($finding) -Session $mockSession

            Should -Invoke Invoke-PAGraphRequest -ParameterFilter { $Uri -like '*roleAssignments*' } -Exactly -Times 0
        }
    }
}
