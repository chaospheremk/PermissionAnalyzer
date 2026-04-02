#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Connect-PASession.ps1')

    # Stubs for external cmdlets
    function Connect-MgGraph { param($TenantId, $Scopes, $Environment, $ErrorAction) }
    function Get-MgContext { }
    function Disconnect-MgGraph { }
    function Connect-AzAccount { param($TenantId, $Environment, $ErrorAction) }
    function Get-AzContext { }
    function Get-AzSubscription { param($TenantId) }
}

Describe 'Connect-PASession' {

    BeforeAll {
        $testTenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        $mockGraphContext = [PSCustomObject]@{
            TenantId = $testTenantId
            Account  = 'user@contoso.com'
            Scopes   = @(
                'AuditLog.Read.All'
                'Directory.Read.All'
                'RoleManagement.Read.All'
                'Application.Read.All'
                'User.Read.All'
            )
            AuthType = 'Delegated'
        }

        $mockAzContext = [PSCustomObject]@{
            Tenant  = [PSCustomObject]@{ Id = $testTenantId }
            Account = [PSCustomObject]@{ Id = 'user@contoso.com' }
        }

        $mockSubscriptions = @(
            [PSCustomObject]@{ Id = '11111111-2222-3333-4444-555555555555'; State = 'Enabled' },
            [PSCustomObject]@{ Id = '66666666-7777-8888-9999-aaaaaaaaaaaa'; State = 'Enabled' },
            [PSCustomObject]@{ Id = 'dddddddd-eeee-ffff-0000-111111111111'; State = 'Disabled' }
        )
    }

    Context 'Already connected — happy path' {

        It 'Returns PA.Session when both connections exist' {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }

            $result = Connect-PASession -TenantId $testTenantId

            $result.PSObject.TypeNames[0] | Should -Be 'PA.Session'
        }

        It 'Populates all session properties' {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }

            $result = Connect-PASession -TenantId $testTenantId

            $result.TenantId | Should -Be $testTenantId
            $result.Environment | Should -Be 'Global'
            $result.AccountId | Should -Be 'user@contoso.com'
            $result.AuthMethod | Should -Be 'Delegated'
            $result.SubscriptionIds | Should -HaveCount 2
            $result.WorkspaceId | Should -Be ''
            $result.RunId | Should -Not -BeNullOrEmpty
            $result.StartTime | Should -Not -BeNullOrEmpty
        }

        It 'Does not call Connect-MgGraph when already connected' {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }
            Mock Connect-MgGraph {}

            Connect-PASession -TenantId $testTenantId

            Should -Invoke Connect-MgGraph -Exactly -Times 0
        }

        It 'Does not call Connect-AzAccount when already connected' {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }
            Mock Connect-AzAccount {}

            Connect-PASession -TenantId $testTenantId

            Should -Invoke Connect-AzAccount -Exactly -Times 0
        }
    }

    Context 'Fresh connection' {

        It 'Calls Connect-MgGraph when no Graph context exists' {
            $script:mgCallCount = 0
            Mock Get-MgContext {
                $script:mgCallCount++
                if ($script:mgCallCount -eq 1) { return $null }
                return $mockGraphContext
            }
            Mock Connect-MgGraph {}
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }

            Connect-PASession -TenantId $testTenantId

            Should -Invoke Connect-MgGraph -Exactly -Times 1
        }

        It 'Passes Environment to Connect-MgGraph' {
            $script:mgCallCount = 0
            Mock Get-MgContext {
                $script:mgCallCount++
                if ($script:mgCallCount -eq 1) { return $null }
                return $mockGraphContext
            }
            Mock Connect-MgGraph {}
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }

            Connect-PASession -TenantId $testTenantId -Environment 'USGov'

            Should -Invoke Connect-MgGraph -ParameterFilter {
                $Environment -eq 'USGov'
            }
        }

        It 'Calls Connect-AzAccount when no Az context exists' {
            Mock Get-MgContext { $mockGraphContext }
            $script:azCallCount = 0
            Mock Get-AzContext {
                $script:azCallCount++
                if ($script:azCallCount -eq 1) { return $null }
                return $mockAzContext
            }
            Mock Connect-AzAccount {}
            Mock Get-AzSubscription { $mockSubscriptions }

            Connect-PASession -TenantId $testTenantId

            Should -Invoke Connect-AzAccount -Exactly -Times 1
        }

        It 'Passes Environment to Connect-AzAccount' {
            Mock Get-MgContext { $mockGraphContext }
            $script:azCallCount = 0
            Mock Get-AzContext {
                $script:azCallCount++
                if ($script:azCallCount -eq 1) { return $null }
                return $mockAzContext
            }
            Mock Connect-AzAccount {}
            Mock Get-AzSubscription { $mockSubscriptions }

            Connect-PASession -TenantId $testTenantId -Environment 'USGovDoD'

            Should -Invoke Connect-AzAccount -ParameterFilter {
                $Environment -eq 'USGovDoD'
            }
        }
    }

    Context 'Tenant mismatch' {

        It 'Throws when Graph context tenant does not match' {
            $wrongTenantContext = [PSCustomObject]@{
                TenantId = '99999999-9999-9999-9999-999999999999'
                Account  = 'user@other.com'
                Scopes   = @()
                AuthType = 'Delegated'
            }
            Mock Get-MgContext { $wrongTenantContext }

            { Connect-PASession -TenantId $testTenantId } | Should -Throw '*does not match*'
        }

        It 'Throws when Azure context tenant does not match' {
            Mock Get-MgContext { $mockGraphContext }
            $wrongAzContext = [PSCustomObject]@{
                Tenant  = [PSCustomObject]@{ Id = '99999999-9999-9999-9999-999999999999' }
                Account = [PSCustomObject]@{ Id = 'user@other.com' }
            }
            Mock Get-AzContext { $wrongAzContext }

            { Connect-PASession -TenantId $testTenantId } | Should -Throw '*does not match*'
        }
    }

    Context 'Scope validation' {

        It 'Warns when Graph scopes are missing' {
            $partialScopeContext = [PSCustomObject]@{
                TenantId = $testTenantId
                Account  = 'user@contoso.com'
                Scopes   = @('Directory.Read.All')
                AuthType = 'Delegated'
            }
            Mock Get-MgContext { $partialScopeContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }

            $result = Connect-PASession -TenantId $testTenantId -WarningVariable warnings

            $warnings | Should -HaveCount 1
            $warnings[0] | Should -BeLike '*missing Graph scopes*'
        }

        It 'Does not warn when scopes are null (app-only)' {
            $appOnlyContext = [PSCustomObject]@{
                TenantId = $testTenantId
                Account  = '<app-id>'
                Scopes   = $null
                AuthType = 'AppOnly'
            }
            Mock Get-MgContext { $appOnlyContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }

            $result = Connect-PASession -TenantId $testTenantId -WarningVariable warnings

            $scopeWarnings = $warnings | Where-Object { $_ -like '*missing Graph scopes*' }
            $scopeWarnings | Should -HaveCount 0
        }
    }

    Context 'Subscription discovery' {

        It 'Discovers enabled subscriptions when none specified' {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }

            $result = Connect-PASession -TenantId $testTenantId

            $result.SubscriptionIds | Should -HaveCount 2
            $result.SubscriptionIds | Should -Contain '11111111-2222-3333-4444-555555555555'
            $result.SubscriptionIds | Should -Not -Contain 'dddddddd-eeee-ffff-0000-111111111111'
        }

        It 'Uses explicit SubscriptionId when provided' {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription {}

            $explicitSubs = @('11111111-2222-3333-4444-555555555555')
            $result = Connect-PASession -TenantId $testTenantId -SubscriptionId $explicitSubs

            $result.SubscriptionIds | Should -HaveCount 1
            $result.SubscriptionIds[0] | Should -Be '11111111-2222-3333-4444-555555555555'
            Should -Invoke Get-AzSubscription -Exactly -Times 0
        }

        It 'Warns when no subscriptions found' {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { @() }

            $result = Connect-PASession -TenantId $testTenantId -WarningVariable warnings

            $result.SubscriptionIds | Should -HaveCount 0
            $subWarnings = $warnings | Where-Object { $_ -like '*no enabled subscriptions*' }
            $subWarnings | Should -HaveCount 1
        }
    }

    Context 'Session object properties' {

        BeforeEach {
            Mock Get-MgContext { $mockGraphContext }
            Mock Get-AzContext { $mockAzContext }
            Mock Get-AzSubscription { $mockSubscriptions }
        }

        It 'Generates a valid GUID for RunId' {
            $result = Connect-PASession -TenantId $testTenantId

            { [guid]::Parse($result.RunId) } | Should -Not -Throw
        }

        It 'Sets StartTime to approximately UtcNow' {
            $before = [datetime]::UtcNow
            $result = Connect-PASession -TenantId $testTenantId
            $after = [datetime]::UtcNow

            $result.StartTime | Should -BeGreaterOrEqual $before
            $result.StartTime | Should -BeLessOrEqual $after
        }

        It 'Defaults WorkspaceId to empty string' {
            $result = Connect-PASession -TenantId $testTenantId

            $result.WorkspaceId | Should -Be ''
        }

        It 'Sets WorkspaceId when provided' {
            $result = Connect-PASession -TenantId $testTenantId -WorkspaceId '<workspace-id>'

            $result.WorkspaceId | Should -Be '<workspace-id>'
        }

        It 'Sets Environment from parameter' {
            $result = Connect-PASession -TenantId $testTenantId -Environment 'USGov'

            $result.Environment | Should -Be 'USGov'
        }

        It 'Returns all expected properties' {
            $result = Connect-PASession -TenantId $testTenantId

            $expectedProperties = @(
                'TenantId', 'Environment', 'AccountId', 'AuthMethod',
                'SubscriptionIds', 'WorkspaceId', 'RunId', 'StartTime'
            )
            foreach ($prop in $expectedProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
    }
}
