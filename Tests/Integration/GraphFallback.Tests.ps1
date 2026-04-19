#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../..'
    . (Join-Path $PSScriptRoot 'IntegrationTestHelpers.ps1')
    foreach ($relative in Get-PAModuleSourceFile) {
        . (Join-Path $moduleRoot $relative)
    }

    $script:PAOperationMap = $null

    function Get-MgContext { }
    function Connect-MgGraph { param($TenantId, $Scopes, $Environment, $ErrorAction) }
    function Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) }
    function Get-AzContext { }
    function Connect-AzAccount { param($TenantId, $Environment, $ErrorAction) }
    function Get-AzSubscription { param($TenantId) }
    function Get-AzRoleAssignment { param($Scope, $ErrorAction) }
    function Get-AzRoleDefinition { param($Scope, $ErrorAction) }
    function Get-AzRoleEligibilityScheduleInstance { param($Scope, $ErrorAction) }
    function Invoke-AzOperationalInsightsQuery { param($WorkspaceId, $Query, $Timespan, $ErrorAction) }

    $script:ScenarioRoot = Join-Path $PSScriptRoot 'Fixtures/graph-fallback'
    Clear-IntegrationFixtureCache

    $script:TenantGuid = '99999999-8888-7777-6666-555555555555'
}

Describe 'Integration: GraphFallback' {

    BeforeAll {
        Mock Get-MgContext {
            [PSCustomObject]@{
                TenantId = $script:TenantGuid
                Account  = 'svc-integration@tenant.onmicrosoft.com'
                AuthType = 'AppOnly'
                Scopes   = @(
                    'AuditLog.Read.All'
                    'Directory.Read.All'
                    'RoleManagement.Read.All'
                    'Application.Read.All'
                    'User.Read.All'
                )
            }
        }
        Mock Get-AzContext {
            [PSCustomObject]@{
                Account = [PSCustomObject]@{ Id = 'svc-integration@tenant.onmicrosoft.com' }
                Tenant  = [PSCustomObject]@{ Id = $script:TenantGuid }
            }
        }
        # Empty subscription list — keeps scenario focused on Entra + AppPermission
        Mock Get-AzSubscription { @() }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzRoleDefinition { @() }
        Mock Get-AzRoleEligibilityScheduleInstance { @() }

        Mock Invoke-MgGraphRequest {
            Get-FixtureGraphResponse -Uri $Uri -ScenarioRoot $script:ScenarioRoot
        }

        # Log Analytics must NOT be called on the Graph fallback path
        Mock Invoke-AzOperationalInsightsQuery {
            throw 'Invoke-AzOperationalInsightsQuery was called on the Graph fallback path'
        }

        $script:OutputDir = New-IntegrationOutputDirectory

        # Pass LookbackDays=180 to verify the 30-day cap. WorkspaceId omitted → fallback path.
        $auditParams = @{
            TenantId        = $script:TenantGuid
            OutputDirectory = $script:OutputDir
            Format          = @('CSV', 'JSON')
            LookbackDays    = 180
            SkipValidation  = $true
            ErrorAction     = 'Stop'
        }
        $script:AuditResult = Invoke-PAPermissionAudit @auditParams
    }

    AfterAll {
        Remove-IntegrationOutputDirectory -Path $script:OutputDir
    }

    It 'runs end to end without invoking Log Analytics' {
        $script:AuditResult | Should -Not -BeNullOrEmpty
        Should -Invoke Invoke-AzOperationalInsightsQuery -Times 0 -Exactly
    }

    It 'activity signals use the GraphApi data source' {
        $script:AuditResult.CollectorResults.ActivitySignal.Items[0].DataSource | Should -Be 'GraphApi'
    }

    It 'caps LookbackDays to 30 on the Graph fallback path (from requested 180)' {
        $script:AuditResult.CollectorResults.ActivitySignal.Items[0].LookbackDays | Should -Be 30
    }

    It 'captures the ADR-006 SP sign-in limitation warning on the ActivitySignal result' {
        $warnings = @($script:AuditResult.CollectorResults.ActivitySignal.Warnings)
        $spWarning = $warnings | Where-Object { $_ -like '*no sign-in coverage*' }
        $spWarning | Should -Not -BeNullOrEmpty
    }

    It 'flags Bob as Tier 1 Unused (no signInActivity in /users response)' {
        $finding = $script:AuditResult.AnalyzerResults.UnusedAssignment.Items.Where({
            $_.PrincipalId -eq '22222222-aaaa-2222-2222-222222222222'
        })[0]
        $finding              | Should -Not -BeNullOrEmpty
        $finding.ActivityTier | Should -Be 1
        $finding.Severity     | Should -Be 'Critical'
    }

    It 'flags DeployBot as Tier 1 Unused due to absent SP sign-in data' {
        $finding = $script:AuditResult.AnalyzerResults.UnusedAssignment.Items.Where({
            $_.PrincipalId -eq '44444444-aaaa-4444-4444-444444444444'
        })[0]
        $finding              | Should -Not -BeNullOrEmpty
        $finding.ActivityTier | Should -Be 1
        $finding.Severity     | Should -Be 'Critical'
    }

    It 'does not flag Alice as Unused — she has both sign-in and audit activity' {
        $aliceFindings = @($script:AuditResult.AnalyzerResults.UnusedAssignment.Items.Where({
            $_.PrincipalId -eq '11111111-aaaa-1111-1111-111111111111'
        }))
        $aliceFindings.Count | Should -Be 0
    }

    It 'Azure RBAC collector completes with zero items when no subscriptions are in scope' {
        $script:AuditResult.CollectorResults.AzureRbacAssignment.Status    | Should -Be 'Complete'
        $script:AuditResult.CollectorResults.AzureRbacAssignment.ItemCount | Should -Be 0
    }
}
