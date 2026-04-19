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

    # Reuse happy-path fixtures — only the /servicePrincipals branch diverges.
    $script:ScenarioRoot = Join-Path $PSScriptRoot 'Fixtures/happy-path'
    Clear-IntegrationFixtureCache

    $script:TenantGuid   = '99999999-8888-7777-6666-555555555555'
    $script:SubId        = '22222222-2222-2222-2222-222222222222'
    $script:ReaderRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
}

Describe 'Integration: PartialFailure' {

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
        Mock Get-AzSubscription {
            @([PSCustomObject]@{
                Id       = $script:SubId
                TenantId = $script:TenantGuid
                State    = 'Enabled'
            })
        }

        Mock Invoke-MgGraphRequest {
            # Simulate a 403 Forbidden on ONLY the AppPermission collector's
            # top-level SP listing. The URI arrives post-wrapper with query
            # string prefixed by '?', so '/servicePrincipals\?' matches the
            # list call but leaves `/servicePrincipals/{id}/appRoleAssignments`
            # and any `/servicePrincipals/{id}` principal-resolution lookups
            # intact — otherwise a broad pattern would cause secondary
            # collector failures and mask the "other three complete"
            # assertion.
            if ($Uri -match '/servicePrincipals\?') {
                throw 'Simulated 403 Forbidden on /servicePrincipals'
            }
            Get-FixtureGraphResponse -Uri $Uri -ScenarioRoot $script:ScenarioRoot
        }

        Mock Invoke-AzOperationalInsightsQuery {
            Get-FixtureLogAnalyticsResponse -Query $Query -ScenarioRoot $script:ScenarioRoot
        }

        Mock Get-AzRoleAssignment {
            @(
                [PSCustomObject]@{
                    ObjectId           = '11111111-aaaa-1111-1111-111111111111'
                    ObjectType         = 'User'
                    RoleDefinitionId   = $script:ReaderRoleId
                    RoleDefinitionName = 'Reader'
                    Scope              = "/subscriptions/$($script:SubId)"
                    DisplayName        = 'Alice Active'
                }
                [PSCustomObject]@{
                    ObjectId           = '22222222-aaaa-2222-2222-222222222222'
                    ObjectType         = 'User'
                    RoleDefinitionId   = $script:ReaderRoleId
                    RoleDefinitionName = 'Reader'
                    Scope              = "/subscriptions/$($script:SubId)"
                    DisplayName        = 'Bob NoSignIn'
                }
                [PSCustomObject]@{
                    ObjectId           = '33333333-aaaa-3333-3333-333333333333'
                    ObjectType         = 'User'
                    RoleDefinitionId   = $script:ReaderRoleId
                    RoleDefinitionName = 'Reader'
                    Scope              = "/subscriptions/$($script:SubId)"
                    DisplayName        = 'Carol Inactive'
                }
            )
        }

        Mock Get-AzRoleDefinition {
            @([PSCustomObject]@{
                Id          = $script:ReaderRoleId
                Name        = 'Reader'
                IsCustom    = $false
                Actions     = @('*/read')
                DataActions = @()
            })
        }

        Mock Get-AzRoleEligibilityScheduleInstance { @() }

        $script:OutputDir = New-IntegrationOutputDirectory

        $auditParams = @{
            TenantId        = $script:TenantGuid
            WorkspaceId     = '<workspace-id>'
            OutputDirectory = $script:OutputDir
            Format          = @('CSV', 'JSON')
            SkipValidation  = $true
            ErrorAction     = 'Stop'
        }
        $script:AuditResult = Invoke-PAPermissionAudit @auditParams
    }

    AfterAll {
        Remove-IntegrationOutputDirectory -Path $script:OutputDir
    }

    It 'returns a PA.AuditResult despite the AppPermission collector failing' {
        $script:AuditResult | Should -Not -BeNullOrEmpty
        $script:AuditResult.PSObject.TypeNames[0] | Should -Be 'PA.AuditResult'
    }

    It 'AppPermission collector reports Failed status with error message' {
        $app = $script:AuditResult.CollectorResults.AppPermission
        $app.Status         | Should -Be 'Failed'
        @($app.Errors).Count | Should -BeGreaterThan 0
        ($app.Errors -join ' ') | Should -Match '/servicePrincipals'
    }

    It 'other three collectors still complete successfully' {
        $script:AuditResult.CollectorResults.EntraRoleAssignment.Status | Should -Be 'Complete'
        $script:AuditResult.CollectorResults.PimEligibility.Status      | Should -Be 'Complete'
        $script:AuditResult.CollectorResults.AzureRbacAssignment.Status | Should -Be 'Complete'
    }

    It 'ActivitySignal collector still runs on the shared happy-path LA fixtures' {
        $activity = $script:AuditResult.CollectorResults.ActivitySignal
        $activity.Status     | Should -Be 'Complete'
        $activity.ItemCount  | Should -BeGreaterThan 0
        $activity.Items[0].DataSource | Should -Be 'LogAnalytics'
    }

    It 'still generates findings from the surviving assignments' {
        $script:AuditResult.TotalFindings | Should -BeGreaterThan 0
        # Unused findings from Bob+Carol survive (Entra + Azure RBAC assignments still processed)
        $script:AuditResult.FindingsByCategory.UnusedAssignment | Should -BeGreaterThan 0
    }

    It 'still writes CSV and JSON reports' {
        $script:AuditResult.ReportResult | Should -Not -BeNullOrEmpty
        @($script:AuditResult.ReportResult.OutputFiles).Count | Should -BeGreaterOrEqual 2
        foreach ($file in $script:AuditResult.ReportResult.OutputFiles) {
            Test-Path -Path $file | Should -BeTrue
        }
    }
}
