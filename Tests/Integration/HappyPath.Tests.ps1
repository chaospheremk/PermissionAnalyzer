#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    $moduleRoot = Join-Path $PSScriptRoot '../..'
    . (Join-Path $PSScriptRoot 'IntegrationTestHelpers.ps1')
    foreach ($relative in Get-PAModuleSourceFile) {
        . (Join-Path $moduleRoot $relative)
    }

    # Reset cache so Resolve-PAOperationNamespace reads the real Data map
    $script:PAOperationMap = $null

    # Stubs for external SDK cmdlets — Pester Mocks attach to these.
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

    $script:ScenarioRoot = Join-Path $PSScriptRoot 'Fixtures/happy-path'
    Clear-IntegrationFixtureCache

    $script:TenantGuid = '99999999-8888-7777-6666-555555555555'
    $script:SubId      = '22222222-2222-2222-2222-222222222222'
    $script:ReaderRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
}

Describe 'Integration: HappyPath' {

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
            Format          = @('CSV', 'JSON', 'HTML')
            SkipValidation  = $true
            ErrorAction     = 'Stop'
        }
        $script:AuditResult = Invoke-PAPermissionAudit @auditParams
    }

    AfterAll {
        Remove-IntegrationOutputDirectory -Path $script:OutputDir
    }

    It 'runs end to end and returns a PA.AuditResult' {
        $script:AuditResult | Should -Not -BeNullOrEmpty
        $script:AuditResult.PSObject.TypeNames[0] | Should -Be 'PA.AuditResult'
    }

    It 'collects 8 assignments (4 Entra + 3 Azure RBAC + 1 AppRole)' {
        $script:AuditResult.TotalAssignments | Should -Be 8
    }

    It 'all four assignment collectors complete successfully' {
        $script:AuditResult.CollectorResults.EntraRoleAssignment.Status | Should -Be 'Complete'
        $script:AuditResult.CollectorResults.PimEligibility.Status      | Should -Be 'Complete'
        $script:AuditResult.CollectorResults.AzureRbacAssignment.Status | Should -Be 'Complete'
        $script:AuditResult.CollectorResults.AppPermission.Status       | Should -Be 'Complete'
    }

    It 'AppPermission collector actually processes the per-SP appRoleAssignment fixture' {
        # Regression guard: a silent-empty dispatch bug (the mapped file
        # missing, returning empty 'value') would leave ItemCount=0 and
        # pass Status=Complete unnoticed.
        $script:AuditResult.CollectorResults.AppPermission.ItemCount | Should -Be 1
    }

    It 'activity signals use the LogAnalytics data source' {
        $script:AuditResult.CollectorResults.ActivitySignal.Items[0].DataSource | Should -Be 'LogAnalytics'
    }

    Context 'Unused assignment findings' {
        It 'produces 4 UnusedAssignment findings across Bob and Carol' {
            $script:AuditResult.FindingsByCategory.UnusedAssignment | Should -Be 4
        }

        It 'flags Bob on Security Administrator as Critical with Tier 1' {
            $finding = $script:AuditResult.AnalyzerResults.UnusedAssignment.Items.Where({
                $_.PrincipalId -eq '22222222-aaaa-2222-2222-222222222222' -and
                $_.RoleName    -eq 'Security Administrator'
            })[0]
            $finding              | Should -Not -BeNullOrEmpty
            $finding.Severity     | Should -Be 'Critical'
            $finding.ActivityTier | Should -Be 1
        }

        It 'flags Carol on Helpdesk Administrator as Medium with Tier 2' {
            $finding = $script:AuditResult.AnalyzerResults.UnusedAssignment.Items.Where({
                $_.PrincipalId -eq '33333333-aaaa-3333-3333-333333333333' -and
                $_.RoleName    -eq 'Helpdesk Administrator'
            })[0]
            $finding              | Should -Not -BeNullOrEmpty
            $finding.Severity     | Should -Be 'Medium'
            $finding.ActivityTier | Should -Be 2
        }
    }

    Context 'Least-privilege gap findings' {
        It 'produces exactly 1 Tier 3 finding on DeployBot / Application Administrator' {
            $script:AuditResult.FindingsByCategory.OverPrivileged | Should -Be 1
            $tier3 = $script:AuditResult.AnalyzerResults.LeastPrivilegeGap.Items[0]
            $tier3.PrincipalId | Should -Be '44444444-aaaa-4444-4444-444444444444'
            $tier3.RoleName    | Should -Be 'Application Administrator'
        }

        It 'computes GapRatio = 0.75 from 4 granted namespaces and 1 used (applications)' {
            # App Admin granted namespaces: applications, servicePrincipals,
            # applicationTemplates, appRoleAssignments. sp-D used: applications.
            # 1 used-in-granted / 4 granted → gapRatio = 0.75.
            $tier3 = $script:AuditResult.AnalyzerResults.LeastPrivilegeGap.Items[0]
            $tier3.Details.GapRatio              | Should -Be 0.75
            @($tier3.Details.GrantedNamespaces).Count | Should -Be 4
            @($tier3.Details.UsedNamespaces).Count    | Should -Be 1
        }

        It 'classifies the finding as High severity for a critical role at gap 0.75' {
            # Severity table: isCritical && gap >= 0.75 && gap < 0.9 -> High.
            $tier3 = $script:AuditResult.AnalyzerResults.LeastPrivilegeGap.Items[0]
            $tier3.Severity | Should -Be 'High'
        }
    }

    Context 'Group consolidation findings' {
        It 'produces 1 consolidation finding for the 3 users sharing Reader' {
            $script:AuditResult.FindingsByCategory.GroupConsolidation | Should -Be 1
            $gc = $script:AuditResult.AnalyzerResults.GroupConsolidation.Items[0]
            $gc.RoleName | Should -Be 'Reader'
            $gc.Scope    | Should -Be "/subscriptions/$($script:SubId)"
        }
    }

    Context 'FindingId determinism' {
        It 'regenerates identical FindingIds when the audit re-runs against the same fixtures' {
            $rerunDir = New-IntegrationOutputDirectory
            try {
                $rerunParams = @{
                    TenantId        = $script:TenantGuid
                    WorkspaceId     = '<workspace-id>'
                    OutputDirectory = $rerunDir
                    Format          = @('CSV')
                    SkipValidation  = $true
                    ErrorAction     = 'Stop'
                }
                $audit2 = Invoke-PAPermissionAudit @rerunParams

                $ids1 = @($script:AuditResult.AnalyzerResults.UnusedAssignment.Items.FindingId | Sort-Object)
                $ids2 = @($audit2.AnalyzerResults.UnusedAssignment.Items.FindingId | Sort-Object)
                $ids1 | Should -BeExactly $ids2
            }
            finally {
                Remove-IntegrationOutputDirectory -Path $rerunDir
            }
        }
    }

    Context 'Report output files' {
        It 'writes CSV, JSON, and HTML reports named by RunId' {
            $runId = $script:AuditResult.RunId
            Test-Path -Path (Join-Path $script:OutputDir "PA-Report-$runId.csv")  | Should -BeTrue
            Test-Path -Path (Join-Path $script:OutputDir "PA-Report-$runId.json") | Should -BeTrue
            Test-Path -Path (Join-Path $script:OutputDir "PA-Report-$runId.html") | Should -BeTrue
        }

        It 'CSV row count equals TotalFindings' {
            $runId = $script:AuditResult.RunId
            $csv = Import-Csv -Path (Join-Path $script:OutputDir "PA-Report-$runId.csv")
            @($csv).Count | Should -Be $script:AuditResult.TotalFindings
        }

        It 'JSON FindingCount matches orchestrator summary' {
            $runId = $script:AuditResult.RunId
            $json = Get-Content -Path (Join-Path $script:OutputDir "PA-Report-$runId.json") -Raw | ConvertFrom-Json
            $json.FindingCount | Should -Be $script:AuditResult.TotalFindings
        }
    }

    Context 'Remediation scripts' {
        It 'produces a Remove-action script with -WhatIf plumbing and commented destructive lines' {
            $script:AuditResult.RemediationResult | Should -Not -BeNullOrEmpty
            $scripts = @($script:AuditResult.RemediationResult.ScriptPaths)
            $scripts.Count | Should -BeGreaterThan 0

            $removeScript = $scripts | Where-Object { $_ -like '*Remove*.ps1' } | Select-Object -First 1
            $removeScript | Should -Not -BeNullOrEmpty

            $body = Get-Content -Path $removeScript -Raw
            $body | Should -Match 'SupportsShouldProcess'
            $body | Should -Match '# UNCOMMENT TO EXECUTE:'
            $body | Should -Match 'Remove-AzRoleAssignment'
        }

        It 'produces a Downgrade script for the Tier 3 finding' {
            $scripts = @($script:AuditResult.RemediationResult.ScriptPaths)
            $downgradeScript = $scripts | Where-Object { $_ -like '*Downgrade*.ps1' } | Select-Object -First 1
            $downgradeScript | Should -Not -BeNullOrEmpty
            $body = Get-Content -Path $downgradeScript -Raw
            $body | Should -Match 'Application Administrator'
        }
    }
}
