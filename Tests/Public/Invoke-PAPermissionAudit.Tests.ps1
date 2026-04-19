#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Invoke-PAPermissionAudit.ps1')
    . (Join-Path $PSScriptRoot '../TestHelpers.ps1')

    # Stubs for public functions that the orchestrator calls.
    # These are overridden by Mock inside Describe/Context blocks.
    function Connect-PASession              { param($TenantId, $Environment, $SubscriptionId, $WorkspaceId) }
    function Get-PAEntraRoleAssignment      { param($Session) }
    function Get-PAPimEligibility           { param($Session) }
    function Get-PAAzureRbacAssignment      { param($Session) }
    function Get-PAAppPermission            { param($Session) }
    function Resolve-PARoleAction            { param($Assignments, $Session) }
    function Get-PAActivitySignal           { param($Session, $Assignments, $LookbackDays, $RoleActionMap) }
    function Find-PAUnusedAssignment        { param($Assignments, $ActivityProfiles, $InactivityThresholdDays) }
    function Find-PALeastPrivilegeGap       { param($Assignments, $ActivityProfiles, $GapThreshold, $RoleActionMap) }
    function Find-PAGroupConsolidation      { param($Assignments, $MinimumGroupSize) }
    function Export-PAReport                { param($Findings, $OutputDirectory, $Format, $RunId) }
    function New-PARemediationScript        { param($Findings, $OutputDirectory, $RunId) }
    function Test-PAFindingAccuracy         { param($Findings, $Session) }
}

Describe 'Invoke-PAPermissionAudit' {

    BeforeAll {
        # Default mocks — all stages succeed; callers override per-context where needed.
        Mock Connect-PASession { New-MockSession }

        Mock Resolve-PARoleAction { @{} }

        Mock Get-PAEntraRoleAssignment {
            New-MockCollectorResult -Collector 'Get-PAEntraRoleAssignment' -Items @(
                [PSCustomObject]@{ PSTypeName = 'PA.Assignment'; PrincipalId = '<p1>'; Source = 'EntraRole' }
            )
        }

        Mock Get-PAPimEligibility {
            New-MockCollectorResult -Collector 'Get-PAPimEligibility' -Items @(
                [PSCustomObject]@{ PSTypeName = 'PA.Assignment'; PrincipalId = '<p1>'; Source = 'PimEntra' }
            )
        }

        Mock Get-PAAzureRbacAssignment {
            New-MockCollectorResult -Collector 'Get-PAAzureRbacAssignment' -Items @(
                [PSCustomObject]@{ PSTypeName = 'PA.Assignment'; PrincipalId = '<p1>'; Source = 'AzureRbac' }
            )
        }

        Mock Get-PAAppPermission {
            New-MockCollectorResult -Collector 'Get-PAAppPermission' -Items @(
                [PSCustomObject]@{ PSTypeName = 'PA.Assignment'; PrincipalId = '<p1>'; Source = 'AppPermission' }
            )
        }

        Mock Get-PAActivitySignal {
            New-MockCollectorResult -Collector 'Get-PAActivitySignal' -Items @(
                [PSCustomObject]@{ PSTypeName = 'PA.ActivityProfile'; PrincipalId = '<p1>' }
            )
        }

        Mock Find-PAUnusedAssignment {
            New-MockCollectorResult -Collector 'Find-PAUnusedAssignment' -Items @(
                [PSCustomObject]@{ PSTypeName = 'PA.Finding'; FindingId = 'f1'; Category = 'UnusedAssignment'; Severity = 'High' }
            )
        }

        Mock Find-PALeastPrivilegeGap {
            New-MockCollectorResult -Collector 'Find-PALeastPrivilegeGap' -Items @()
        }

        Mock Find-PAGroupConsolidation {
            New-MockCollectorResult -Collector 'Find-PAGroupConsolidation' -Items @()
        }

        Mock Export-PAReport {
            [PSCustomObject]@{
                PSTypeName  = 'PA.ReportResult'
                RunId       = 'test-run-001'
                OutputFiles = @('report.csv')
            }
        }

        Mock New-PARemediationScript {
            [PSCustomObject]@{
                PSTypeName  = 'PA.RemediationResult'
                RunId       = 'test-run-001'
                ScriptPaths = @('script.ps1')
            }
        }

        Mock Test-PAFindingAccuracy {
            New-MockCollectorResult -Collector 'Test-PAFindingAccuracy' -Items @()
        }

        $defaultParams = @{
            TenantId        = '<tenant-id>'
            OutputDirectory = 'TestDrive:\audit-output'
        }
    }

    # =========================================================================
    Context 'PA.AuditResult object shape' {

        BeforeAll {
            $result = Invoke-PAPermissionAudit @defaultParams
        }

        It 'PSTypeName is PA.AuditResult' {
            $result.PSObject.TypeNames[0] | Should -Be 'PA.AuditResult'
        }

        It 'Has all required top-level properties' {
            $props = $result.PSObject.Properties.Name
            $props | Should -Contain 'RunId'
            $props | Should -Contain 'TenantId'
            $props | Should -Contain 'Environment'
            $props | Should -Contain 'Duration'
            $props | Should -Contain 'CollectorResults'
            $props | Should -Contain 'TotalAssignments'
            $props | Should -Contain 'TotalActivityProfiles'
            $props | Should -Contain 'AnalyzerResults'
            $props | Should -Contain 'TotalFindings'
            $props | Should -Contain 'FindingsBySeverity'
            $props | Should -Contain 'FindingsByCategory'
            $props | Should -Contain 'ReportResult'
            $props | Should -Contain 'RemediationResult'
            $props | Should -Contain 'ValidationResult'
            $props | Should -Contain 'Warnings'
            $props | Should -Contain 'Errors'
        }

        It 'RunId matches the session RunId' {
            $result.RunId | Should -Be 'test-run-001'
        }

        It 'TenantId matches the input TenantId parameter' {
            $result.TenantId | Should -Be '<tenant-id>'
        }

        It 'Duration is a TimeSpan with TotalMilliseconds >= 0' {
            $result.Duration | Should -BeOfType [timespan]
            $result.Duration.TotalMilliseconds | Should -BeGreaterOrEqual 0
        }

        It 'TotalFindings equals sum of all analyzer Items counts' {
            # Default mocks: Find-PAUnusedAssignment=1, Find-PALeastPrivilegeGap=0, Find-PAGroupConsolidation=0
            $result.TotalFindings | Should -Be 1
        }
    }

    # =========================================================================
    Context 'Happy path — all pipeline stages called' {

        It 'Connect-PASession called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Connect-PASession -Exactly -Times 1
        }

        It 'Get-PAEntraRoleAssignment called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Get-PAEntraRoleAssignment -Exactly -Times 1
        }

        It 'Get-PAPimEligibility called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Get-PAPimEligibility -Exactly -Times 1
        }

        It 'Get-PAAzureRbacAssignment called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Get-PAAzureRbacAssignment -Exactly -Times 1
        }

        It 'Get-PAAppPermission called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Get-PAAppPermission -Exactly -Times 1
        }

        It 'Get-PAActivitySignal called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Get-PAActivitySignal -Exactly -Times 1
        }

        It 'Find-PAUnusedAssignment called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Find-PAUnusedAssignment -Exactly -Times 1
        }

        It 'Find-PALeastPrivilegeGap called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Find-PALeastPrivilegeGap -Exactly -Times 1
        }

        It 'Find-PAGroupConsolidation called exactly once' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Find-PAGroupConsolidation -Exactly -Times 1
        }

        It 'Export-PAReport called exactly once by default' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Export-PAReport -Exactly -Times 1
        }

        It 'New-PARemediationScript called exactly once when SkipRemediation not set' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke New-PARemediationScript -Exactly -Times 1
        }
    }

    # =========================================================================
    Context 'Connect-PASession failure' {

        BeforeEach {
            Mock Connect-PASession { throw 'Authentication failed: no valid token' }
        }

        It 'Throws when Connect-PASession throws' {
            { Invoke-PAPermissionAudit @defaultParams } | Should -Throw
        }

        It 'No collectors are called when Connect-PASession fails' {
            try { Invoke-PAPermissionAudit @defaultParams } catch { }
            Should -Invoke Get-PAEntraRoleAssignment  -Exactly -Times 0
            Should -Invoke Get-PAPimEligibility        -Exactly -Times 0
            Should -Invoke Get-PAAzureRbacAssignment   -Exactly -Times 0
            Should -Invoke Get-PAAppPermission         -Exactly -Times 0
        }
    }

    # =========================================================================
    Context 'Collector partial failure' {

        BeforeEach {
            Mock Get-PAEntraRoleAssignment { throw 'Graph API 503 Service Unavailable' }
        }

        It 'Remaining collectors are still called when one collector throws' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Get-PAPimEligibility      -Exactly -Times 1
            Should -Invoke Get-PAAzureRbacAssignment -Exactly -Times 1
            Should -Invoke Get-PAAppPermission       -Exactly -Times 1
        }

        It 'TotalAssignments reflects only the items from successful collectors' {
            # Default: PIM=1, RBAC=1, App=1 — Entra throws → 3 total assignments
            $result = Invoke-PAPermissionAudit @defaultParams
            $result.TotalAssignments | Should -Be 3
        }

        It 'Warnings include a message about the failed collector' {
            $result = Invoke-PAPermissionAudit @defaultParams
            $result.Warnings | Where-Object { $_ -like '*Get-PAEntraRoleAssignment*' } |
                Should -Not -BeNullOrEmpty
        }
    }

    # =========================================================================
    Context 'Activity signal failure' {

        BeforeEach {
            Mock Get-PAActivitySignal { throw 'Log Analytics workspace unreachable' }
        }

        It 'All three analyzers are still called when Get-PAActivitySignal throws' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Find-PAUnusedAssignment  -Exactly -Times 1
            Should -Invoke Find-PALeastPrivilegeGap -Exactly -Times 1
            Should -Invoke Find-PAGroupConsolidation -Exactly -Times 1
        }

        It 'Warnings include a message about the activity signal failure' {
            $result = Invoke-PAPermissionAudit @defaultParams
            $result.Warnings.Where({ $_ -like '*Activity signal*' }) |
                Should -Not -BeNullOrEmpty
        }
    }

    # =========================================================================
    Context 'Analyzer partial failure' {

        BeforeEach {
            Mock Find-PAUnusedAssignment { throw 'Analyzer error: null reference' }
        }

        It 'Remaining analyzers are still called when one analyzer throws' {
            Invoke-PAPermissionAudit @defaultParams
            Should -Invoke Find-PALeastPrivilegeGap  -Exactly -Times 1
            Should -Invoke Find-PAGroupConsolidation -Exactly -Times 1
        }

        It 'TotalFindings reflects only items from the analyzers that succeeded' {
            # Find-PALeastPrivilegeGap=0, Find-PAGroupConsolidation=0 → total = 0
            $result = Invoke-PAPermissionAudit @defaultParams
            $result.TotalFindings | Should -Be 0
        }
    }

    # =========================================================================
    Context 'SkipRemediation switch' {

        It 'New-PARemediationScript is not called when -SkipRemediation is set' {
            Invoke-PAPermissionAudit @defaultParams -SkipRemediation
            Should -Invoke New-PARemediationScript -Exactly -Times 0
        }

        It 'RemediationResult is $null when -SkipRemediation is set' {
            $result = Invoke-PAPermissionAudit @defaultParams -SkipRemediation
            $result.RemediationResult | Should -BeNullOrEmpty
        }
    }

    # =========================================================================
    Context 'SkipValidation switch' {

        It 'Test-PAFindingAccuracy is not called when -SkipValidation is set' {
            Invoke-PAPermissionAudit @defaultParams -SkipValidation
            Should -Invoke Test-PAFindingAccuracy -Exactly -Times 0
        }

        It 'ValidationResult is $null when -SkipValidation is set' {
            $result = Invoke-PAPermissionAudit @defaultParams -SkipValidation
            $result.ValidationResult | Should -BeNullOrEmpty
        }
    }

    # =========================================================================
    Context 'Report failure is non-fatal' {

        BeforeEach {
            Mock Export-PAReport { throw 'Disk full: cannot write output files' }
        }

        It 'Does not throw when Export-PAReport fails' {
            { Invoke-PAPermissionAudit @defaultParams } | Should -Not -Throw
        }

        It 'ReportResult is $null when Export-PAReport fails' {
            $result = Invoke-PAPermissionAudit @defaultParams
            $result.ReportResult | Should -BeNullOrEmpty
        }
    }

    # =========================================================================
    Context 'Parameter passthrough' {

        It 'LookbackDays is passed to Get-PAActivitySignal' {
            $params = $defaultParams + @{ LookbackDays = 180 }
            Invoke-PAPermissionAudit @params
            Should -Invoke Get-PAActivitySignal -ParameterFilter { $LookbackDays -eq 180 } -Exactly -Times 1
        }

        It 'InactivityThresholdDays is passed to Find-PAUnusedAssignment' {
            $params = $defaultParams + @{ InactivityThresholdDays = 60 }
            Invoke-PAPermissionAudit @params
            Should -Invoke Find-PAUnusedAssignment -ParameterFilter { $InactivityThresholdDays -eq 60 } -Exactly -Times 1
        }

        It 'GapThreshold is passed to Find-PALeastPrivilegeGap' {
            $params = $defaultParams + @{ GapThreshold = 0.8 }
            Invoke-PAPermissionAudit @params
            Should -Invoke Find-PALeastPrivilegeGap -ParameterFilter { $GapThreshold -eq 0.8 } -Exactly -Times 1
        }

        It 'MinimumGroupSize is passed to Find-PAGroupConsolidation' {
            $params = $defaultParams + @{ MinimumGroupSize = 5 }
            Invoke-PAPermissionAudit @params
            Should -Invoke Find-PAGroupConsolidation -ParameterFilter { $MinimumGroupSize -eq 5 } -Exactly -Times 1
        }

        It 'Format is passed to Export-PAReport' {
            $params = $defaultParams + @{ Format = @('HTML') }
            Invoke-PAPermissionAudit @params
            Should -Invoke Export-PAReport -ParameterFilter { $Format -contains 'HTML' } -Exactly -Times 1
        }
    }

    # =========================================================================
    Context 'Finding counts and aggregates' {

        BeforeAll {
            # Override analyzers so we have a known set of findings to assert against.
            Mock Find-PAUnusedAssignment {
                New-MockCollectorResult -Collector 'Find-PAUnusedAssignment' -Items @(
                    [PSCustomObject]@{ PSTypeName = 'PA.Finding'; FindingId = 'fa1'; Category = 'UnusedAssignment'; Severity = 'High' },
                    [PSCustomObject]@{ PSTypeName = 'PA.Finding'; FindingId = 'fa2'; Category = 'UnusedAssignment'; Severity = 'High' }
                )
            }
            Mock Find-PALeastPrivilegeGap {
                New-MockCollectorResult -Collector 'Find-PALeastPrivilegeGap' -Items @(
                    [PSCustomObject]@{ PSTypeName = 'PA.Finding'; FindingId = 'fb1'; Category = 'OverPrivileged'; Severity = 'Critical' }
                )
            }
            Mock Find-PAGroupConsolidation {
                New-MockCollectorResult -Collector 'Find-PAGroupConsolidation' -Items @(
                    [PSCustomObject]@{ PSTypeName = 'PA.Finding'; FindingId = 'fc1'; Category = 'GroupConsolidation'; Severity = 'Info' }
                )
            }

            $result = Invoke-PAPermissionAudit @defaultParams
        }

        It 'FindingsBySeverity reflects correct counts from mock findings' {
            # Critical=1, High=2, Medium=0, Low=0, Info=1
            $result.FindingsBySeverity.Critical | Should -Be 1
            $result.FindingsBySeverity.High     | Should -Be 2
            $result.FindingsBySeverity.Info     | Should -Be 1
        }

        It 'FindingsByCategory reflects correct counts from mock findings' {
            $result.FindingsByCategory.UnusedAssignment   | Should -Be 2
            $result.FindingsByCategory.OverPrivileged      | Should -Be 1
            $result.FindingsByCategory.GroupConsolidation  | Should -Be 1
        }

        It 'Zero-count severities are still present in FindingsBySeverity' {
            $result.FindingsBySeverity.Keys | Should -Contain 'Medium'
            $result.FindingsBySeverity.Keys | Should -Contain 'Low'
            $result.FindingsBySeverity.Medium | Should -Be 0
            $result.FindingsBySeverity.Low    | Should -Be 0
        }

        It 'TotalAssignments is the sum of all collector ItemCounts' {
            # Default collector mocks each return 1 item — 4 collectors × 1 = 4
            $result.TotalAssignments | Should -Be 4
        }
    }

    # =========================================================================
    Context 'Tier 3 — role action resolution wiring' {

        It 'Calls Resolve-PARoleAction after collecting assignments' {
            Invoke-PAPermissionAudit @defaultParams

            Should -Invoke Resolve-PARoleAction -Exactly -Times 1
        }

        It 'Passes RoleActionMap to Get-PAActivitySignal' {
            Mock Resolve-PARoleAction { @{ '<role-def-id>' = @('some/action') } }

            Invoke-PAPermissionAudit @defaultParams

            Should -Invoke Get-PAActivitySignal -ParameterFilter {
                $null -ne $RoleActionMap -and $RoleActionMap.ContainsKey('<role-def-id>')
            }
        }

        It 'Passes RoleActionMap to Find-PALeastPrivilegeGap' {
            Mock Resolve-PARoleAction { @{ '<role-def-id>' = @('some/action') } }

            Invoke-PAPermissionAudit @defaultParams

            Should -Invoke Find-PALeastPrivilegeGap -ParameterFilter {
                $null -ne $RoleActionMap -and $RoleActionMap.ContainsKey('<role-def-id>')
            }
        }

        It 'Continues with empty map when Resolve-PARoleAction throws' {
            Mock Resolve-PARoleAction { throw 'Graph API timeout' }

            $result = Invoke-PAPermissionAudit @defaultParams

            $result | Should -Not -BeNullOrEmpty
            $result.Warnings | Where-Object { $_ -like '*Role action resolution failed*' } | Should -Not -BeNullOrEmpty
        }
    }
}
