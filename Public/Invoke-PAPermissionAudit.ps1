#Requires -Version 7.0

function Invoke-PAPermissionAudit {
    <#
    .SYNOPSIS
        Runs a complete permission audit pipeline.
    .DESCRIPTION
        End-to-end orchestrator that connects to a tenant, collects all permission
        assignments across four planes (Entra roles, PIM, Azure RBAC, app permissions),
        gathers activity signals, runs three analyzers (unused assignments, least
        privilege gaps, group consolidation), generates reports and remediation scripts,
        and optionally re-validates findings. Each stage is independently error-isolated
        so a single failure does not prevent the remaining pipeline from completing.
        The module never executes changes — it produces findings, reports, and scripts
        for manual review.
    .PARAMETER TenantId
        Entra ID tenant identifier.
    .PARAMETER Environment
        Cloud environment. Defaults to Global.
    .PARAMETER SubscriptionId
        Explicit list of Azure subscription IDs to scope. If empty, all enabled
        subscriptions are auto-discovered.
    .PARAMETER WorkspaceId
        Log Analytics workspace ID for activity signal collection. If empty, falls
        back to Graph API direct queries (30-day cap).
    .PARAMETER OutputDirectory
        Directory path where reports and remediation scripts are written.
    .PARAMETER LookbackDays
        Activity lookback window in days. Defaults to 90.
    .PARAMETER InactivityThresholdDays
        Days without role activity before a Tier 0 principal triggers an unused
        assignment finding. Defaults to 90.
    .PARAMETER GapThreshold
        Minimum gap ratio (0.0–1.0) for least privilege gap findings. Defaults to 0.5.
    .PARAMETER MinimumGroupSize
        Minimum principals sharing a role+scope for group consolidation. Defaults to 3.
    .PARAMETER Format
        Output formats for the report. Defaults to CSV and JSON.
    .PARAMETER SkipRemediation
        Skip remediation script generation.
    .PARAMETER SkipValidation
        Skip finding re-validation against live data.
    .EXAMPLE
        $audit = Invoke-PAPermissionAudit -TenantId '<tenant-id>' -OutputDirectory './audit-output'
    .EXAMPLE
        $auditParams = @{
            TenantId        = '<tenant-id>'
            WorkspaceId     = '<workspace-id>'
            OutputDirectory = './audit-output'
            Format          = @('CSV', 'JSON', 'HTML')
            LookbackDays    = 180
        }
        $audit = Invoke-PAPermissionAudit @auditParams
    .EXAMPLE
        $auditParams = @{
            TenantId              = '<tenant-id>'
            OutputDirectory       = './audit-output'
            InactivityThresholdDays = 30
            GapThreshold          = 0.3
            MinimumGroupSize      = 2
            SkipValidation        = $true
        }
        $audit = Invoke-PAPermissionAudit @auditParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.AuditResult)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Invoke-PAPermissionAudit/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter()]
        [ValidateSet('Global', 'USGov', 'USGovDoD')]
        [string]$Environment = 'Global',

        [Parameter()]
        [string[]]$SubscriptionId = @(),

        [Parameter()]
        [string]$WorkspaceId = '',

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$LookbackDays = 90,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$InactivityThresholdDays = 90,

        [Parameter()]
        [ValidateRange(0.0, 1.0)]
        [double]$GapThreshold = 0.5,

        [Parameter()]
        [ValidateRange(2, 100)]
        [int]$MinimumGroupSize = 3,

        [Parameter()]
        [ValidateSet('CSV', 'JSON', 'HTML')]
        [string[]]$Format = @('CSV', 'JSON'),

        [Parameter()]
        [switch]$SkipRemediation,

        [Parameter()]
        [switch]$SkipValidation
    )

    $auditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $allWarnings = [System.Collections.Generic.List[string]]::new()
    $allErrors = [System.Collections.Generic.List[string]]::new()

    # ================================================================
    # Stage 1 — Connect (fatal on failure)
    # ================================================================

    Write-Verbose 'Invoke-PAPermissionAudit: Stage 1 — connecting to tenant'
    $session = $null
    try {
        $connectParams = @{
            TenantId       = $TenantId
            Environment    = $Environment
            WorkspaceId    = $WorkspaceId
            SubscriptionId = $SubscriptionId
        }
        $session = Connect-PASession @connectParams
        Write-Verbose "Invoke-PAPermissionAudit: connected (RunId: $($session.RunId))"
    }
    catch {
        $ex = $_
        Write-Warning "Invoke-PAPermissionAudit: connection failed — $($ex.Exception.Message)"
        throw
    }

    try {
        # ================================================================
        # Stage 2 — Collect assignments (per-collector error isolation)
        # ================================================================

        Write-Verbose 'Invoke-PAPermissionAudit: Stage 2 — collecting assignments'

        $collectorNames = @(
            'Get-PAEntraRoleAssignment'
            'Get-PAPimEligibility'
            'Get-PAAzureRbacAssignment'
            'Get-PAAppPermission'
        )
        $collectorResults = [ordered]@{}

        foreach ($collectorName in $collectorNames) {
            try {
                Write-Verbose "Invoke-PAPermissionAudit: running $collectorName"
                $cr = & $collectorName -Session $session
                $collectorResults[$collectorName] = $cr
                Write-Verbose "Invoke-PAPermissionAudit: $collectorName — $($cr.Status), $($cr.ItemCount) items"
            }
            catch {
                $ex = $_
                $msg = "$collectorName failed: $($ex.Exception.Message)"
                $allWarnings.Add($msg)
                Write-Warning "Invoke-PAPermissionAudit: $msg"
                $collectorResults[$collectorName] = $null
            }
        }

        # Merge all assignments
        $allAssignments = @(
            foreach ($cr in $collectorResults.Values) {
                if ($cr -and $cr.Items) {
                    foreach ($item in $cr.Items) { $item }
                }
            }
        )
        Write-Verbose "Invoke-PAPermissionAudit: $($allAssignments.Count) total assignments collected"

        if ($allAssignments.Count -eq 0) {
            $allWarnings.Add('No assignments collected — report will be empty')
            Write-Warning 'Invoke-PAPermissionAudit: no assignments collected — report will be empty'
        }

        # ================================================================
        # Stage 2.5 — Resolve role definition actions (for Tier 3)
        # ================================================================

        Write-Verbose 'Invoke-PAPermissionAudit: Stage 2.5 — resolving role definition actions'
        $roleActionMap = @{}
        try {
            $roleActionMap = Resolve-PARoleAction -Assignments $allAssignments -Session $session
            Write-Verbose "Invoke-PAPermissionAudit: resolved $($roleActionMap.Count) role definitions to action lists"
        }
        catch {
            $ex = $_
            $msg = "Role action resolution failed: $($ex.Exception.Message)"
            $allWarnings.Add($msg)
            Write-Warning "Invoke-PAPermissionAudit: $msg — Tier 3 analysis may be limited"
        }

        # ================================================================
        # Stage 3 — Activity signals
        # ================================================================

        Write-Verbose 'Invoke-PAPermissionAudit: Stage 3 — collecting activity signals'
        $activityResult = $null
        $activityProfiles = @()

        try {
            $activityParams = @{
                Session       = $session
                Assignments   = $allAssignments
                LookbackDays  = $LookbackDays
                RoleActionMap = $roleActionMap
            }
            $activityResult = Get-PAActivitySignal @activityParams
            $activityProfiles = @($activityResult.Items)
            Write-Verbose "Invoke-PAPermissionAudit: activity signals — $($activityResult.Status), $($activityProfiles.Count) profiles"
        }
        catch {
            $ex = $_
            $msg = "Activity signal collection failed: $($ex.Exception.Message)"
            $allWarnings.Add($msg)
            Write-Warning "Invoke-PAPermissionAudit: $msg"
        }

        # ================================================================
        # Stage 4 — Analyze (per-analyzer error isolation)
        # ================================================================

        Write-Verbose 'Invoke-PAPermissionAudit: Stage 4 — running analyzers'

        $unusedResult = $null
        try {
            $unusedParams = @{
                Assignments            = $allAssignments
                ActivityProfiles       = $activityProfiles
                InactivityThresholdDays = $InactivityThresholdDays
            }
            $unusedResult = Find-PAUnusedAssignment @unusedParams
            Write-Verbose "Invoke-PAPermissionAudit: Find-PAUnusedAssignment — $($unusedResult.Status), $($unusedResult.ItemCount) findings"
        }
        catch {
            $ex = $_
            $msg = "Find-PAUnusedAssignment failed: $($ex.Exception.Message)"
            $allWarnings.Add($msg)
            Write-Warning "Invoke-PAPermissionAudit: $msg"
        }

        $leastPrivResult = $null
        try {
            $leastPrivParams = @{
                Assignments      = $allAssignments
                ActivityProfiles = $activityProfiles
                GapThreshold     = $GapThreshold
                RoleActionMap    = $roleActionMap
            }
            $leastPrivResult = Find-PALeastPrivilegeGap @leastPrivParams
            Write-Verbose "Invoke-PAPermissionAudit: Find-PALeastPrivilegeGap — $($leastPrivResult.Status), $($leastPrivResult.ItemCount) findings"
        }
        catch {
            $ex = $_
            $msg = "Find-PALeastPrivilegeGap failed: $($ex.Exception.Message)"
            $allWarnings.Add($msg)
            Write-Warning "Invoke-PAPermissionAudit: $msg"
        }

        $groupResult = $null
        try {
            $groupParams = @{
                Assignments      = $allAssignments
                MinimumGroupSize = $MinimumGroupSize
            }
            $groupResult = Find-PAGroupConsolidation @groupParams
            Write-Verbose "Invoke-PAPermissionAudit: Find-PAGroupConsolidation — $($groupResult.Status), $($groupResult.ItemCount) findings"
        }
        catch {
            $ex = $_
            $msg = "Find-PAGroupConsolidation failed: $($ex.Exception.Message)"
            $allWarnings.Add($msg)
            Write-Warning "Invoke-PAPermissionAudit: $msg"
        }

        # Merge all findings
        $allFindings = @(
            foreach ($ar in @($unusedResult, $leastPrivResult, $groupResult)) {
                if ($ar -and $ar.Items) {
                    foreach ($item in $ar.Items) { $item }
                }
            }
        )
        Write-Verbose "Invoke-PAPermissionAudit: $($allFindings.Count) total findings"

        # ================================================================
        # Stage 5 — Report
        # ================================================================

        Write-Verbose 'Invoke-PAPermissionAudit: Stage 5 — generating reports'
        $reportResult = $null

        try {
            $reportParams = @{
                Findings        = $allFindings
                OutputDirectory = $OutputDirectory
                Format          = $Format
                RunId           = $session.RunId
            }
            $reportResult = Export-PAReport @reportParams
            Write-Verbose "Invoke-PAPermissionAudit: report — $($reportResult.OutputFiles.Count) file(s) written"
        }
        catch {
            $ex = $_
            $msg = "Export-PAReport failed: $($ex.Exception.Message)"
            $allWarnings.Add($msg)
            Write-Warning "Invoke-PAPermissionAudit: $msg"
        }

        # ================================================================
        # Stage 6 — Remediation (optional)
        # ================================================================

        $remediationResult = $null

        if ($SkipRemediation) {
            Write-Verbose 'Invoke-PAPermissionAudit: Stage 6 — remediation skipped (-SkipRemediation)'
        }
        else {
            Write-Verbose 'Invoke-PAPermissionAudit: Stage 6 — generating remediation scripts'
            try {
                $remParams = @{
                    Findings        = $allFindings
                    OutputDirectory = $OutputDirectory
                    RunId           = $session.RunId
                }
                $remediationResult = New-PARemediationScript @remParams
                Write-Verbose "Invoke-PAPermissionAudit: remediation — $($remediationResult.ScriptPaths.Count) script(s) written"
            }
            catch {
                $ex = $_
                $msg = "New-PARemediationScript failed: $($ex.Exception.Message)"
                $allWarnings.Add($msg)
                Write-Warning "Invoke-PAPermissionAudit: $msg"
            }
        }

        # ================================================================
        # Stage 7 — Validation (optional)
        # ================================================================

        $validationResult = $null

        if ($SkipValidation) {
            Write-Verbose 'Invoke-PAPermissionAudit: Stage 7 — validation skipped (-SkipValidation)'
        }
        else {
            Write-Verbose 'Invoke-PAPermissionAudit: Stage 7 — validating findings'
            try {
                $validationParams = @{
                    Findings = $allFindings
                    Session  = $session
                }
                $validationResult = Test-PAFindingAccuracy @validationParams
                Write-Verbose "Invoke-PAPermissionAudit: validation — $($validationResult.Status), $($validationResult.ItemCount) items"
            }
            catch {
                $ex = $_
                $msg = "Test-PAFindingAccuracy failed: $($ex.Exception.Message)"
                $allWarnings.Add($msg)
                Write-Warning "Invoke-PAPermissionAudit: $msg"
            }
        }

        # ================================================================
        # Build summary counts
        # ================================================================

        $severityCounts = [ordered]@{
            Critical = 0
            High     = 0
            Medium   = 0
            Low      = 0
            Info     = 0
        }
        $categoryCounts = [ordered]@{
            UnusedAssignment   = 0
            OverPrivileged     = 0
            GroupConsolidation = 0
        }

        foreach ($finding in $allFindings) {
            if ($severityCounts.Contains($finding.Severity)) {
                $severityCounts[$finding.Severity]++
            }
            if ($categoryCounts.Contains($finding.Category)) {
                $categoryCounts[$finding.Category]++
            }
        }

        # ================================================================
        # Build and return PA.AuditResult
        # ================================================================

        $auditStopwatch.Stop()

        $result = [PSCustomObject]@{
            PSTypeName          = 'PA.AuditResult'
            RunId               = $session.RunId
            TenantId            = $session.TenantId
            Environment         = $session.Environment
            Duration            = $auditStopwatch.Elapsed
            CollectorResults    = [ordered]@{
                EntraRoleAssignment = $collectorResults['Get-PAEntraRoleAssignment']
                PimEligibility      = $collectorResults['Get-PAPimEligibility']
                AzureRbacAssignment = $collectorResults['Get-PAAzureRbacAssignment']
                AppPermission       = $collectorResults['Get-PAAppPermission']
                ActivitySignal      = $activityResult
            }
            TotalAssignments    = $allAssignments.Count
            TotalActivityProfiles = $activityProfiles.Count
            AnalyzerResults     = [ordered]@{
                UnusedAssignment   = $unusedResult
                LeastPrivilegeGap  = $leastPrivResult
                GroupConsolidation = $groupResult
            }
            TotalFindings       = $allFindings.Count
            FindingsBySeverity  = $severityCounts
            FindingsByCategory  = $categoryCounts
            ReportResult        = $reportResult
            RemediationResult   = $remediationResult
            ValidationResult    = $validationResult
            Warnings            = $allWarnings.ToArray()
            Errors              = $allErrors.ToArray()
        }

        Write-Verbose "Invoke-PAPermissionAudit: complete — $($allFindings.Count) findings, $($auditStopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

        return $result
    }
    catch {
        $ex = $_
        Write-Warning "Invoke-PAPermissionAudit: pipeline failed — $($ex.Exception.Message)"
        throw
    }
}
