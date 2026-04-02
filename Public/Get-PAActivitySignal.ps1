#Requires -Version 7.0

function Get-PAActivitySignal {
    <#
    .SYNOPSIS
        Collects activity signals per principal from Log Analytics or Graph API.
    .DESCRIPTION
        Queries sign-in and role-related activity for each unique principal
        found in the supplied assignments. Returns PA.ActivityProfile objects
        with last sign-in datetime, role activity evidence, and computed
        activity tier (0–2).

        Two data paths are supported:
        - Log Analytics (preferred): KQL queries across SigninLogs,
          AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs,
          AADManagedIdentitySignInLogs, AuditLogs, and AzureActivity.
          Supports up to 365-day lookback.
        - Graph API (fallback): user.signInActivity property and
          directoryAudits endpoint. Limited to 30-day lookback for audit
          data. No SP sign-in coverage in v1.0.

        Activity tiers: 0 = Active (sign-in + role activity), 1 = NoSignIn,
        2 = NoRoleActivity. Tier 3 (action gap) is computed by
        Find-PALeastPrivilegeGap.
    .PARAMETER Session
        PA.Session object from Connect-PASession. If WorkspaceId is set,
        Log Analytics path is used; otherwise Graph API fallback.
    .PARAMETER Assignments
        Array of PA.Assignment objects from collectors. Used to extract
        unique principal IDs and types.
    .PARAMETER LookbackDays
        Number of days for the activity lookback window. Defaults to 90.
        Capped at 30 for Graph API path (directoryAudits limitation).
    .EXAMPLE
        $sessionParams = @{
            TenantId    = '<tenant-id>'
            WorkspaceId = '<workspace-id>'
        }
        $session = Connect-PASession @sessionParams
        $assignments = ($entraResult.Items + $rbacResult.Items)
        $result = Get-PAActivitySignal -Session $session -Assignments $assignments
        $result.Items.Where({ $_.ActivityTier -ge 1 })

        Collects activity signals and filters to inactive principals.
    .EXAMPLE
        $signalParams = @{
            Session      = $session
            Assignments  = $allAssignments
            LookbackDays = 180
        }
        $result = Get-PAActivitySignal @signalParams
        $result.Items | Group-Object ActivityTier | Select-Object Name, Count

        Collects with 180-day lookback and shows tier distribution.
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Get-PAActivitySignal/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Session,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Assignments,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$LookbackDays = 90
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    # --- Extract unique principals -------------------------------------------

    $principalMap = @{}
    foreach ($a in $Assignments) {
        if (-not $principalMap.ContainsKey($a.PrincipalId)) {
            $principalMap[$a.PrincipalId] = @{
                PrincipalType        = $a.PrincipalType
                PrincipalDisplayName = $a.PrincipalDisplayName
            }
        }
    }

    $principalIds = @($principalMap.Keys)

    if ($principalIds.Count -eq 0) {
        Write-Verbose 'Get-PAActivitySignal: no principals to query'
        $stopwatch.Stop()
        $resultParams = @{
            Collector = 'Get-PAActivitySignal'
            Status    = 'Complete'
            Items     = @()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }

    Write-Verbose "Get-PAActivitySignal: querying activity for $($principalIds.Count) unique principals"

    # --- Determine data source -----------------------------------------------

    $useLogAnalytics = $Session.WorkspaceId -ne ''
    $dataSource = if ($useLogAnalytics) { 'LogAnalytics' } else { 'GraphApi' }

    if (-not $useLogAnalytics -and $LookbackDays -gt 30) {
        $warnings.Add("Graph API path: LookbackDays capped from $LookbackDays to 30 (directoryAudits limitation)")
        Write-Warning "Get-PAActivitySignal: Graph API path — capping LookbackDays to 30"
        $LookbackDays = 30
    }

    Write-Verbose "Get-PAActivitySignal: using $dataSource path with $LookbackDays-day lookback"

    $signInMap = @{}
    $roleActivityMap = @{}

    try {
        if ($useLogAnalytics) {
            # =================================================================
            # Log Analytics path
            # =================================================================

            $idListKql = (@(foreach ($id in $principalIds) { "'$id'" }) -join ',')
            $timespan = [timespan]::FromDays($LookbackDays)

            # Query A: Sign-in summary
            $signInFailed = $false
            try {
                Write-Verbose 'Get-PAActivitySignal: querying sign-in logs (Log Analytics)'
                $signInKql = @"
let ids = dynamic([$idListKql]);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where UserId in (ids)
| summarize LastSignIn=max(TimeGenerated), SignInCount=count() by PrincipalId=UserId
| union (
    union AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs
    | where ServicePrincipalId in (ids)
    | summarize LastSignIn=max(TimeGenerated), SignInCount=count() by PrincipalId=ServicePrincipalId
)
| summarize LastSignIn=max(LastSignIn), SignInCount=sum(SignInCount) by PrincipalId
"@
                $signInQueryParams = @{
                    WorkspaceId = $Session.WorkspaceId
                    Query       = $signInKql
                    Timespan    = $timespan
                }
                $signInRows = Invoke-PALogAnalyticsQuery @signInQueryParams

                foreach ($row in $signInRows) {
                    $signInMap[$row.PrincipalId] = @{
                        LastSignIn  = if ($row.LastSignIn) { [datetime]$row.LastSignIn } else { $null }
                        SignInCount = if ($row.SignInCount) { [int]$row.SignInCount } else { 0 }
                    }
                }
                Write-Verbose "Get-PAActivitySignal: sign-in data for $($signInMap.Count) principals"
            }
            catch {
                $ex = $_
                $signInFailed = $true
                $warnings.Add("Sign-in query failed: $($ex.Exception.Message)")
                Write-Warning "Get-PAActivitySignal: sign-in query failed — $($ex.Exception.Message)"
            }

            # Query B: AuditLogs role activity
            $auditFailed = $false
            try {
                Write-Verbose 'Get-PAActivitySignal: querying AuditLogs (Log Analytics)'
                $auditKql = @"
let ids = dynamic([$idListKql]);
AuditLogs
| extend InitiatorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.objectId))
| where InitiatorId in (ids)
| summarize LastActivity=max(TimeGenerated), ActivityCount=count() by PrincipalId=InitiatorId
"@
                $auditQueryParams = @{
                    WorkspaceId = $Session.WorkspaceId
                    Query       = $auditKql
                    Timespan    = $timespan
                }
                $auditRows = Invoke-PALogAnalyticsQuery @auditQueryParams

                foreach ($row in $auditRows) {
                    $roleActivityMap[$row.PrincipalId] = @{
                        LastActivity  = if ($row.LastActivity) { [datetime]$row.LastActivity } else { $null }
                        ActivityCount = if ($row.ActivityCount) { [int]$row.ActivityCount } else { 0 }
                    }
                }
            }
            catch {
                $ex = $_
                $auditFailed = $true
                $warnings.Add("AuditLogs query failed: $($ex.Exception.Message)")
                Write-Warning "Get-PAActivitySignal: AuditLogs query failed — $($ex.Exception.Message)"
            }

            # Query C: AzureActivity
            try {
                Write-Verbose 'Get-PAActivitySignal: querying AzureActivity (Log Analytics)'
                $azActivityKql = @"
let ids = dynamic([$idListKql]);
AzureActivity
| where Caller in (ids)
| summarize LastActivity=max(TimeGenerated), ActivityCount=count() by PrincipalId=Caller
"@
                $azActivityParams = @{
                    WorkspaceId = $Session.WorkspaceId
                    Query       = $azActivityKql
                    Timespan    = $timespan
                }
                $azRows = Invoke-PALogAnalyticsQuery @azActivityParams

                # Merge with AuditLogs results
                foreach ($row in $azRows) {
                    $lastAz = if ($row.LastActivity) { [datetime]$row.LastActivity } else { $null }
                    $countAz = if ($row.ActivityCount) { [int]$row.ActivityCount } else { 0 }

                    if ($roleActivityMap.ContainsKey($row.PrincipalId)) {
                        $existing = $roleActivityMap[$row.PrincipalId]
                        if ($lastAz -and (-not $existing.LastActivity -or $lastAz -gt $existing.LastActivity)) {
                            $existing.LastActivity = $lastAz
                        }
                        $existing.ActivityCount += $countAz
                    }
                    else {
                        $roleActivityMap[$row.PrincipalId] = @{
                            LastActivity  = $lastAz
                            ActivityCount = $countAz
                        }
                    }
                }
                Write-Verbose "Get-PAActivitySignal: role activity data for $($roleActivityMap.Count) principals"
            }
            catch {
                $ex = $_
                $warnings.Add("AzureActivity query failed: $($ex.Exception.Message)")
                Write-Warning "Get-PAActivitySignal: AzureActivity query failed — $($ex.Exception.Message)"
            }

            if ($signInFailed -and $auditFailed) {
                throw 'Both sign-in and audit queries failed — no activity data available'
            }
        }
        else {
            # =================================================================
            # Graph API fallback path
            # =================================================================

            # User sign-in via signInActivity property
            try {
                Write-Verbose 'Get-PAActivitySignal: fetching user signInActivity (Graph API)'
                $userParams = @{
                    Uri    = '/users'
                    Select = @('id', 'displayName', 'signInActivity')
                }
                $users = Invoke-PAGraphRequest @userParams

                if ($users) {
                    foreach ($user in @($users)) {
                        if ($user.id -and $principalMap.ContainsKey($user.id)) {
                            $sia = $user.signInActivity
                            $lastSignIn = $null
                            if ($sia) {
                                $lastSignIn = if ($sia.lastSuccessfulSignInDateTime) {
                                    [datetime]$sia.lastSuccessfulSignInDateTime
                                }
                                elseif ($sia.lastSignInDateTime) {
                                    [datetime]$sia.lastSignInDateTime
                                }
                                else { $null }
                            }

                            if ($lastSignIn) {
                                $signInMap[$user.id] = @{
                                    LastSignIn  = $lastSignIn
                                    SignInCount = 1
                                }
                            }
                        }
                    }
                }
                Write-Verbose "Get-PAActivitySignal: sign-in data for $($signInMap.Count) users"
            }
            catch {
                $ex = $_
                $warnings.Add("User signInActivity query failed: $($ex.Exception.Message)")
                Write-Warning "Get-PAActivitySignal: user signInActivity query failed — $($ex.Exception.Message)"
            }

            # SP sign-in limitation
            $spPrincipals = $principalIds.Where({
                $principalMap[$_].PrincipalType -eq 'ServicePrincipal'
            })
            if ($spPrincipals.Count -gt 0) {
                $warnings.Add("Graph API path: $($spPrincipals.Count) service principals have no sign-in coverage (no v1.0 endpoint). Use Log Analytics for SP activity.")
                Write-Warning "Get-PAActivitySignal: $($spPrincipals.Count) SPs have no sign-in data on Graph API path"
            }

            # Directory audit logs for role activity
            try {
                Write-Verbose 'Get-PAActivitySignal: fetching directoryAudits (Graph API)'
                $cutoff = [datetime]::UtcNow.AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
                $auditParams = @{
                    Uri    = '/auditLogs/directoryAudits'
                    Filter = "activityDateTime ge $cutoff"
                }
                $audits = Invoke-PAGraphRequest @auditParams

                if ($audits) {
                    foreach ($audit in @($audits)) {
                        $initiatorId = $null
                        if ($audit.initiatedBy) {
                            if ($audit.initiatedBy.user -and $audit.initiatedBy.user.id) {
                                $initiatorId = $audit.initiatedBy.user.id
                            }
                            elseif ($audit.initiatedBy.app -and $audit.initiatedBy.app.objectId) {
                                $initiatorId = $audit.initiatedBy.app.objectId
                            }
                        }

                        if (-not $initiatorId -or -not $principalMap.ContainsKey($initiatorId)) {
                            continue
                        }

                        $activityDt = if ($audit.activityDateTime) {
                            [datetime]$audit.activityDateTime
                        }
                        else { $null }

                        if ($roleActivityMap.ContainsKey($initiatorId)) {
                            $existing = $roleActivityMap[$initiatorId]
                            $existing.ActivityCount++
                            if ($activityDt -and (-not $existing.LastActivity -or $activityDt -gt $existing.LastActivity)) {
                                $existing.LastActivity = $activityDt
                            }
                        }
                        else {
                            $roleActivityMap[$initiatorId] = @{
                                LastActivity  = $activityDt
                                ActivityCount = 1
                            }
                        }
                    }
                }
                Write-Verbose "Get-PAActivitySignal: role activity data for $($roleActivityMap.Count) principals"
            }
            catch {
                $ex = $_
                $warnings.Add("directoryAudits query failed: $($ex.Exception.Message)")
                Write-Warning "Get-PAActivitySignal: directoryAudits query failed — $($ex.Exception.Message)"
            }
        }

        # =================================================================
        # Build activity profiles
        # =================================================================

        $profiles = [System.Collections.Generic.List[object]]::new()

        foreach ($principalId in $principalIds) {
            $principal = $principalMap[$principalId]

            # Sign-in data
            $lastSignIn = $null
            $signInCount = 0
            if ($signInMap.ContainsKey($principalId)) {
                $lastSignIn = $signInMap[$principalId].LastSignIn
                $signInCount = $signInMap[$principalId].SignInCount
            }

            # Role activity data
            $lastRoleActivity = $null
            $roleActivityCount = 0
            if ($roleActivityMap.ContainsKey($principalId)) {
                $lastRoleActivity = $roleActivityMap[$principalId].LastActivity
                $roleActivityCount = $roleActivityMap[$principalId].ActivityCount
            }

            # Compute activity tier (0, 1, 2)
            $activityTier = if ($null -eq $lastSignIn) {
                1  # NoSignIn
            }
            elseif ($null -eq $lastRoleActivity) {
                2  # NoRoleActivity
            }
            else {
                0  # Active
            }

            $profileParams = @{
                PrincipalId              = $principalId
                PrincipalDisplayName     = $principal.PrincipalDisplayName
                PrincipalType            = $principal.PrincipalType
                LastSignInDateTime       = $lastSignIn
                LastRoleActivityDateTime = $lastRoleActivity
                SignInCount              = $signInCount
                RoleActivityCount        = $roleActivityCount
                ActivityTier             = $activityTier
                LookbackDays             = $LookbackDays
                DataSource               = $dataSource
            }
            $profiles.Add((New-PAActivityProfile @profileParams))
        }

        # =================================================================
        # Result assembly
        # =================================================================

        $stopwatch.Stop()

        $status = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }

        Write-Verbose "Get-PAActivitySignal: returning $($profiles.Count) profiles ($status) in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

        $resultParams = @{
            Collector = 'Get-PAActivitySignal'
            Status    = $status
            Items     = $profiles.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
    catch {
        $ex = $_
        $stopwatch.Stop()
        $errors.Add($ex.Exception.Message)
        Write-Warning "Get-PAActivitySignal: failed — $($ex.Exception.Message)"

        $resultParams = @{
            Collector = 'Get-PAActivitySignal'
            Status    = 'Failed'
            Items     = @()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
}
