#Requires -Version 7.0

function Find-PALeastPrivilegeGap {
    <#
    .SYNOPSIS
        Identifies over-privileged access by comparing granted vs used permissions.
    .DESCRIPTION
        Analyzes PA.Assignment objects against PA.ActivityProfile data to identify
        assignments where the principal uses only a fraction of their granted
        permissions. Compares granted and used actions at the namespace level
        (first two path segments) and generates PA.Finding objects when the gap
        ratio meets or exceeds the threshold.

        Requires GrantedActions and UsedActions to be populated in the activity
        profiles. Profiles with empty action data are skipped with a warning.
    .PARAMETER Assignments
        Array of PA.Assignment objects from collectors.
    .PARAMETER ActivityProfiles
        Array of PA.ActivityProfile objects from Get-PAActivitySignal.
    .PARAMETER RoleActionMap
        Hashtable mapping RoleDefinitionId to string arrays of granted
        actions, as returned by Resolve-PARoleAction. When supplied, the
        analyzer uses per-assignment granted actions from the map instead
        of the per-principal GrantedActions from the activity profile. This
        gives accurate per-role gap analysis.
    .PARAMETER GapThreshold
        Minimum gap ratio (0.0–1.0) to generate a finding. A value of 0.5 means
        the principal must be using less than 50% of their granted namespaces.
        Defaults to 0.5.
    .EXAMPLE
        $findings = Find-PALeastPrivilegeGap -Assignments $assignments -ActivityProfiles $actProfiles
    .EXAMPLE
        $findingParams = @{
            Assignments      = $assignments
            ActivityProfiles = $actProfiles
            GapThreshold     = 0.3
        }
        $findings = Find-PALeastPrivilegeGap @findingParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult) wrapping PA.Finding items.
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PALeastPrivilegeGap/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Assignments,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$ActivityProfiles,

        [Parameter()]
        [hashtable]$RoleActionMap,

        [Parameter()]
        [ValidateRange(0.0, 1.0)]
        [double]$GapThreshold = 0.5
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    # Critical role names for severity escalation
    $criticalRoles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $roleNames = @(
        'Global Administrator'
        'Privileged Role Administrator'
        'Privileged Authentication Administrator'
        'Application Administrator'
        'Cloud Application Administrator'
        'Exchange Administrator'
        'SharePoint Administrator'
        'Security Administrator'
        'User Access Administrator'
        'Owner'
        'Contributor'
    )
    foreach ($roleName in $roleNames) { [void]$criticalRoles.Add($roleName) }

    # Early return for empty assignments
    if ($Assignments.Count -eq 0) {
        $stopwatch.Stop()
        $resultParams = @{
            Collector = 'Find-PALeastPrivilegeGap'
            Status    = 'Complete'
            Items     = @()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }

    try {
        $findings = [System.Collections.Generic.List[object]]::new()

        # Build profile lookup by PrincipalId
        $actProfileMap = @{}
        foreach ($actProfile in $ActivityProfiles) {
            $actProfileMap[$actProfile.PrincipalId] = $actProfile
        }

        foreach ($assignment in $Assignments) {
            try {
                $principalId = $assignment.PrincipalId

                # Skip AppPermission assignments (app roles don't map to allowedResourceActions)
                if ($assignment.Source -eq 'AppPermission') {
                    Write-Verbose "Find-PALeastPrivilegeGap: skipping AppPermission assignment for '$principalId' — app roles require different analysis"
                    continue
                }

                $actProfile = $actProfileMap[$principalId]

                # Skip assignments with no activity profile
                if ($null -eq $actProfile) {
                    $msg = "No activity profile for principal '$principalId' — skipping"
                    $warnings.Add($msg)
                    Write-Warning "Find-PALeastPrivilegeGap: $msg"
                    continue
                }

                # Skip Tier 1 profiles (no sign-in — covered by Find-PAUnusedAssignment)
                if ($actProfile.ActivityTier -eq 1) {
                    continue
                }

                # Skip profiles with no action data
                if ($actProfile.GrantedActions.Count -eq 0 -and $actProfile.UsedActions.Count -eq 0) {
                    $msg = "No action data for principal '$principalId' — GrantedActions and UsedActions are empty"
                    $warnings.Add($msg)
                    Write-Warning "Find-PALeastPrivilegeGap: $msg"
                    continue
                }

                # Skip profiles where UsedActions is empty (no activity = covered by UnusedAssignment Tier 2)
                if ($actProfile.UsedActions.Count -eq 0) {
                    continue
                }

                # Resolve granted actions: per-assignment from RoleActionMap, or per-principal fallback
                $roleGrantedActions = if ($RoleActionMap -and $RoleActionMap.ContainsKey($assignment.RoleDefinitionId)) {
                    $RoleActionMap[$assignment.RoleDefinitionId]
                }
                else {
                    $actProfile.GrantedActions
                }

                # Skip if no granted actions to compare against
                if ($roleGrantedActions.Count -eq 0) {
                    continue
                }

                # Extract namespace prefixes (first 2 path segments)
                $grantedNamespaces = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase
                )
                foreach ($action in $roleGrantedActions) {
                    $segments = $action -split '/'
                    if ($segments.Count -ge 2) {
                        [void]$grantedNamespaces.Add("$($segments[0])/$($segments[1])")
                    }
                }

                $usedNamespaces = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase
                )
                foreach ($action in $actProfile.UsedActions) {
                    $segments = $action -split '/'
                    if ($segments.Count -ge 2) {
                        [void]$usedNamespaces.Add("$($segments[0])/$($segments[1])")
                    }
                }

                # Skip if no granted namespaces after extraction
                if ($grantedNamespaces.Count -eq 0) {
                    continue
                }

                # Compute gap ratio
                $usedInGranted = 0
                foreach ($ns in $usedNamespaces) {
                    if ($grantedNamespaces.Contains($ns)) {
                        $usedInGranted++
                    }
                }
                $gapRatio = [double](1.0 - ($usedInGranted / $grantedNamespaces.Count))

                # Skip if below threshold
                if ($gapRatio -lt $GapThreshold) {
                    continue
                }

                # Compute unused namespaces
                $unusedNamespaces = [System.Collections.Generic.List[string]]::new()
                foreach ($ns in $grantedNamespaces) {
                    if (-not $usedNamespaces.Contains($ns)) {
                        $unusedNamespaces.Add($ns)
                    }
                }

                # Determine severity
                $isCritical = $criticalRoles.Contains($assignment.RoleName)
                $severity = if ($gapRatio -ge 0.9) {
                    if ($isCritical) { 'Critical' } else { 'High' }
                }
                elseif ($gapRatio -ge 0.75) {
                    if ($isCritical) { 'High' } else { 'Medium' }
                }
                else {
                    # >= GapThreshold (default 0.5)
                    if ($isCritical) { 'High' } else { 'Medium' }
                }

                $usedPercent = [int]((1 - $gapRatio) * 100)
                $title = "$($assignment.PrincipalType) '$($assignment.PrincipalDisplayName)' uses ${usedPercent}% of $($assignment.RoleName) permissions ($($unusedNamespaces.Count) unused namespaces)"

                $usedNamespacesSummary = ($usedNamespaces | Sort-Object) -join ', '
                $recommendation = "Consider downgrading from $($assignment.RoleName) to a more specific role covering only: $usedNamespacesSummary"

                $grantedArr = @($grantedNamespaces | Sort-Object)
                $usedArr = @($usedNamespaces | Sort-Object)
                $unusedArr = @($unusedNamespaces | Sort-Object)

                $findingParams = @{
                    Category             = 'OverPrivileged'
                    Severity             = $severity
                    Title                = $title
                    PrincipalId          = $principalId
                    PrincipalDisplayName = $assignment.PrincipalDisplayName
                    PrincipalType        = $assignment.PrincipalType
                    RoleName             = $assignment.RoleName
                    RoleDefinitionId     = $assignment.RoleDefinitionId
                    Scope                = $assignment.Scope
                    Source               = $assignment.Source
                    ActivityTier         = 3
                    DaysSinceActive      = $actProfile.DaysSinceLastRoleActivity
                    Recommendation       = $recommendation
                    RemediationAction    = 'Downgrade'
                    Details              = @{
                        AssignmentType    = $assignment.AssignmentType
                        ScopeType         = $assignment.ScopeType
                        RoleType          = $assignment.RoleType
                        GapRatio          = [double]$gapRatio
                        GrantedNamespaces = $grantedArr
                        UsedNamespaces    = $usedArr
                        UnusedNamespaces  = $unusedArr
                        LookbackDays      = $actProfile.LookbackDays
                        DataSource        = $actProfile.DataSource
                    }
                }

                $findings.Add((New-PAFinding @findingParams))
            }
            catch {
                $ex = $_
                $msg = "Failed to analyze assignment for '$($assignment.PrincipalId)': $($ex.Exception.Message)"
                $warnings.Add($msg)
                Write-Warning "Find-PALeastPrivilegeGap: $msg"
            }
        }

        $stopwatch.Stop()
        $status = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }

        $resultParams = @{
            Collector = 'Find-PALeastPrivilegeGap'
            Status    = $status
            Items     = $findings.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
    catch {
        $ex = $_
        $stopwatch.Stop()
        $errors.Add($ex.Exception.Message)
        Write-Warning "Find-PALeastPrivilegeGap: failed — $($ex.Exception.Message)"

        $resultParams = @{
            Collector = 'Find-PALeastPrivilegeGap'
            Status    = 'Failed'
            Items     = @()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
}
