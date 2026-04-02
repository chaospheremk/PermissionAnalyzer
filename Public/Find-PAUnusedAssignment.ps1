#Requires -Version 7.0

function Find-PAUnusedAssignment {
    <#
    .SYNOPSIS
        Identifies unused role assignments based on activity analysis.
    .DESCRIPTION
        Analyzes PA.Assignment objects against PA.ActivityProfile data to identify
        assignments where the principal shows no sign-in (Tier 1), no role-related
        activity (Tier 2), or stale role usage exceeding the inactivity threshold
        (Tier 0 threshold breach). Each unused assignment produces a PA.Finding with
        severity scaled by activity tier and role criticality.
    .PARAMETER Assignments
        Array of PA.Assignment objects from collectors.
    .PARAMETER ActivityProfiles
        Array of PA.ActivityProfile objects from Get-PAActivitySignal.
    .PARAMETER InactivityThresholdDays
        Number of days without role activity before a Tier 0 principal triggers a
        finding. Defaults to 90.
    .EXAMPLE
        $findings = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles $profiles
    .EXAMPLE
        $findings = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles $profiles -InactivityThresholdDays 30
    .OUTPUTS
        PSCustomObject (PA.CollectorResult) wrapping PA.Finding items.
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
        [ValidateRange(1, 365)]
        [int]$InactivityThresholdDays = 90
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    # Critical role names for severity escalation
    $criticalRoles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @(
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
    ) | ForEach-Object { [void]$criticalRoles.Add($_) }

    # Early return for empty assignments
    if ($Assignments.Count -eq 0) {
        $stopwatch.Stop()
        $resultParams = @{
            Collector = 'Find-PAUnusedAssignment'
            Status    = 'Complete'
            Items     = @()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }

    try {
        $findings = [System.Collections.Generic.List[object]]::new()

        # Build profile lookup by PrincipalId
        $profileMap = @{}
        foreach ($profile in $ActivityProfiles) {
            $profileMap[$profile.PrincipalId] = $profile
        }

        foreach ($assignment in $Assignments) {
            try {
                $principalId = $assignment.PrincipalId
                $profile = $profileMap[$principalId]

                # Skip assignments with no activity profile
                if ($null -eq $profile) {
                    $msg = "No activity profile for principal '$principalId' — skipping"
                    $warnings.Add($msg)
                    Write-Warning "Find-PAUnusedAssignment: $msg"
                    continue
                }

                $tier = $profile.ActivityTier
                $isCritical = $criticalRoles.Contains($assignment.RoleName)

                # Determine if this assignment qualifies as unused
                $daysSinceActive = $null
                $severity = $null

                if ($tier -eq 1) {
                    # Tier 1: No sign-in
                    $daysSinceActive = if ($null -ne $profile.DaysSinceLastSignIn) {
                        $profile.DaysSinceLastSignIn
                    } else {
                        $profile.LookbackDays
                    }
                    $severity = if ($isCritical) { 'Critical' } else { 'High' }
                }
                elseif ($tier -eq 2) {
                    # Tier 2: Signs in but no role-related activity
                    $daysSinceActive = if ($null -ne $profile.DaysSinceLastRoleActivity) {
                        $profile.DaysSinceLastRoleActivity
                    } else {
                        $profile.LookbackDays
                    }
                    $severity = if ($isCritical) { 'High' } else { 'Medium' }
                }
                elseif ($tier -eq 0) {
                    # Tier 0: Active principal — check for stale role usage
                    $effectiveDays = if ($null -ne $profile.DaysSinceLastRoleActivity) {
                        $profile.DaysSinceLastRoleActivity
                    } else {
                        $profile.LookbackDays
                    }

                    if ($effectiveDays -gt $InactivityThresholdDays) {
                        $daysSinceActive = $effectiveDays
                        $severity = if ($isCritical) { 'Medium' } else { 'Low' }
                    }
                    else {
                        # Active and within threshold — no finding
                        continue
                    }
                }
                else {
                    # Tier 3 or unknown — skip (handled by Find-PALeastPrivilegeGap)
                    continue
                }

                # Determine remediation action
                $remediationAction = if ($assignment.AssignmentType -eq 'Eligible') {
                    'ReviewEligible'
                } else {
                    'Remove'
                }

                # Build title and recommendation
                $activityDesc = switch ($tier) {
                    1 { 'no sign-in' }
                    2 { 'no role activity' }
                    0 { 'no role activity' }
                }

                $title = "$($assignment.PrincipalType) '$($assignment.PrincipalDisplayName)' has $($assignment.RoleName) with $activityDesc in $daysSinceActive days"

                $recommendation = if ($assignment.AssignmentType -eq 'Eligible') {
                    "Review and consider removing the eligible $($assignment.RoleName) assignment for $($assignment.PrincipalDisplayName)."
                } else {
                    "Remove the $($assignment.RoleName) assignment for $($assignment.PrincipalDisplayName)."
                }

                $findingParams = @{
                    Category             = 'UnusedAssignment'
                    Severity             = $severity
                    Title                = $title
                    PrincipalId          = $principalId
                    PrincipalDisplayName = $assignment.PrincipalDisplayName
                    PrincipalType        = $assignment.PrincipalType
                    RoleName             = $assignment.RoleName
                    RoleDefinitionId     = $assignment.RoleDefinitionId
                    Scope                = $assignment.Scope
                    Source               = $assignment.Source
                    ActivityTier         = $tier
                    DaysSinceActive      = $daysSinceActive
                    Recommendation       = $recommendation
                    RemediationAction    = $remediationAction
                    Details              = @{
                        AssignmentType = $assignment.AssignmentType
                        ScopeType      = $assignment.ScopeType
                        RoleType       = $assignment.RoleType
                        LookbackDays   = $profile.LookbackDays
                        DataSource     = $profile.DataSource
                    }
                }

                $findings.Add((New-PAFinding @findingParams))
            }
            catch {
                $msg = "Failed to analyze assignment for '$($assignment.PrincipalId)': $($_.Exception.Message)"
                $warnings.Add($msg)
                Write-Warning "Find-PAUnusedAssignment: $msg"
            }
        }

        $stopwatch.Stop()
        $status = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }

        $resultParams = @{
            Collector = 'Find-PAUnusedAssignment'
            Status    = $status
            Items     = $findings.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
    catch {
        $stopwatch.Stop()
        $errors.Add($_.Exception.Message)
        Write-Warning "Find-PAUnusedAssignment: failed — $($_.Exception.Message)"

        $resultParams = @{
            Collector = 'Find-PAUnusedAssignment'
            Status    = 'Failed'
            Items     = @()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
}
