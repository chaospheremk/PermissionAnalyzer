#Requires -Version 7.0

function Find-PAGroupConsolidation {
    <#
    .SYNOPSIS
        Identifies opportunities to consolidate individual role assignments into groups.
    .DESCRIPTION
        Analyzes PA.Assignment objects to find patterns where multiple principals
        share the same role at the same scope, indicating that a group-based
        assignment would simplify management. Only considers User and
        ServicePrincipal assignments (groups are already consolidated).
        Generates one PA.Finding per consolidation opportunity.
    .PARAMETER Assignments
        Array of PA.Assignment objects from collectors.
    .PARAMETER MinimumGroupSize
        Minimum number of distinct principals sharing the same role+scope before
        a consolidation finding is generated. Defaults to 3.
    .EXAMPLE
        $findings = Find-PAGroupConsolidation -Assignments $assignments
    .EXAMPLE
        $findings = Find-PAGroupConsolidation -Assignments $assignments -MinimumGroupSize 5
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult) wrapping PA.Finding items.
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PAGroupConsolidation/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Assignments,

        [Parameter()]
        [ValidateRange(2, 100)]
        [int]$MinimumGroupSize = 3
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
            Collector = 'Find-PAGroupConsolidation'
            Status    = 'Complete'
            Items     = @()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }

    try {
        $findings = [System.Collections.Generic.List[object]]::new()

        # Filter to individual assignments (User/ServicePrincipal only, exclude DelegatedGrant)
        $eligible = $Assignments.Where({
            ($_.PrincipalType -eq 'User' -or $_.PrincipalType -eq 'ServicePrincipal' -or $_.PrincipalType -eq 'ManagedIdentity') -and
            $_.AssignmentType -ne 'DelegatedGrant'
        })

        # Group by Source|RoleDefinitionId|Scope
        $groups = @{}
        foreach ($assignment in $eligible) {
            $key = "$($assignment.Source)|$($assignment.RoleDefinitionId)|$($assignment.Scope)"
            if (-not $groups.ContainsKey($key)) {
                $groups[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $groups[$key].Add($assignment)
        }

        foreach ($entry in $groups.GetEnumerator()) {
            try {
                $groupAssignments = $entry.Value

                # Get distinct principals
                $principalMap = @{}
                foreach ($a in $groupAssignments) {
                    if (-not $principalMap.ContainsKey($a.PrincipalId)) {
                        $principalMap[$a.PrincipalId] = $a.PrincipalDisplayName
                    }
                }

                $principalCount = $principalMap.Count
                if ($principalCount -lt $MinimumGroupSize) {
                    continue
                }

                # Sort principals alphabetically for deterministic output
                $sortedIds = @($principalMap.Keys | Sort-Object)
                $sortedNames = @(foreach ($id in $sortedIds) { $principalMap[$id] })

                # Use first alphabetically for FindingId determinism
                $firstPrincipalId = $sortedIds[0]
                $firstPrincipalName = $sortedNames[0]

                # Get representative assignment for role/scope metadata
                $rep = $groupAssignments[0]

                # Collect unique assignment types
                $assignmentTypes = @($groupAssignments | Select-Object -ExpandProperty AssignmentType -Unique | Sort-Object)

                # Determine severity
                $isCritical = $criticalRoles.Contains($rep.RoleName)
                $severity = if ($principalCount -ge 10) {
                    if ($isCritical) { 'High' } else { 'Medium' }
                }
                elseif ($principalCount -ge 5) {
                    if ($isCritical) { 'Medium' } else { 'Low' }
                }
                else {
                    if ($isCritical) { 'Low' } else { 'Info' }
                }

                $title = "$principalCount principals share $($rep.RoleName) at $($rep.Scope) — consolidate to group assignment"
                $recommendation = "Create a security group and assign $($rep.RoleName) at $($rep.Scope) to the group. Add these $principalCount principals as members."

                $findingParams = @{
                    Category             = 'GroupConsolidation'
                    Severity             = $severity
                    Title                = $title
                    PrincipalId          = $firstPrincipalId
                    PrincipalDisplayName = $firstPrincipalName
                    PrincipalType        = ''
                    RoleName             = $rep.RoleName
                    RoleDefinitionId     = $rep.RoleDefinitionId
                    Scope                = $rep.Scope
                    Source               = $rep.Source
                    ActivityTier         = $null
                    DaysSinceActive      = $null
                    Recommendation       = $recommendation
                    RemediationAction    = 'ConsolidateToGroup'
                    Details              = @{
                        PrincipalCount  = [int]$principalCount
                        PrincipalIds    = $sortedIds
                        PrincipalNames  = $sortedNames
                        ScopeType       = $rep.ScopeType
                        RoleType        = $rep.RoleType
                        AssignmentTypes = $assignmentTypes
                    }
                }

                $findings.Add((New-PAFinding @findingParams))
            }
            catch {
                $ex = $_
                $msg = "Failed to analyze consolidation group '$($entry.Key)': $($ex.Exception.Message)"
                $warnings.Add($msg)
                Write-Warning "Find-PAGroupConsolidation: $msg"
            }
        }

        $stopwatch.Stop()
        $status = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }

        $resultParams = @{
            Collector = 'Find-PAGroupConsolidation'
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
        Write-Warning "Find-PAGroupConsolidation: failed — $($ex.Exception.Message)"

        $resultParams = @{
            Collector = 'Find-PAGroupConsolidation'
            Status    = 'Failed'
            Items     = @()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
}
