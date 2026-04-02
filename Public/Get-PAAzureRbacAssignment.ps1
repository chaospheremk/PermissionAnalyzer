#Requires -Version 7.0

function Get-PAAzureRbacAssignment {
    <#
    .SYNOPSIS
        Collects Azure RBAC role assignments across in-scope subscriptions.
    .DESCRIPTION
        Queries Azure RBAC for all role assignments across the subscriptions
        specified in the PA.Session object. Enriches each assignment with
        BuiltIn/Custom classification from role definitions, maps scope
        types, normalizes into PA.Assignment objects, and wraps the result
        in a PA.CollectorResult.

        Iterates per subscription with independent error handling so that
        a failure on one subscription does not prevent collection from
        others. Deduplicates inherited management group assignments that
        appear under multiple subscriptions.

        All returned assignments have Source='AzureRbac',
        AssignmentType='Direct', and Status='Active'.
    .PARAMETER Session
        PA.Session object from Connect-PASession. Provides SubscriptionIds
        for RBAC iteration.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAAzureRbacAssignment -Session $session
        $result.Items | Format-Table PrincipalDisplayName, RoleName, Scope

        Collects all Azure RBAC assignments and displays them in a table.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAAzureRbacAssignment -Session $session
        $result.Items | Group-Object ScopeType | Select-Object Name, Count

        Shows the count of assignments by scope type.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Session
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $assignments = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $roleDefCustomMap = @{}

    if ($Session.SubscriptionIds.Count -eq 0) {
        Write-Warning 'Get-PAAzureRbacAssignment: no subscriptions in scope — nothing to collect'
        $warnings.Add('No subscriptions in scope')
        $stopwatch.Stop()
        $resultParams = @{
            Collector = 'Get-PAAzureRbacAssignment'
            Status    = 'Complete'
            Items     = @()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }

    $subsFailed = 0

    foreach ($subId in $Session.SubscriptionIds) {
        try {
            Write-Verbose "Get-PAAzureRbacAssignment: processing subscription $subId"
            $subScope = "/subscriptions/$subId"

            # --- Fetch role definitions for BuiltIn/Custom -------------------

            try {
                Write-Verbose "Get-PAAzureRbacAssignment: fetching role definitions for $subId"
                $roleDefParams = @{
                    Scope       = $subScope
                    ErrorAction = 'Stop'
                }
                $roleDefs = Get-AzRoleDefinition @roleDefParams

                foreach ($rd in $roleDefs) {
                    if (-not $roleDefCustomMap.ContainsKey($rd.Id)) {
                        $roleDefCustomMap[$rd.Id] = $rd.IsCustom
                    }
                }
            }
            catch {
                $warnings.Add("Failed to fetch role definitions for subscription $subId`: $($_.Exception.Message)")
                Write-Warning "Get-PAAzureRbacAssignment: role definitions unavailable for $subId — RoleType will be empty"
            }

            # --- Fetch role assignments --------------------------------------

            Write-Verbose "Get-PAAzureRbacAssignment: fetching role assignments for $subId"
            $assignmentParams = @{
                Scope       = $subScope
                ErrorAction = 'Stop'
            }
            $rawAssignments = Get-AzRoleAssignment @assignmentParams

            if (-not $rawAssignments) { continue }

            foreach ($ra in $rawAssignments) {
                # Deduplicate by composite key
                $dedupeKey = "$($ra.ObjectId)|$($ra.RoleDefinitionId)|$($ra.Scope)"
                if (-not $seen.Add($dedupeKey)) { continue }

                # ObjectType mapping
                $principalType = switch ($ra.ObjectType) {
                    'User' { 'User' }
                    'Group' { 'Group' }
                    'ServicePrincipal' { 'ServicePrincipal' }
                    'Unknown' {
                        $warnings.Add("Unknown ObjectType for principal '$($ra.ObjectId)' — likely deleted")
                        'User'
                    }
                    default {
                        $warnings.Add("Unexpected ObjectType '$($ra.ObjectType)' for principal '$($ra.ObjectId)'")
                        'User'
                    }
                }

                # RoleType from definition cache
                $roleType = if ($roleDefCustomMap.ContainsKey($ra.RoleDefinitionId)) {
                    if ($roleDefCustomMap[$ra.RoleDefinitionId]) { 'Custom' } else { 'BuiltIn' }
                }
                else {
                    ''
                }

                # ScopeType classification
                $scopeType = if ($ra.Scope -match '^/providers/Microsoft\.Management/managementGroups/') {
                    'ManagementGroup'
                }
                elseif ($ra.Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+/.+') {
                    'Resource'
                }
                elseif ($ra.Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') {
                    'ResourceGroup'
                }
                elseif ($ra.Scope -match '^/subscriptions/[^/]+$') {
                    'Subscription'
                }
                else {
                    ''
                }

                # Build PA.Assignment
                $paParams = @{
                    PrincipalId          = $ra.ObjectId
                    PrincipalDisplayName = if ($ra.DisplayName) { $ra.DisplayName } else { '' }
                    PrincipalType        = $principalType
                    RoleDefinitionId     = $ra.RoleDefinitionId
                    RoleName             = if ($ra.RoleDefinitionName) { $ra.RoleDefinitionName } else { '' }
                    RoleType             = $roleType
                    Scope                = $ra.Scope
                    ScopeType            = $scopeType
                    Source               = 'AzureRbac'
                    AssignmentType       = 'Direct'
                }
                $assignments.Add((New-PAAssignment @paParams))
            }
        }
        catch {
            $subsFailed++
            $errors.Add("Subscription $subId`: $($_.Exception.Message)")
            Write-Warning "Get-PAAzureRbacAssignment: failed for subscription $subId — $($_.Exception.Message)"
        }
    }

    # --- Result assembly -----------------------------------------------------

    $stopwatch.Stop()

    $status = if ($subsFailed -eq $Session.SubscriptionIds.Count) {
        'Failed'
    }
    elseif ($subsFailed -gt 0 -or $warnings.Count -gt 0) {
        'Partial'
    }
    else {
        'Complete'
    }

    Write-Verbose "Get-PAAzureRbacAssignment: returning $($assignments.Count) assignments ($status) in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

    $resultParams = @{
        Collector = 'Get-PAAzureRbacAssignment'
        Status    = $status
        Items     = $assignments.ToArray()
        Errors    = $errors.ToArray()
        Warnings  = $warnings.ToArray()
        Duration  = $stopwatch.Elapsed
    }
    return New-PACollectorResult @resultParams
}
