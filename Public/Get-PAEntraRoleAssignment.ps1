#Requires -Version 7.0

function Get-PAEntraRoleAssignment {
    <#
    .SYNOPSIS
        Collects Entra ID directory role assignments from a tenant.
    .DESCRIPTION
        Queries Microsoft Graph for all active directory role assignments
        (unifiedRoleAssignment), enriches each with role definition metadata
        and principal display names, normalizes into PA.Assignment objects,
        and wraps the result in a PA.CollectorResult.

        Uses $expand=principal to resolve principal types and display names
        in a single paginated call. Falls back to batch resolution via
        Resolve-PAPrincipal if the expand is not available.

        All returned assignments have Source='EntraRole' and
        AssignmentType='Direct'. PIM eligible assignments are collected
        separately by Get-PAPimEligibility.
    .PARAMETER Session
        PA.Session object from Connect-PASession. Provides auth context
        for Graph API calls.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAEntraRoleAssignment -Session $session
        $result.Items | Format-Table PrincipalDisplayName, RoleName, Scope

        Collects all Entra role assignments and displays them in a table.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAEntraRoleAssignment -Session $session
        $result.Status    # Complete, Partial, or Failed
        $result.ItemCount # number of assignments found

        Checks the collection status and item count.
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Get-PAEntraRoleAssignment/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Session
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        # --- Fetch role definitions (small bounded set) ----------------------

        $roleDefMap = @{}
        try {
            Write-Verbose 'Get-PAEntraRoleAssignment: fetching role definitions'
            $roleDefParams = @{
                Uri    = '/roleManagement/directory/roleDefinitions'
                Select = @('id', 'displayName', 'isBuiltIn')
            }
            $roleDefinitions = Invoke-PAGraphRequest @roleDefParams

            foreach ($rd in $roleDefinitions) {
                $roleDefMap[$rd.id] = @{
                    DisplayName = $rd.displayName
                    IsBuiltIn   = $rd.isBuiltIn
                }
            }
            Write-Verbose "Get-PAEntraRoleAssignment: loaded $($roleDefMap.Count) role definitions"
        }
        catch {
            $ex = $_
            $warnings.Add("Failed to fetch role definitions: $($ex.Exception.Message)")
            Write-Warning 'Get-PAEntraRoleAssignment: role definitions unavailable — role names will be empty'
        }

        # --- Fetch role assignments with $expand=principal -------------------

        Write-Verbose 'Get-PAEntraRoleAssignment: fetching role assignments'
        $assignmentParams = @{
            Uri    = '/roleManagement/directory/roleAssignments'
            Select = @('id', 'principalId', 'roleDefinitionId', 'directoryScopeId')
            Expand = 'principal($select=id,displayName)'
        }
        $rawAssignments = Invoke-PAGraphRequest @assignmentParams

        if (-not $rawAssignments -or @($rawAssignments).Count -eq 0) {
            Write-Verbose 'Get-PAEntraRoleAssignment: no role assignments found'
            $stopwatch.Stop()
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }
                Items     = @()
                Warnings  = $warnings.ToArray()
                Duration  = $stopwatch.Elapsed
            }
            return New-PACollectorResult @resultParams
        }

        $rawAssignments = @($rawAssignments)
        Write-Verbose "Get-PAEntraRoleAssignment: processing $($rawAssignments.Count) raw assignments"

        # --- Check if $expand worked -----------------------------------------

        $expandWorked = $null -ne $rawAssignments[0].principal
        $nameMap = $null
        if (-not $expandWorked) {
            Write-Warning 'Get-PAEntraRoleAssignment: $expand=principal not available; falling back to batch resolution'
            $warnings.Add('$expand=principal not available; principal types will default to User')
            $allPrincipalIds = @(foreach ($ra in $rawAssignments) { $ra.principalId })
            $nameMap = Resolve-PAPrincipal -PrincipalIds $allPrincipalIds -Session $Session
        }

        # --- OData type → PrincipalType mapping ------------------------------

        $odataTypeMap = @{
            '#microsoft.graph.user'             = 'User'
            '#microsoft.graph.group'            = 'Group'
            '#microsoft.graph.servicePrincipal' = 'ServicePrincipal'
        }

        # --- Transform each raw assignment into PA.Assignment ----------------

        $assignments = [System.Collections.Generic.List[object]]::new()

        foreach ($ra in $rawAssignments) {
            # Principal resolution
            if ($expandWorked -and $ra.principal) {
                $odataType = $ra.principal.'@odata.type'
                $principalType = if ($odataTypeMap.ContainsKey($odataType)) {
                    $odataTypeMap[$odataType]
                }
                else {
                    $warnings.Add("Unknown principal type '$odataType' for principal $($ra.principalId)")
                    'User'
                }
                $principalDisplayName = $ra.principal.displayName
                if ([string]::IsNullOrEmpty($principalDisplayName)) {
                    $principalDisplayName = ''
                }
            }
            else {
                $principalType = 'User'
                $principalDisplayName = if ($nameMap) { $nameMap[$ra.principalId] } else { '' }
                if ([string]::IsNullOrEmpty($principalDisplayName)) {
                    $principalDisplayName = ''
                }
            }

            # Role definition enrichment
            $roleDef = $roleDefMap[$ra.roleDefinitionId]
            if ($roleDef) {
                $roleName = $roleDef.DisplayName
                $roleType = if ($roleDef.IsBuiltIn) { 'BuiltIn' } else { 'Custom' }
            }
            else {
                $roleName = ''
                $roleType = ''
                if ($roleDefMap.Count -gt 0) {
                    $warnings.Add("Role definition '$($ra.roleDefinitionId)' not found in definitions cache")
                }
            }

            # Scope mapping
            $scope = $ra.directoryScopeId
            $scopeType = if ($scope -eq '/') {
                'Tenant'
            }
            elseif ($scope -like '/administrativeUnits/*') {
                'AdministrativeUnit'
            }
            else {
                ''
            }

            # Build PA.Assignment
            $paParams = @{
                PrincipalId          = $ra.principalId
                PrincipalDisplayName = $principalDisplayName
                PrincipalType        = $principalType
                RoleDefinitionId     = $ra.roleDefinitionId
                RoleName             = $roleName
                RoleType             = $roleType
                Scope                = $scope
                ScopeType            = $scopeType
                Source               = 'EntraRole'
                AssignmentType       = 'Direct'
            }
            $assignments.Add((New-PAAssignment @paParams))
        }

        # --- Return result ---------------------------------------------------

        $status = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }
        $stopwatch.Stop()
        Write-Verbose "Get-PAEntraRoleAssignment: returning $($assignments.Count) assignments ($status) in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

        $resultParams = @{
            Collector = 'Get-PAEntraRoleAssignment'
            Status    = $status
            Items     = $assignments.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
    catch {
        $ex = $_
        $stopwatch.Stop()
        $errors.Add($ex.Exception.Message)
        Write-Warning "Get-PAEntraRoleAssignment: failed — $($ex.Exception.Message)"

        $resultParams = @{
            Collector = 'Get-PAEntraRoleAssignment'
            Status    = 'Failed'
            Items     = @()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
}
