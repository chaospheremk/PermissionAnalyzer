#Requires -Version 7.0

function Resolve-PARoleAction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'Session',
        Justification = 'Reserved for future environment-specific endpoint selection')]
    <#
    .SYNOPSIS
        Resolves role definition IDs to their granted action strings.
    .DESCRIPTION
        Maps each unique RoleDefinitionId found in the supplied assignments to
        an array of allowed action strings. Used by Get-PAActivitySignal to
        populate GrantedActions on PA.ActivityProfile objects for Tier 3
        gap analysis.

        Two resolution paths:
        - Entra (Source in EntraRole, PimEntra): queries Graph API for
          roleManagement/directory/roleDefinitions and extracts
          rolePermissions[0].allowedResourceActions.
        - Azure RBAC (Source in AzureRbac, PimAzure): calls
          Get-AzRoleDefinition per unique subscription scope and extracts
          Actions + DataActions. Wildcard-provider actions (starting with *)
          are filtered out because they cannot produce meaningful namespace
          comparisons.

        AppPermission source assignments are skipped (app roles don't map to
        allowedResourceActions).

        Entra and Azure resolution are independently error-isolated so a
        failure on one path does not prevent the other from returning results.
    .PARAMETER Assignments
        Array of PA.Assignment objects. Used to extract unique
        RoleDefinitionIds grouped by source type.
    .PARAMETER Session
        PA.Session object from Connect-PASession. Provides context for
        Graph API and Azure resource calls.
    .EXAMPLE
        $roleActionMap = Resolve-PARoleAction -Assignments $allAssignments -Session $session
        $roleActionMap['<role-definition-id>']
        # Returns: @('microsoft.directory/users/basic/update', ...)
    .INPUTS
        None.
    .OUTPUTS
        System.Collections.Hashtable
        Keys are RoleDefinitionId strings; values are string arrays of
        allowed actions.
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Assignments,

        [Parameter(Mandatory)]
        [PSCustomObject]$Session
    )

    $roleActionMap = @{}

    if ($Assignments.Count -eq 0) {
        $roleActionMap
        return
    }

    # --- Classify assignments by source type ---------------------------------

    $entraRoleDefIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    # Azure RBAC: track unique (RoleDefinitionId, SubscriptionId) pairs
    $azureRoleDefIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $azureSubscriptionScopes = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($assignment in $Assignments) {
        switch ($assignment.Source) {
            { $_ -in 'EntraRole', 'PimEntra' } {
                [void]$entraRoleDefIds.Add($assignment.RoleDefinitionId)
            }
            { $_ -in 'AzureRbac', 'PimAzure' } {
                [void]$azureRoleDefIds.Add($assignment.RoleDefinitionId)
                # Extract subscription scope from assignment Scope
                if ($assignment.Scope -match '^(/subscriptions/[^/]+)') {
                    [void]$azureSubscriptionScopes.Add($Matches[1])
                }
            }
            # AppPermission — skip
        }
    }

    # --- Entra role definition resolution ------------------------------------

    if ($entraRoleDefIds.Count -gt 0) {
        try {
            Write-Verbose "Resolve-PARoleAction: resolving $($entraRoleDefIds.Count) Entra role definition(s)"
            $graphParams = @{
                Uri    = '/roleManagement/directory/roleDefinitions'
                Select = @('id', 'rolePermissions')
            }
            $entraRoleDefs = Invoke-PAGraphRequest @graphParams

            foreach ($rd in @($entraRoleDefs)) {
                if (-not $entraRoleDefIds.Contains($rd.id)) {
                    continue
                }

                $actions = @()
                if ($rd.rolePermissions -and $rd.rolePermissions.Count -gt 0) {
                    $perms = $rd.rolePermissions[0]
                    if ($perms.allowedResourceActions) {
                        $actions = @($perms.allowedResourceActions)
                    }
                }

                $roleActionMap[$rd.id] = $actions
            }

            Write-Verbose "Resolve-PARoleAction: resolved $($roleActionMap.Count) Entra role definition(s)"
        }
        catch {
            $ex = $_
            Write-Warning "Resolve-PARoleAction: Entra role definition resolution failed — $($ex.Exception.Message)"
        }
    }

    # --- Azure RBAC role definition resolution --------------------------------

    if ($azureRoleDefIds.Count -gt 0 -and $azureSubscriptionScopes.Count -gt 0) {
        try {
            Write-Verbose "Resolve-PARoleAction: resolving $($azureRoleDefIds.Count) Azure RBAC role definition(s) across $($azureSubscriptionScopes.Count) subscription(s)"

            # Build a combined map from all subscription-scoped queries
            $azureRoleDefMap = @{}

            foreach ($subScope in $azureSubscriptionScopes) {
                try {
                    $roleDefParams = @{
                        Scope       = $subScope
                        ErrorAction = 'Stop'
                    }
                    $roleDefs = Get-AzRoleDefinition @roleDefParams

                    foreach ($rd in @($roleDefs)) {
                        if ($null -eq $rd -or -not $azureRoleDefIds.Contains($rd.Id)) {
                            continue
                        }
                        if ($azureRoleDefMap.ContainsKey($rd.Id)) {
                            continue
                        }

                        # Combine Actions + DataActions, filter wildcard-provider entries
                        $allActions = [System.Collections.Generic.List[string]]::new()
                        if ($rd.Actions) {
                            foreach ($action in $rd.Actions) {
                                if (-not $action.StartsWith('*')) {
                                    $allActions.Add($action)
                                }
                            }
                        }
                        if ($rd.DataActions) {
                            foreach ($action in $rd.DataActions) {
                                if (-not $action.StartsWith('*')) {
                                    $allActions.Add($action)
                                }
                            }
                        }

                        $azureRoleDefMap[$rd.Id] = $allActions.ToArray()
                    }
                }
                catch {
                    $ex = $_
                    Write-Warning "Resolve-PARoleAction: Azure role definitions failed for scope '$subScope' — $($ex.Exception.Message)"
                }
            }

            # Merge Azure results into the main map
            foreach ($key in $azureRoleDefMap.Keys) {
                $roleActionMap[$key] = $azureRoleDefMap[$key]
            }

            Write-Verbose "Resolve-PARoleAction: resolved $($azureRoleDefMap.Count) Azure RBAC role definition(s)"
        }
        catch {
            $ex = $_
            Write-Warning "Resolve-PARoleAction: Azure RBAC role definition resolution failed — $($ex.Exception.Message)"
        }
    }

    $roleActionMap
}
