#Requires -Version 7.0

function Get-PAAppPermission {
    <#
    .SYNOPSIS
        Collects application permissions and delegated permission grants from a tenant.
    .DESCRIPTION
        Queries Microsoft Graph for all application permissions (appRoleAssignments)
        and delegated permission grants (oauth2PermissionGrants). Resolves permission
        names from resource service principal appRoles collections, normalizes into
        PA.Assignment objects, and wraps the result in a PA.CollectorResult.

        appRoleAssignments require per-service-principal iteration (no tenant-wide
        endpoint). oauth2PermissionGrants use a single tenant-wide call.

        All returned assignments have Source='AppPermission'. AppRole assignments
        use AssignmentType='AppRole', delegated grants use
        AssignmentType='DelegatedGrant'.
    .PARAMETER Session
        PA.Session object from Connect-PASession. Provides auth context
        for Graph API calls.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAAppPermission -Session $session
        $result.Items.Where({ $_.AssignmentType -eq 'AppRole' })

        Collects all app permissions and filters to application role assignments.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAAppPermission -Session $session
        $result.Items | Group-Object AssignmentType | Select-Object Name, Count

        Shows the count of permissions by assignment type.
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Get-PAAppPermission/
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'Session',
        Justification = 'Session provides auth context implicitly via connected Graph session')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Session
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $assignments = [System.Collections.Generic.List[object]]::new()

    try {
        # =================================================================
        # Phase 1: Build caches from service principal listing
        # =================================================================

        Write-Verbose 'Get-PAAppPermission: fetching all service principals'
        $spParams = @{
            Uri    = '/servicePrincipals'
            Select = @('id', 'displayName', 'appId', 'appRoles')
        }
        $allServicePrincipals = Invoke-PAGraphRequest @spParams

        $spDisplayNameMap = @{}
        $appRoleValueMap = @{}

        if ($allServicePrincipals) {
            $allServicePrincipals = @($allServicePrincipals)

            foreach ($sp in $allServicePrincipals) {
                $spDisplayNameMap[$sp.id] = if ($sp.displayName) { $sp.displayName } else { '' }

                if ($sp.appRoles -and @($sp.appRoles).Count -gt 0) {
                    $roleMap = @{}
                    foreach ($role in $sp.appRoles) {
                        $roleMap[$role.id] = $role.value
                    }
                    $appRoleValueMap[$sp.id] = $roleMap
                }
            }
        }
        else {
            $allServicePrincipals = @()
        }

        Write-Verbose "Get-PAAppPermission: cached $($spDisplayNameMap.Count) service principals, $($appRoleValueMap.Count) with appRoles"

        # =================================================================
        # Phase 2: Collect appRoleAssignments (iterate SPs)
        # =================================================================

        $appRoleFailed = $false
        $spsFailed = 0
        $spTotal = $allServicePrincipals.Count
        $emptyGuid = '00000000-0000-0000-0000-000000000000'

        try {
            for ($i = 0; $i -lt $spTotal; $i++) {
                $sp = $allServicePrincipals[$i]

                if (($i + 1) % 100 -eq 0) {
                    Write-Verbose "Get-PAAppPermission: appRoleAssignments progress $($i + 1)/$spTotal"
                }

                try {
                    $araParams = @{
                        Uri = "/servicePrincipals/$($sp.id)/appRoleAssignments"
                    }
                    $appRoleAssignments = Invoke-PAGraphRequest @araParams

                    if (-not $appRoleAssignments -or @($appRoleAssignments).Count -eq 0) { continue }

                    foreach ($ara in @($appRoleAssignments)) {
                        # Resolve permission name
                        $permissionName = 'Default Access'

                        if ($ara.appRoleId -ne $emptyGuid) {
                            $permissionName = ''
                            if ($appRoleValueMap.ContainsKey($ara.resourceId)) {
                                $resourceRoles = $appRoleValueMap[$ara.resourceId]
                                if ($resourceRoles.ContainsKey($ara.appRoleId)) {
                                    $permissionName = $resourceRoles[$ara.appRoleId]
                                }
                            }
                            if ([string]::IsNullOrEmpty($permissionName)) {
                                $permissionName = $ara.appRoleId
                                $warnings.Add("Could not resolve appRoleId '$($ara.appRoleId)' for resource '$($ara.resourceId)'")
                            }
                        }

                        # PrincipalType mapping
                        $principalType = switch ($ara.principalType) {
                            'User' { 'User' }
                            'Group' { 'Group' }
                            'ServicePrincipal' { 'ServicePrincipal' }
                            default {
                                $warnings.Add("Unknown principalType '$($ara.principalType)' for principal $($ara.principalId)")
                                'ServicePrincipal'
                            }
                        }

                        # Parse CreatedDateTime
                        $createdDt = if ($ara.createdDateTime) { [datetime]$ara.createdDateTime } else { $null }

                        # Build PA.Assignment
                        $paParams = @{
                            PrincipalId          = $ara.principalId
                            PrincipalDisplayName = if ($ara.principalDisplayName) { $ara.principalDisplayName } else { '' }
                            PrincipalType        = $principalType
                            RoleDefinitionId     = $ara.appRoleId
                            RoleName             = $permissionName
                            RoleType             = 'AppRole'
                            Scope                = if ($ara.resourceDisplayName) { $ara.resourceDisplayName } else { '' }
                            ScopeType            = 'Application'
                            Source               = 'AppPermission'
                            AssignmentType       = 'AppRole'
                            ResourceDisplayName  = if ($ara.resourceDisplayName) { $ara.resourceDisplayName } else { '' }
                            CreatedDateTime      = $createdDt
                        }
                        $assignments.Add((New-PAAssignment @paParams))
                    }
                }
                catch {
                    $ex = $_
                    $spsFailed++
                    $warnings.Add("appRoleAssignments failed for SP '$($sp.id)': $($ex.Exception.Message)")
                    Write-Warning "Get-PAAppPermission: appRoleAssignments failed for SP $($sp.id) — $($ex.Exception.Message)"
                }
            }

            if ($spsFailed -gt 0) {
                Write-Verbose "Get-PAAppPermission: appRoleAssignment iteration: $spsFailed of $spTotal SPs failed"
            }
        }
        catch {
            $ex = $_
            $appRoleFailed = $true
            $errors.Add("appRoleAssignment iteration failed: $($ex.Exception.Message)")
            Write-Warning "Get-PAAppPermission: appRoleAssignment iteration aborted — $($ex.Exception.Message)"
        }

        # =================================================================
        # Phase 3: Collect oauth2PermissionGrants (single call)
        # =================================================================

        $delegatedFailed = $false

        try {
            Write-Verbose 'Get-PAAppPermission: fetching oauth2PermissionGrants'
            $grantParams = @{
                Uri = '/oauth2PermissionGrants'
            }
            $grants = Invoke-PAGraphRequest @grantParams

            if ($grants -and @($grants).Count -gt 0) {
                $grants = @($grants)
                Write-Verbose "Get-PAAppPermission: processing $($grants.Count) oauth2PermissionGrants"

                foreach ($grant in $grants) {
                    # Resolve display names from cache
                    $clientDisplayName = if ($spDisplayNameMap.ContainsKey($grant.clientId)) {
                        $spDisplayNameMap[$grant.clientId]
                    }
                    else { '' }

                    $resourceDisplayName = if ($spDisplayNameMap.ContainsKey($grant.resourceId)) {
                        $spDisplayNameMap[$grant.resourceId]
                    }
                    else { '' }

                    # Scope string
                    $scopeString = if ($grant.scope) { $grant.scope.Trim() } else { '' }

                    # ConsentType mapping
                    $consentType = switch ($grant.consentType) {
                        'AllPrincipals' { 'AllPrincipals' }
                        'Principal' { 'Principal' }
                        default { '' }
                    }

                    # Build PA.Assignment
                    $paParams = @{
                        PrincipalId          = $grant.clientId
                        PrincipalDisplayName = $clientDisplayName
                        PrincipalType        = 'ServicePrincipal'
                        RoleDefinitionId     = $grant.id
                        RoleName             = $scopeString
                        RoleType             = 'DelegatedGrant'
                        Scope                = $resourceDisplayName
                        ScopeType            = 'Application'
                        Source               = 'AppPermission'
                        AssignmentType       = 'DelegatedGrant'
                        ResourceDisplayName  = $resourceDisplayName
                        ConsentType          = $consentType
                    }
                    $assignments.Add((New-PAAssignment @paParams))
                }
            }
            else {
                Write-Verbose 'Get-PAAppPermission: no oauth2PermissionGrants found'
            }
        }
        catch {
            $ex = $_
            $delegatedFailed = $true
            $errors.Add("oauth2PermissionGrants failed: $($ex.Exception.Message)")
            Write-Warning "Get-PAAppPermission: oauth2PermissionGrants collection failed — $($ex.Exception.Message)"
        }

        # =================================================================
        # Phase 4: Result assembly
        # =================================================================

        $stopwatch.Stop()

        $status = if ($appRoleFailed -and $delegatedFailed) {
            'Failed'
        }
        elseif ($appRoleFailed -or $delegatedFailed -or $spsFailed -gt 0 -or $warnings.Count -gt 0) {
            'Partial'
        }
        else {
            'Complete'
        }

        Write-Verbose "Get-PAAppPermission: returning $($assignments.Count) assignments ($status) in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

        $resultParams = @{
            Collector = 'Get-PAAppPermission'
            Status    = $status
            Items     = $assignments.ToArray()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
    catch {
        # SP listing failed — nothing else can proceed
        $ex = $_
        $stopwatch.Stop()
        $errors.Add($ex.Exception.Message)
        Write-Warning "Get-PAAppPermission: failed — $($ex.Exception.Message)"

        $resultParams = @{
            Collector = 'Get-PAAppPermission'
            Status    = 'Failed'
            Items     = @()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
}
