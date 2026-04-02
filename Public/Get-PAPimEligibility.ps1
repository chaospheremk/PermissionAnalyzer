#Requires -Version 7.0

function Get-PAPimEligibility {
    <#
    .SYNOPSIS
        Collects PIM eligible assignments from Entra ID and Azure RBAC.
    .DESCRIPTION
        Queries two independent sources for PIM eligible assignments:

        1. Entra PIM — Microsoft Graph roleEligibilityScheduleInstances
           for directory role eligibilities. Uses $expand=principal to
           resolve principal types and display names.

        2. Azure PIM — Get-AzRoleEligibilityScheduleInstance for Azure
           RBAC eligibilities across all in-scope subscriptions.

        All returned assignments have AssignmentType='Eligible' and
        Status='Eligible'. Entra assignments use Source='PimEntra',
        Azure assignments use Source='PimAzure'.

        Failure of one source does not prevent collection from the other.
        Both failing produces a Failed result; one failing produces Partial.
    .PARAMETER Session
        PA.Session object from Connect-PASession. Provides auth context
        and SubscriptionIds for Azure PIM iteration.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAPimEligibility -Session $session
        $result.Items | Where-Object Source -eq 'PimEntra'

        Collects all PIM eligible assignments and filters to Entra PIM.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'
        $result = Get-PAPimEligibility -Session $session
        $result.Items | Group-Object Source | Select-Object Name, Count

        Shows the count of eligible assignments by source.
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
    $entraFailed = $false
    $azureFailed = $false

    # =========================================================================
    # Phase 1: Entra PIM
    # =========================================================================

    try {
        # --- Fetch role definitions ------------------------------------------

        $roleDefMap = @{}
        try {
            Write-Verbose 'Get-PAPimEligibility: fetching role definitions'
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
            Write-Verbose "Get-PAPimEligibility: loaded $($roleDefMap.Count) role definitions"
        }
        catch {
            $warnings.Add("Failed to fetch role definitions: $($_.Exception.Message)")
            Write-Warning 'Get-PAPimEligibility: role definitions unavailable — role names will be empty'
        }

        # --- Fetch Entra PIM eligibilities -----------------------------------

        Write-Verbose 'Get-PAPimEligibility: fetching Entra PIM eligibility instances'
        $eligParams = @{
            Uri    = '/roleManagement/directory/roleEligibilityScheduleInstances'
            Select = @('id', 'principalId', 'roleDefinitionId', 'directoryScopeId', 'startDateTime', 'endDateTime', 'memberType')
            Expand = 'principal($select=id,displayName)'
        }
        $rawEligibilities = Invoke-PAGraphRequest @eligParams

        if ($rawEligibilities -and @($rawEligibilities).Count -gt 0) {
            $rawEligibilities = @($rawEligibilities)
            Write-Verbose "Get-PAPimEligibility: processing $($rawEligibilities.Count) Entra PIM eligibilities"

            # Check if $expand worked
            $expandWorked = $null -ne $rawEligibilities[0].principal
            $nameMap = $null
            if (-not $expandWorked) {
                Write-Warning 'Get-PAPimEligibility: $expand=principal not available; falling back to batch resolution'
                $warnings.Add('$expand=principal not available for Entra PIM; principal types will default to User')
                $allPrincipalIds = @($rawEligibilities | ForEach-Object { $_.principalId })
                $nameMap = Resolve-PAPrincipal -PrincipalIds $allPrincipalIds -Session $Session
            }

            $odataTypeMap = @{
                '#microsoft.graph.user'             = 'User'
                '#microsoft.graph.group'            = 'Group'
                '#microsoft.graph.servicePrincipal' = 'ServicePrincipal'
            }

            foreach ($re in $rawEligibilities) {
                # Principal resolution
                if ($expandWorked -and $re.principal) {
                    $odataType = $re.principal.'@odata.type'
                    $principalType = if ($odataTypeMap.ContainsKey($odataType)) {
                        $odataTypeMap[$odataType]
                    }
                    else {
                        $warnings.Add("Unknown principal type '$odataType' for principal $($re.principalId)")
                        'User'
                    }
                    $principalDisplayName = $re.principal.displayName
                    if ([string]::IsNullOrEmpty($principalDisplayName)) {
                        $principalDisplayName = ''
                    }
                }
                else {
                    $principalType = 'User'
                    $principalDisplayName = if ($nameMap) { $nameMap[$re.principalId] } else { '' }
                    if ([string]::IsNullOrEmpty($principalDisplayName)) {
                        $principalDisplayName = ''
                    }
                }

                # Role definition enrichment
                $roleDef = $roleDefMap[$re.roleDefinitionId]
                if ($roleDef) {
                    $roleName = $roleDef.DisplayName
                    $roleType = if ($roleDef.IsBuiltIn) { 'BuiltIn' } else { 'Custom' }
                }
                else {
                    $roleName = ''
                    $roleType = ''
                    if ($roleDefMap.Count -gt 0) {
                        $warnings.Add("Role definition '$($re.roleDefinitionId)' not found in definitions cache")
                    }
                }

                # Scope mapping
                $scope = $re.directoryScopeId
                $scopeType = if ($scope -eq '/') {
                    'Tenant'
                }
                elseif ($scope -like '/administrativeUnits/*') {
                    'AdministrativeUnit'
                }
                else {
                    ''
                }

                # Parse datetimes
                $startDt = if ($re.startDateTime) { [datetime]$re.startDateTime } else { $null }
                $endDt = if ($re.endDateTime) { [datetime]$re.endDateTime } else { $null }

                # Build PA.Assignment
                $paParams = @{
                    PrincipalId          = $re.principalId
                    PrincipalDisplayName = $principalDisplayName
                    PrincipalType        = $principalType
                    RoleDefinitionId     = $re.roleDefinitionId
                    RoleName             = $roleName
                    RoleType             = $roleType
                    Scope                = $scope
                    ScopeType            = $scopeType
                    Source               = 'PimEntra'
                    AssignmentType       = 'Eligible'
                    Status               = 'Eligible'
                    StartDateTime        = $startDt
                    EndDateTime          = $endDt
                }
                $assignments.Add((New-PAAssignment @paParams))
            }
        }
        else {
            Write-Verbose 'Get-PAPimEligibility: no Entra PIM eligibilities found'
        }
    }
    catch {
        $entraFailed = $true
        $errors.Add("Entra PIM failed: $($_.Exception.Message)")
        Write-Warning "Get-PAPimEligibility: Entra PIM collection failed — $($_.Exception.Message)"
    }

    # =========================================================================
    # Phase 2: Azure PIM
    # =========================================================================

    if ($Session.SubscriptionIds.Count -gt 0) {
        $subsFailed = 0
        $seen = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($subId in $Session.SubscriptionIds) {
            try {
                Write-Verbose "Get-PAPimEligibility: fetching Azure PIM eligibilities for subscription $subId"
                $azEligParams = @{
                    Scope       = "/subscriptions/$subId"
                    ErrorAction = 'Stop'
                }
                $azInstances = Get-AzRoleEligibilityScheduleInstance @azEligParams

                if (-not $azInstances) { continue }

                foreach ($inst in $azInstances) {
                    # Extract GUID from ARM role definition path
                    $roleDefGuid = ''
                    if ($inst.RoleDefinitionId -match '/roleDefinitions/([^/]+)$') {
                        $roleDefGuid = $Matches[1]
                    }

                    # Deduplicate by composite key
                    $dedupeKey = "$($inst.PrincipalId)|$roleDefGuid|$($inst.Scope)"
                    if (-not $seen.Add($dedupeKey)) { continue }

                    # PrincipalType mapping
                    $principalType = switch ($inst.PrincipalType) {
                        'User' { 'User' }
                        'Group' { 'Group' }
                        'ServicePrincipal' { 'ServicePrincipal' }
                        'ForeignGroup' {
                            $warnings.Add("ForeignGroup principal '$($inst.PrincipalId)' mapped to Group")
                            'Group'
                        }
                        default {
                            $warnings.Add("Unknown Azure PIM principal type '$($inst.PrincipalType)' for principal $($inst.PrincipalId)")
                            'User'
                        }
                    }

                    # RoleType from RoleDefinitionType
                    $roleType = if ($inst.RoleDefinitionType -like '*BuiltIn*') {
                        'BuiltIn'
                    }
                    elseif ($inst.RoleDefinitionType) {
                        'Custom'
                    }
                    else {
                        ''
                    }

                    # ScopeType from ARM cmdlet
                    $scopeType = switch -Regex ($inst.ScopeType) {
                        '(?i)^subscription$'    { 'Subscription' }
                        '(?i)^resourcegroup$'   { 'ResourceGroup' }
                        '(?i)^managementgroup$' { 'ManagementGroup' }
                        default                 { 'Resource' }
                    }

                    # Build PA.Assignment
                    $paParams = @{
                        PrincipalId          = $inst.PrincipalId
                        PrincipalDisplayName = if ($inst.PrincipalDisplayName) { $inst.PrincipalDisplayName } else { '' }
                        PrincipalType        = $principalType
                        RoleDefinitionId     = $roleDefGuid
                        RoleName             = if ($inst.RoleDefinitionDisplayName) { $inst.RoleDefinitionDisplayName } else { '' }
                        RoleType             = $roleType
                        Scope                = $inst.Scope
                        ScopeType            = $scopeType
                        Source               = 'PimAzure'
                        AssignmentType       = 'Eligible'
                        Status               = 'Eligible'
                        StartDateTime        = $inst.StartDateTime
                        EndDateTime          = $inst.EndDateTime
                    }
                    $assignments.Add((New-PAAssignment @paParams))
                }
            }
            catch {
                $subsFailed++
                $warnings.Add("Azure PIM failed for subscription $subId`: $($_.Exception.Message)")
                Write-Warning "Get-PAPimEligibility: Azure PIM failed for subscription $subId — $($_.Exception.Message)"
            }
        }

        $azureFailed = $subsFailed -eq $Session.SubscriptionIds.Count -and $subsFailed -gt 0
    }
    else {
        Write-Verbose 'Get-PAPimEligibility: no subscriptions in scope — skipping Azure PIM'
    }

    # =========================================================================
    # Phase 3: Result assembly
    # =========================================================================

    $stopwatch.Stop()

    $status = if ($entraFailed -and ($azureFailed -or $Session.SubscriptionIds.Count -eq 0)) {
        'Failed'
    }
    elseif ($entraFailed -or $azureFailed -or $warnings.Count -gt 0) {
        'Partial'
    }
    else {
        'Complete'
    }

    Write-Verbose "Get-PAPimEligibility: returning $($assignments.Count) eligibilities ($status) in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

    $resultParams = @{
        Collector = 'Get-PAPimEligibility'
        Status    = $status
        Items     = $assignments.ToArray()
        Errors    = $errors.ToArray()
        Warnings  = $warnings.ToArray()
        Duration  = $stopwatch.Elapsed
    }
    return New-PACollectorResult @resultParams
}
