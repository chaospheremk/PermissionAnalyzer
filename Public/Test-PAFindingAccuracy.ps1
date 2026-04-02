#Requires -Version 7.0

function Test-PAFindingAccuracy {
    <#
    .SYNOPSIS
        Re-validates findings against current tenant state.
    .DESCRIPTION
        Takes an array of PA.Finding objects and checks whether each finding's
        underlying assignment still exists by querying live data. Groups findings
        by Source, pre-fetches current assignments in batch, then validates each
        finding against the fetched data. Returns a PA.CollectorResult wrapping
        PA.ValidationResult items.
    .PARAMETER Findings
        Array of PA.Finding objects to re-validate.
    .PARAMETER Session
        PA.Session object from Connect-PASession providing auth context.
    .EXAMPLE
        $validation = Test-PAFindingAccuracy -Findings $findings -Session $session
    .EXAMPLE
        $validationParams = @{
            Findings = $allFindings
            Session  = $session
        }
        $validation = Test-PAFindingAccuracy @validationParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult) wrapping PA.ValidationResult items.
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Test-PAFindingAccuracy/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [PSCustomObject]$Session
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    # Early return for empty findings
    if ($Findings.Count -eq 0) {
        $stopwatch.Stop()
        $resultParams = @{
            Collector = 'Test-PAFindingAccuracy'
            Status    = 'Complete'
            Items     = @()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }

    try {
        $validationResults = [System.Collections.Generic.List[object]]::new()

        # Determine which sources need pre-fetching
        $sourcesNeeded = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($finding in $Findings) {
            [void]$sourcesNeeded.Add($finding.Source)
        }

        # --- Pre-fetch live data per source ---

        $entraLookup = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $entraFetchFailed = $false
        $entraFetchError = ''

        if ($sourcesNeeded.Contains('EntraRole')) {
            try {
                Write-Verbose 'Test-PAFindingAccuracy: fetching Entra role assignments'
                $graphParams = @{
                    Uri    = '/roleManagement/directory/roleAssignments'
                    Select = @('principalId', 'roleDefinitionId')
                }
                $entraAssignments = Invoke-PAGraphRequest @graphParams
                foreach ($ra in $entraAssignments) {
                    [void]$entraLookup.Add("$($ra.principalId)|$($ra.roleDefinitionId)")
                }
                Write-Verbose "Test-PAFindingAccuracy: $($entraLookup.Count) Entra role assignments loaded"
            }
            catch {
                $ex = $_
                $entraFetchFailed = $true
                $entraFetchError = $ex.Exception.Message
                $errors.Add("Entra role assignment fetch failed: $entraFetchError")
                Write-Warning "Test-PAFindingAccuracy: Entra role assignment fetch failed — $entraFetchError"
            }
        }

        $pimEntraLookup = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $pimEntraFetchFailed = $false
        $pimEntraFetchError = ''

        if ($sourcesNeeded.Contains('PimEntra')) {
            try {
                Write-Verbose 'Test-PAFindingAccuracy: fetching PIM Entra eligibility instances'
                $graphParams = @{
                    Uri    = '/roleManagement/directory/roleEligibilityScheduleInstances'
                    Select = @('principalId', 'roleDefinitionId')
                }
                $pimInstances = Invoke-PAGraphRequest @graphParams
                foreach ($inst in $pimInstances) {
                    [void]$pimEntraLookup.Add("$($inst.principalId)|$($inst.roleDefinitionId)")
                }
                Write-Verbose "Test-PAFindingAccuracy: $($pimEntraLookup.Count) PIM Entra eligibilities loaded"
            }
            catch {
                $ex = $_
                $pimEntraFetchFailed = $true
                $pimEntraFetchError = $ex.Exception.Message
                $errors.Add("PIM Entra eligibility fetch failed: $pimEntraFetchError")
                Write-Warning "Test-PAFindingAccuracy: PIM Entra eligibility fetch failed — $pimEntraFetchError"
            }
        }

        $azRbacLookup = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $azRbacFetchFailed = $false
        $azRbacFetchError = ''

        if ($sourcesNeeded.Contains('AzureRbac')) {
            try {
                Write-Verbose 'Test-PAFindingAccuracy: fetching Azure RBAC assignments'
                foreach ($subId in $Session.SubscriptionIds) {
                    $rbacParams = @{
                        Scope       = "/subscriptions/$subId"
                        ErrorAction = 'Stop'
                    }
                    $azAssignments = Get-AzRoleAssignment @rbacParams
                    foreach ($ra in $azAssignments) {
                        [void]$azRbacLookup.Add("$($ra.ObjectId)|$($ra.RoleDefinitionName)|$($ra.Scope)")
                    }
                }
                Write-Verbose "Test-PAFindingAccuracy: $($azRbacLookup.Count) Azure RBAC assignments loaded"
            }
            catch {
                $ex = $_
                $azRbacFetchFailed = $true
                $azRbacFetchError = $ex.Exception.Message
                $errors.Add("Azure RBAC assignment fetch failed: $azRbacFetchError")
                Write-Warning "Test-PAFindingAccuracy: Azure RBAC assignment fetch failed — $azRbacFetchError"
            }
        }

        $pimAzureLookup = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $pimAzureFetchFailed = $false
        $pimAzureFetchError = ''

        if ($sourcesNeeded.Contains('PimAzure')) {
            try {
                Write-Verbose 'Test-PAFindingAccuracy: fetching Azure PIM eligibilities'
                foreach ($subId in $Session.SubscriptionIds) {
                    $pimParams = @{
                        Scope       = "/subscriptions/$subId"
                        ErrorAction = 'Stop'
                    }
                    $pimAzInstances = Get-AzRoleEligibilityScheduleInstance @pimParams
                    foreach ($inst in $pimAzInstances) {
                        [void]$pimAzureLookup.Add("$($inst.PrincipalId)|$($inst.RoleDefinitionId)|$($inst.Scope)")
                    }
                }
                Write-Verbose "Test-PAFindingAccuracy: $($pimAzureLookup.Count) Azure PIM eligibilities loaded"
            }
            catch {
                $ex = $_
                $pimAzureFetchFailed = $true
                $pimAzureFetchError = $ex.Exception.Message
                $errors.Add("Azure PIM eligibility fetch failed: $pimAzureFetchError")
                Write-Warning "Test-PAFindingAccuracy: Azure PIM eligibility fetch failed — $pimAzureFetchError"
            }
        }

        $appPermLookup = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $appPermFetchFailed = $false
        $appPermFetchError = ''

        if ($sourcesNeeded.Contains('AppPermission')) {
            try {
                Write-Verbose 'Test-PAFindingAccuracy: fetching app role assignments'
                $uniqueSpIds = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($f in $Findings) {
                    if ($f.Source -eq 'AppPermission') {
                        [void]$uniqueSpIds.Add($f.PrincipalId)
                    }
                }
                foreach ($spId in $uniqueSpIds) {
                    $araParams = @{
                        Uri = "/servicePrincipals/$spId/appRoleAssignments"
                    }
                    $appRoleAssignments = Invoke-PAGraphRequest @araParams
                    foreach ($ara in $appRoleAssignments) {
                        [void]$appPermLookup.Add("$($ara.principalId)|$($ara.appRoleId)")
                    }
                }
                Write-Verbose "Test-PAFindingAccuracy: $($appPermLookup.Count) app role assignments loaded"
            }
            catch {
                $ex = $_
                $appPermFetchFailed = $true
                $appPermFetchError = $ex.Exception.Message
                $errors.Add("App permission fetch failed: $appPermFetchError")
                Write-Warning "Test-PAFindingAccuracy: app permission fetch failed — $appPermFetchError"
            }
        }

        # --- Validate each finding ---

        foreach ($finding in $Findings) {
            try {
                $source = $finding.Source

                # Check if pre-fetch failed for this source
                $fetchFailed = switch ($source) {
                    'EntraRole'     { $entraFetchFailed }
                    'PimEntra'      { $pimEntraFetchFailed }
                    'AzureRbac'     { $azRbacFetchFailed }
                    'PimAzure'      { $pimAzureFetchFailed }
                    'AppPermission' { $appPermFetchFailed }
                    default         { $true }
                }

                if ($fetchFailed) {
                    $fetchError = switch ($source) {
                        'EntraRole'     { $entraFetchError }
                        'PimEntra'      { $pimEntraFetchError }
                        'AzureRbac'     { $azRbacFetchError }
                        'PimAzure'      { $pimAzureFetchError }
                        'AppPermission' { $appPermFetchError }
                        default         { "Unknown source '$source'" }
                    }
                    $vrParams = @{
                        FindingId        = $finding.FindingId
                        OriginalCategory = $finding.Category
                        OriginalSeverity = $finding.Severity
                        IsStillValid     = $false
                        CurrentState     = 'Validation error'
                        Notes            = "Pre-fetch failed: $fetchError"
                    }
                    $validationResults.Add((New-PAValidationResult @vrParams))
                    continue
                }

                # Build lookup key and check
                $lookupKey = switch ($source) {
                    'EntraRole'     { "$($finding.PrincipalId)|$($finding.RoleDefinitionId)" }
                    'PimEntra'      { "$($finding.PrincipalId)|$($finding.RoleDefinitionId)" }
                    'AzureRbac'     { "$($finding.PrincipalId)|$($finding.RoleName)|$($finding.Scope)" }
                    'PimAzure'      { "$($finding.PrincipalId)|$($finding.RoleDefinitionId)|$($finding.Scope)" }
                    'AppPermission' { "$($finding.PrincipalId)|$($finding.RoleDefinitionId)" }
                }

                $exists = switch ($source) {
                    'EntraRole'     { $entraLookup.Contains($lookupKey) }
                    'PimEntra'      { $pimEntraLookup.Contains($lookupKey) }
                    'AzureRbac'     { $azRbacLookup.Contains($lookupKey) }
                    'PimAzure'      { $pimAzureLookup.Contains($lookupKey) }
                    'AppPermission' { $appPermLookup.Contains($lookupKey) }
                }

                $vrParams = @{
                    FindingId        = $finding.FindingId
                    OriginalCategory = $finding.Category
                    OriginalSeverity = $finding.Severity
                    IsStillValid     = $exists
                    CurrentState     = if ($exists) { 'Assignment still exists' } else { 'Assignment no longer exists' }
                }
                $validationResults.Add((New-PAValidationResult @vrParams))
            }
            catch {
                $ex = $_
                $msg = "Validation failed for FindingId '$($finding.FindingId)': $($ex.Exception.Message)"
                $warnings.Add($msg)
                Write-Warning "Test-PAFindingAccuracy: $msg"

                $vrParams = @{
                    FindingId        = $finding.FindingId
                    OriginalCategory = $finding.Category
                    OriginalSeverity = $finding.Severity
                    IsStillValid     = $false
                    CurrentState     = 'Validation error'
                    Notes            = $ex.Exception.Message
                }
                $validationResults.Add((New-PAValidationResult @vrParams))
            }
        }

        # --- Result assembly ---

        $stopwatch.Stop()
        $status = if ($errors.Count -gt 0 -and $validationResults.Count -eq 0) {
            'Failed'
        }
        elseif ($errors.Count -gt 0 -or $warnings.Count -gt 0) {
            'Partial'
        }
        else {
            'Complete'
        }

        $resultParams = @{
            Collector = 'Test-PAFindingAccuracy'
            Status    = $status
            Items     = $validationResults.ToArray()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
    catch {
        $ex = $_
        $stopwatch.Stop()
        $errors.Add($ex.Exception.Message)
        Write-Warning "Test-PAFindingAccuracy: failed — $($ex.Exception.Message)"

        $resultParams = @{
            Collector = 'Test-PAFindingAccuracy'
            Status    = 'Failed'
            Items     = @()
            Errors    = $errors.ToArray()
            Warnings  = $warnings.ToArray()
            Duration  = $stopwatch.Elapsed
        }
        return New-PACollectorResult @resultParams
    }
}
