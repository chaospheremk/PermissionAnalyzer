#Requires -Version 7.0

<#
Integration-test helpers for PermissionAnalyzer.

Each integration test mocks only at the HTTP/SDK boundary
(Invoke-MgGraphRequest, Invoke-AzOperationalInsightsQuery, and Az cmdlets)
so that collectors, analyzers, and exporters execute unmocked. Fixture
responses live under Tests/Integration/Fixtures/<scenario>/ and are keyed
by endpoint.

# Fixture refresh playbook

When Microsoft changes a response shape, fixtures drift and tests keep
passing against stale data. To refresh:

1. In a scratch directory, run Invoke-PAPermissionAudit against a known
   dev tenant with Write-Debug transcripts enabled, capturing the raw
   Invoke-MgGraphRequest return values and KQL Results arrays.
2. Sanitize the captures — replace real tenant IDs, object IDs, sign-in
   data, and principal display names with placeholder values.
3. Drop the sanitized JSON into Tests/Integration/Fixtures/<scenario>/
   under the matching fixture name (see Get-FixtureGraphResponse for the
   URI-to-file mapping).
4. Re-run the integration suite; failing assertions identify fields that
   need new handling in collectors/analyzers.
#>

$script:PAFixtureCache = @{}

function Get-IntegrationFixture {
    <#
    .SYNOPSIS
        Loads and caches a scenario fixture JSON file.
    .DESCRIPTION
        Reads the JSON at <ScenarioRoot>/<RelativePath>, parses it with
        ConvertFrom-Json, and caches the result keyed by absolute path so
        repeat calls inside a single test run are free. Returns $null when
        the file does not exist so callers can distinguish "no data" from
        "missing mapping."
    .PARAMETER ScenarioRoot
        Absolute or script-relative path to the per-scenario Fixtures
        directory (e.g. .../Tests/Integration/Fixtures/happy-path).
    .PARAMETER RelativePath
        Fixture path relative to ScenarioRoot (e.g. graph/roleAssignments.json).
    .EXAMPLE
        $users = Get-IntegrationFixture -ScenarioRoot $root -RelativePath 'graph/users.json'
    .OUTPUTS
        System.Management.Automation.PSCustomObject or System.Object[] or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScenarioRoot,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath
    )

    $cacheKey = "$ScenarioRoot||$RelativePath"
    if ($script:PAFixtureCache.ContainsKey($cacheKey)) {
        return $script:PAFixtureCache[$cacheKey]
    }

    $fullPath = Join-Path $ScenarioRoot $RelativePath
    if (-not (Test-Path -Path $fullPath -PathType Leaf)) {
        $script:PAFixtureCache[$cacheKey] = $null
        return $null
    }

    $raw = [System.IO.File]::ReadAllText($fullPath)
    $parsed = $raw | ConvertFrom-Json -Depth 20
    $script:PAFixtureCache[$cacheKey] = $parsed
    $parsed
}

function Clear-IntegrationFixtureCache {
    <#
    .SYNOPSIS
        Empties the fixture cache.
    .DESCRIPTION
        Used by test BeforeAll blocks to guarantee that subsequent fixture
        reads pick up any on-disk changes between test runs in the same
        PowerShell session.
    .EXAMPLE
        Clear-IntegrationFixtureCache
    .OUTPUTS
        None.
    #>
    [CmdletBinding()]
    param()
    $script:PAFixtureCache = @{}
}

function Resolve-FixtureDateToken {
    <#
    .SYNOPSIS
        Replaces 'RELATIVE:<N>d' tokens with ISO-8601 datetimes offset from UtcNow.
    .DESCRIPTION
        Recursively walks an object graph and returns a copy with every
        string matching /^RELATIVE:(-?\d+)d$/ replaced by
        [datetime]::UtcNow.AddDays(<N>).ToString('o'). Lets fixtures express
        activity freshness symbolically so tests don't start failing once
        their hardcoded dates age past inactivity thresholds.

        Mutation semantics: PSCustomObject property values are replaced
        in place via `$prop.Value = ...` so callers that hold a reference
        to the object still see the resolved tokens. Arrays and
        dictionaries are returned as fresh copies because strings are
        immutable and array elements can't be reassigned through an
        enumerator. Nested arrays inside an object are therefore replaced,
        not mutated — a caller that cached a reference to an inner array
        before calling this function will observe the cached reference go
        stale. Callers must assign the return value at the top level.
    .PARAMETER InputObject
        Any object graph parsed from JSON — commonly a PSCustomObject[]
        from ConvertFrom-Json, but scalars and nested arrays are handled.
    .EXAMPLE
        $resolved = Resolve-FixtureDateToken -InputObject $fixture
    .OUTPUTS
        System.Object — the input with all RELATIVE tokens substituted.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [string]) {
        if ($InputObject -match '^RELATIVE:(-?\d+)d$') {
            $days = [int]$Matches[1]
            return [datetime]::UtcNow.AddDays($days).ToString('o')
        }
        return $InputObject
    }

    if ($InputObject.GetType().IsValueType) {
        return $InputObject
    }

    # Arrays and lists: iterate and build a resolved copy so that
    # scalar-string tokens (which can't be mutated in place) still get
    # replaced. @($resolved) collapses null and scalar results to a
    # well-formed array.
    if ($InputObject -is [array] -or $InputObject -is [System.Collections.IList]) {
        $resolved = foreach ($item in $InputObject) {
            Resolve-FixtureDateToken -InputObject $item
        }
        return @($resolved)
    }

    # Dictionaries (including [ordered]@{} / OrderedDictionary, Hashtable,
    # and ConvertFrom-Json -AsHashtable output): mutate values in place
    # via the Keys collection so the caller's reference stays valid.
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in @($InputObject.Keys)) {
            $InputObject[$key] = Resolve-FixtureDateToken -InputObject $InputObject[$key]
        }
        return $InputObject
    }

    # PSCustomObject (or similar with NoteProperty collection): mutate
    # property values in place and return the same reference so callers
    # that rely on reference identity still work.
    foreach ($prop in $InputObject.PSObject.Properties) {
        $prop.Value = Resolve-FixtureDateToken -InputObject $prop.Value
    }
    $InputObject
}

function Get-FixtureGraphResponse {
    <#
    .SYNOPSIS
        Maps a Graph API URI to a fixture file and returns a paginated response shape.
    .DESCRIPTION
        Dispatches a post-wrapper Graph URI (which includes the /v1.0 or /beta
        prefix and the query string) to a fixture JSON file under
        <ScenarioRoot>/graph/. Returns a PSCustomObject with a `value`
        property so Invoke-PAGraphRequest's pagination loop unwraps it
        cleanly. Empty `value` is returned when no fixture matches the URI
        (e.g. an SP with no appRoleAssignments) so optional endpoints don't
        fail the collector; required-endpoint gaps surface as empty-result
        assertion failures downstream.

        URI-to-fixture mapping:
            /roleManagement/directory/roleDefinitions              → graph/roleDefinitions.json
            /roleManagement/directory/roleAssignments              → graph/roleAssignments.json
            /roleManagement/directory/roleEligibilityScheduleInstances → graph/roleEligibilityScheduleInstances.json
            /servicePrincipals                                     → graph/servicePrincipals.json
            /servicePrincipals/{id}/appRoleAssignments             → graph/appRoleAssignments-{id}.json
            /oauth2PermissionGrants                                → graph/oauth2PermissionGrants.json
            /users                                                 → graph/users.json
            /auditLogs/directoryAudits                             → graph/directoryAudits.json
    .PARAMETER Uri
        The Graph URI passed to Invoke-MgGraphRequest.
    .PARAMETER ScenarioRoot
        Absolute path to the per-scenario Fixtures directory.
    .EXAMPLE
        Mock Invoke-MgGraphRequest {
            Get-FixtureGraphResponse -Uri $Uri -ScenarioRoot $script:ScenarioRoot
        }
    .OUTPUTS
        System.Management.Automation.PSCustomObject — shape @{ value = @(...); '@odata.nextLink' = $null }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScenarioRoot
    )

    $path = ($Uri -split '\?')[0]

    $fixtureFile = switch -Regex ($path) {
        '/roleManagement/directory/roleDefinitions$'                 { 'graph/roleDefinitions.json'; break }
        '/roleManagement/directory/roleAssignments$'                 { 'graph/roleAssignments.json'; break }
        '/roleManagement/directory/roleEligibilityScheduleInstances$' { 'graph/roleEligibilityScheduleInstances.json'; break }
        '/servicePrincipals$'                                        { 'graph/servicePrincipals.json'; break }
        '/servicePrincipals/[^/]+/appRoleAssignments$' {
            $spId = ($path -replace '.*/servicePrincipals/([^/]+)/appRoleAssignments$', '$1')
            "graph/appRoleAssignments-$spId.json"
            break
        }
        '/oauth2PermissionGrants$'                                   { 'graph/oauth2PermissionGrants.json'; break }
        '/users$'                                                    { 'graph/users.json'; break }
        '/auditLogs/directoryAudits$'                                { 'graph/directoryAudits.json'; break }
        default { $null }
    }

    $value = @()
    if ($fixtureFile) {
        $fixture = Get-IntegrationFixture -ScenarioRoot $ScenarioRoot -RelativePath $fixtureFile
        if ($null -ne $fixture) {
            $value = @(Resolve-FixtureDateToken -InputObject $fixture)
        }
    }

    [PSCustomObject]@{ value = $value; '@odata.nextLink' = $null }
}

function Get-FixtureLogAnalyticsResponse {
    <#
    .SYNOPSIS
        Maps a KQL query to a fixture file and returns a Results-shaped response.
    .DESCRIPTION
        Dispatches a KQL query to a fixture under <ScenarioRoot>/log-analytics/
        by matching on distinctive KQL fragments unique to each query the
        module emits. Returns a PSCustomObject with a `Results` property so
        Invoke-PALogAnalyticsQuery unwraps it cleanly. Throws when no
        pattern matches — silent fallthrough would mask KQL drift by
        serving the wrong fixture.

        Pattern ordering is specific-first so Tier 3 used-actions queries
        match before the broader role-activity queries for the same table.
    .PARAMETER Query
        The KQL string passed to Invoke-AzOperationalInsightsQuery.
    .PARAMETER ScenarioRoot
        Absolute path to the per-scenario Fixtures directory.
    .EXAMPLE
        Mock Invoke-AzOperationalInsightsQuery {
            Get-FixtureLogAnalyticsResponse -Query $Query -ScenarioRoot $script:ScenarioRoot
        }
    .OUTPUTS
        System.Management.Automation.PSCustomObject — shape @{ Results = @(...); Error = $null }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Query,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScenarioRoot
    )

    # .NET regex in PowerShell's `switch -Regex` defaults to MultiLine-off/
    # Singleline-off, so patterns rely on single-line fragments (\s includes
    # newlines but `.` does not). Unmatched queries throw — silent fixture
    # misses would test the wrong data path without surfacing the drift.
    $fixtureFile = switch -Regex ($Query) {
        'where\s+OperationNameValue' {
            'log-analytics/AzureActivity-UsedActions.json'; break
        }
        'summarize by PrincipalId=InitiatorId, OperationName, Category' {
            'log-analytics/AuditLogs-UsedActions.json'; break
        }
        'SigninLogs|AADNonInteractiveUserSignInLogs|AADServicePrincipalSignInLogs|AADManagedIdentitySignInLogs' {
            'log-analytics/SigninLogs.json'; break
        }
        'AzureActivity' { 'log-analytics/AzureActivity.json'; break }
        'AuditLogs'     { 'log-analytics/AuditLogs.json'; break }
        default { $null }
    }

    if (-not $fixtureFile) {
        $preview = $Query.Substring(0, [math]::Min(160, $Query.Length))
        throw "Get-FixtureLogAnalyticsResponse: no fixture mapping for KQL query. First 160 chars: $preview"
    }

    $results = @()
    $fixture = Get-IntegrationFixture -ScenarioRoot $ScenarioRoot -RelativePath $fixtureFile
    if ($null -ne $fixture) {
        $results = @(Resolve-FixtureDateToken -InputObject $fixture)
    }

    [PSCustomObject]@{ Results = $results; Error = $null }
}

function Get-PAModuleSourceFile {
    <#
    .SYNOPSIS
        Returns the ordered list of module source files for dot-source loading.
    .DESCRIPTION
        Integration tests dot-source private and public function files
        directly rather than Import-Module-ing the psd1, because the
        manifest's RequiredModules declaration would pull in the real
        Microsoft.Graph.Authentication and Az.* modules and prevent the
        stub functions (`function Invoke-MgGraphRequest {...}`) that Pester
        needs to Mock against. Returning the list from one place keeps the
        three scenario files in sync when new functions are added. Order
        matters: private constructors and helpers before the public
        collectors and analyzers that call them, and the orchestrator last.
    .EXAMPLE
        foreach ($relative in Get-PAModuleSourceFile) {
            . (Join-Path $moduleRoot $relative)
        }
    .OUTPUTS
        System.String[] — relative paths rooted at the module directory.
    #>
    [CmdletBinding()]
    param()

    @(
        'Private/New-PAAssignment.ps1'
        'Private/New-PAActivityProfile.ps1'
        'Private/New-PAFinding.ps1'
        'Private/New-PACollectorResult.ps1'
        'Private/New-PAValidationResult.ps1'
        'Private/Invoke-PAGraphRequest.ps1'
        'Private/Invoke-PALogAnalyticsQuery.ps1'
        'Private/Resolve-PAPrincipal.ps1'
        'Private/Resolve-PAOperationNamespace.ps1'
        'Private/Resolve-PARoleAction.ps1'
        'Public/Connect-PASession.ps1'
        'Public/Get-PAEntraRoleAssignment.ps1'
        'Public/Get-PAPimEligibility.ps1'
        'Public/Get-PAAzureRbacAssignment.ps1'
        'Public/Get-PAAppPermission.ps1'
        'Public/Get-PAActivitySignal.ps1'
        'Public/Find-PAUnusedAssignment.ps1'
        'Public/Find-PALeastPrivilegeGap.ps1'
        'Public/Find-PAGroupConsolidation.ps1'
        'Public/Export-PAReport.ps1'
        'Public/New-PARemediationScript.ps1'
        'Public/Test-PAFindingAccuracy.ps1'
        'Public/Invoke-PAPermissionAudit.ps1'
    )
}

function New-IntegrationOutputDirectory {
    <#
    .SYNOPSIS
        Creates a unique temp directory for integration-test artifacts.
    .DESCRIPTION
        Generates a GUID-suffixed directory under the system temp root so
        concurrent test runs, re-runs, and determinism checks don't collide
        on output paths. Caller is responsible for cleanup via
        Remove-IntegrationOutputDirectory.
    .EXAMPLE
        $outDir = New-IntegrationOutputDirectory
    .OUTPUTS
        System.String — absolute path to the newly created directory.
    #>
    [CmdletBinding()]
    param()
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "pa-integration-$([guid]::NewGuid())"
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    $path
}

function Remove-IntegrationOutputDirectory {
    <#
    .SYNOPSIS
        Deletes a scratch output directory created by New-IntegrationOutputDirectory.
    .DESCRIPTION
        Recursively removes the directory if it exists. No-ops silently when
        the path is empty or missing so teardown in AfterAll/finally is safe
        after partial setup failures.
    .PARAMETER Path
        Absolute path returned by New-IntegrationOutputDirectory.
    .EXAMPLE
        Remove-IntegrationOutputDirectory -Path $outDir
    .OUTPUTS
        None.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path
    )
    if ($Path -and (Test-Path -Path $Path -PathType Container)) {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}
