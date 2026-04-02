#Requires -Version 7.0

function Invoke-PAGraphRequest {
    <#
    .SYNOPSIS
        Thin pagination wrapper over Invoke-MgGraphRequest.
    .DESCRIPTION
        Executes a Microsoft Graph API request with automatic pagination,
        $select injection, $filter support, and ConsistencyLevel header
        handling. Stops pagination at MaxPages to prevent runaway queries.

        This function does NOT add retry logic — Invoke-MgGraphRequest
        already handles HTTP 429 with Retry-After internally (ADR-001).
    .PARAMETER Uri
        Graph API relative path (e.g. '/roleManagement/directory/roleAssignments').
        If the path does not start with 'http', the ApiVersion is prepended.
    .PARAMETER Select
        Fields to include as the $select query parameter.
    .PARAMETER Filter
        OData $filter expression.
    .PARAMETER ApiVersion
        Graph API version to use.
    .PARAMETER MaxPages
        Maximum number of pages to fetch before stopping. Prevents runaway
        pagination on large tenants.
    .PARAMETER ConsistencyLevel
        Sets the ConsistencyLevel request header. Required for certain beta
        endpoints (e.g. PIM schedule listings). When set, $count=true is
        automatically added to the query parameters.
    .PARAMETER HttpMethod
        HTTP method for the request.
    .EXAMPLE
        $graphParams = @{
            Uri    = '/roleManagement/directory/roleAssignments'
            Select = @('id', 'principalId', 'roleDefinitionId', 'directoryScopeId')
        }
        $assignments = Invoke-PAGraphRequest @graphParams
    .EXAMPLE
        $graphParams = @{
            Uri              = '/roleManagement/directory/roleEligibilitySchedules'
            ApiVersion       = 'beta'
            ConsistencyLevel = 'eventual'
        }
        $schedules = Invoke-PAGraphRequest @graphParams
    .OUTPUTS
        System.Object[]
        Array of result objects from the Graph API response.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [string[]]$Select = @(),

        [Parameter()]
        [string]$Filter = '',

        [Parameter()]
        [ValidateSet('v1.0', 'beta')]
        [string]$ApiVersion = 'v1.0',

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$MaxPages = 50,

        [Parameter()]
        [ValidateSet('', 'eventual')]
        [string]$ConsistencyLevel = '',

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$HttpMethod = 'GET'
    )

    # Build URI with API version prefix
    if (-not $Uri.StartsWith('http')) {
        $Uri = "/$ApiVersion$Uri"
    }

    # Build query parameters
    $queryParts = [System.Collections.Generic.List[string]]::new()
    if ($Select.Count -gt 0) {
        $queryParts.Add("`$select=$($Select -join ',')")
    }
    if ($Filter -ne '') {
        $queryParts.Add("`$filter=$Filter")
    }
    if ($ConsistencyLevel -ne '') {
        $queryParts.Add('$count=true')
    }

    if ($queryParts.Count -gt 0) {
        $separator = if ($Uri.Contains('?')) { '&' } else { '?' }
        $Uri = $Uri + $separator + ($queryParts -join '&')
    }

    # Build headers
    $headers = @{}
    if ($ConsistencyLevel -ne '') {
        $headers['ConsistencyLevel'] = $ConsistencyLevel
    }

    # Build splat for Invoke-MgGraphRequest
    $mgParams = @{
        Method     = $HttpMethod
        Uri        = $Uri
        OutputType = 'PSObject'
    }
    if ($headers.Count -gt 0) {
        $mgParams['Headers'] = $headers
    }

    # Pagination loop
    $allResults = [System.Collections.Generic.List[object]]::new()
    $pageCount = 0
    $currentUri = $mgParams.Uri

    do {
        $mgParams.Uri = $currentUri
        $response = Invoke-MgGraphRequest @mgParams
        $pageCount++

        if ($response.PSObject.Properties['value']) {
            $items = $response.value
            if ($null -ne $items) {
                $allResults.AddRange([object[]]@($items))
            }
        }
        elseif ($pageCount -eq 1) {
            # Single-object response (no .value property, no pagination)
            return $response
        }

        Write-Verbose "Invoke-PAGraphRequest: page $pageCount ($($allResults.Count) items so far)"
        $currentUri = $response.'@odata.nextLink'

    } while ($currentUri -and $pageCount -lt $MaxPages)

    if ($currentUri) {
        Write-Warning "Invoke-PAGraphRequest: stopped at $MaxPages pages ($($allResults.Count) items). Results may be incomplete."
    }

    return $allResults.ToArray()
}
