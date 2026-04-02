#Requires -Version 7.0

function Invoke-PALogAnalyticsQuery {
    <#
    .SYNOPSIS
        Executes a KQL query against a Log Analytics workspace with retry.
    .DESCRIPTION
        Wrapper over Invoke-AzOperationalInsightsQuery that adds retry logic
        for transient failures and structured error handling. Permanent
        failures (bad syntax, permission denied) are thrown immediately
        without retry.

        Log Analytics endpoints are cloud-agnostic — the workspace ID
        handles routing to the correct environment (ADR-003).
    .PARAMETER WorkspaceId
        Log Analytics workspace ID.
    .PARAMETER Query
        KQL query string to execute.
    .PARAMETER Timespan
        Query time window. Defaults to 90 days.
    .PARAMETER MaxRetries
        Maximum number of retry attempts for transient failures.
    .PARAMETER RetryDelaySeconds
        Seconds to wait between retry attempts.
    .EXAMPLE
        $queryParams = @{
            WorkspaceId = '<workspace-id>'
            Query       = 'SigninLogs | summarize count() by UserPrincipalName'
            Timespan    = [timespan]::FromDays(30)
        }
        $rows = Invoke-PALogAnalyticsQuery @queryParams
    .INPUTS
        None.
    .OUTPUTS
        System.Object[]
        Array of result row objects from the KQL query.
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Query,

        [Parameter()]
        [timespan]$Timespan = [timespan]::FromDays(90),

        [Parameter()]
        [ValidateRange(0, 5)]
        [int]$MaxRetries = 2,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySeconds = 5
    )

    $queryParams = @{
        WorkspaceId = $WorkspaceId
        Query       = $Query
        Timespan    = $Timespan
        ErrorAction = 'Stop'
    }

    $attempt = 0
    $maxAttempts = $MaxRetries + 1
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $response = $null

    while ($attempt -lt $maxAttempts) {
        $attempt++
        try {
            $response = Invoke-AzOperationalInsightsQuery @queryParams
            break
        }
        catch {
            $errorMessage = $_.Exception.Message
            $statusCode = $null
            if ($_.Exception.PSObject.Properties['Response'] -and
                $_.Exception.Response.PSObject.Properties['StatusCode']) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $isPermanent = ($statusCode -in @(400, 403, 404)) -or
                           ($errorMessage -match 'syntax error|bad request|forbidden|not found')

            if ($isPermanent -or $attempt -ge $maxAttempts) {
                throw
            }

            Write-Warning "Invoke-PALogAnalyticsQuery: attempt $attempt failed ($errorMessage). Retrying in $RetryDelaySeconds seconds..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    $stopwatch.Stop()

    # Check for query-level errors (can occur even with HTTP 200)
    if ($response.Error) {
        throw "Log Analytics query failed: $($response.Error.Message)"
    }

    $results = if ($null -ne $response.Results) { @($response.Results) } else { @() }

    $workspaceShort = $WorkspaceId.Substring(0, [math]::Min(8, $WorkspaceId.Length))
    Write-Verbose "Invoke-PALogAnalyticsQuery: workspace $workspaceShort..., $($results.Count) rows, $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

    return $results
}
