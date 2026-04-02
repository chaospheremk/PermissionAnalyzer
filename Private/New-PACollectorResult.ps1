#Requires -Version 7.0

function New-PACollectorResult {
    <#
    .SYNOPSIS
        Creates a collector result wrapper object.
    .DESCRIPTION
        Factory function that returns a PA.CollectorResult object wrapping the
        output of a data collector. Tracks completion status, item count, errors,
        warnings, and elapsed duration for pipeline observability.
    .PARAMETER Collector
        Name of the collector function that produced this result
        (e.g. 'Get-PAEntraRoleAssignment').
    .PARAMETER Status
        Completion status of the collector run.
    .PARAMETER Items
        Array of objects returned by the collector (typically PA.Assignment objects).
    .PARAMETER Errors
        Array of error messages encountered during collection.
    .PARAMETER Warnings
        Array of warning messages encountered during collection.
    .PARAMETER Duration
        Elapsed time for the collector run.
    .PARAMETER Timestamp
        UTC timestamp when the result was created. Defaults to current UTC time.
    .EXAMPLE
        $resultParams = @{
            Collector = 'Get-PAEntraRoleAssignment'
            Status    = 'Complete'
            Items     = $assignments
            Duration  = $stopwatch.Elapsed
        }
        $result = New-PACollectorResult @resultParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.CollectorResult)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure data constructor — no system state change')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Collector,

        [Parameter(Mandatory)]
        [ValidateSet('Complete', 'Partial', 'Failed')]
        [string]$Status,

        [Parameter()]
        [object[]]$Items = @(),

        [Parameter()]
        [string[]]$Errors = @(),

        [Parameter()]
        [string[]]$Warnings = @(),

        [Parameter(Mandatory)]
        [timespan]$Duration,

        [Parameter()]
        [datetime]$Timestamp = [datetime]::UtcNow
    )

    Write-Verbose "Creating PA.CollectorResult for collector '$Collector' (Status: $Status)"

    $result = [PSCustomObject]@{
        PSTypeName = 'PA.CollectorResult'
        Collector  = $Collector
        Status     = $Status
        Items      = $Items
        ItemCount  = $Items.Count
        Errors     = $Errors
        Warnings   = $Warnings
        Duration   = $Duration
        Timestamp  = $Timestamp
    }

    return $result
}
