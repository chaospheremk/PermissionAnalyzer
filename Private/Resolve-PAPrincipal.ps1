#Requires -Version 7.0

function Resolve-PAPrincipal {
    <#
    .SYNOPSIS
        Batch-resolves principal IDs to display names via Microsoft Graph.
    .DESCRIPTION
        Resolves an array of Entra object IDs to their display names using
        the /directoryObjects endpoint. Processes in batches of 15 (Graph
        $filter 'in' operator limit). Returns a hashtable mapping each ID
        to its display name. Unresolved IDs are mapped to a placeholder.

        Uses Invoke-PAGraphRequest internally (ADR-001).
    .PARAMETER PrincipalIds
        Array of Entra object IDs to resolve. Duplicates are removed
        automatically.
    .PARAMETER Session
        PA.Session object for environment context. Reserved for future use.
    .EXAMPLE
        $ids = @('<principal-id-1>', '<principal-id-2>')
        $nameMap = Resolve-PAPrincipal -PrincipalIds $ids
        $nameMap['<principal-id-1>']  # returns the display name
    .INPUTS
        None.
    .OUTPUTS
        System.Collections.Hashtable
        Hashtable mapping principal ID strings to display name strings.
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'Session',
        Justification = 'Reserved for future environment-aware resolution')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$PrincipalIds,

        [Parameter()]
        [PSCustomObject]$Session = $null
    )

    if (-not $PrincipalIds -or $PrincipalIds.Count -eq 0) {
        return @{}
    }

    $uniqueIds = @($PrincipalIds | Select-Object -Unique)
    $resolved = @{}
    $batchSize = 15

    for ($i = 0; $i -lt $uniqueIds.Count; $i += $batchSize) {
        $endIndex = [math]::Min($i + $batchSize - 1, $uniqueIds.Count - 1)
        $batch = $uniqueIds[$i..$endIndex]

        $idList = (@(foreach ($id in $batch) { "'$id'" }) -join ',')
        $filter = "id in ($idList)"

        $graphParams = @{
            Uri    = '/directoryObjects'
            Filter = $filter
        }
        $objects = Invoke-PAGraphRequest @graphParams

        foreach ($obj in $objects) {
            $displayName = $obj.displayName

            # Service principals may have empty displayName; fall back to appDisplayName
            if ($obj.'@odata.type' -eq '#microsoft.graph.servicePrincipal' -and
                [string]::IsNullOrEmpty($displayName)) {
                $displayName = $obj.appDisplayName
            }

            if (-not [string]::IsNullOrEmpty($displayName)) {
                $resolved[$obj.id] = $displayName
            }
        }
    }

    # Map unresolved IDs to placeholder
    foreach ($id in $uniqueIds) {
        if (-not $resolved.ContainsKey($id)) {
            $shortId = $id.Substring(0, [math]::Min(8, $id.Length))
            $resolved[$id] = "[Deleted or inaccessible: $shortId...]"
        }
    }

    $resolvedCount = $resolved.Values.Where({ $_ -notlike '`[Deleted*' }).Count
    Write-Verbose "Resolve-PAPrincipal: resolved $resolvedCount of $($uniqueIds.Count) principal IDs"

    return $resolved
}
