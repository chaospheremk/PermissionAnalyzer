#Requires -Version 7.0

# Script-scoped cache for the operation map
$script:PAOperationMap = $null

function Resolve-PAOperationNamespace {
    <#
    .SYNOPSIS
        Resolves an AuditLog operation to an allowedResourceActions namespace.
    .DESCRIPTION
        Maps an Entra AuditLog OperationName to the corresponding
        microsoft.directory/* namespace prefix used in role definition
        allowedResourceActions. Used by Find-PALeastPrivilegeGap for Tier 3
        granted-vs-used action gap analysis.

        Resolution order:
        1. Explicit mapping (OperationName exact match)
        2. Category-to-namespace inference (AuditLog Category fallback)
        3. Null (unmapped — caller decides how to handle)

        The operation map is loaded from Data/EntraOperationMap.json on first
        call and cached for the module session.
    .PARAMETER OperationName
        AuditLog OperationName value (e.g. 'Add user', 'Update group').
    .PARAMETER Category
        AuditLog Category value (e.g. 'UserManagement', 'GroupManagement').
        Used as fallback when no explicit mapping exists.
    .EXAMPLE
        Resolve-PAOperationNamespace -OperationName 'Add user'
        # Returns: microsoft.directory/users/create
    .EXAMPLE
        Resolve-PAOperationNamespace -OperationName 'Some unknown op' -Category 'UserManagement'
        # Returns: microsoft.directory/users (category fallback)
    .EXAMPLE
        Resolve-PAOperationNamespace -OperationName 'Totally unknown' -Category 'UnknownCategory'
        # Returns: $null
    .OUTPUTS
        System.String or $null
        The resolved namespace prefix, or null if unmapped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName,

        [Parameter()]
        [string]$Category = ''
    )

    # Load and cache the operation map on first call
    if ($null -eq $script:PAOperationMap) {
        $mapPath = Join-Path $PSScriptRoot '../Data/EntraOperationMap.json'
        if (-not (Test-Path $mapPath)) {
            throw "Resolve-PAOperationNamespace: operation map not found at '$mapPath'."
        }

        $script:PAOperationMap = Get-Content $mapPath -Raw | ConvertFrom-Json
        Write-Verbose 'Resolve-PAOperationNamespace: loaded EntraOperationMap.json'
    }

    # Tier 1: explicit mapping (exact match)
    $explicit = $script:PAOperationMap.explicitMappings.$OperationName
    if ($explicit) {
        return $explicit
    }

    # Tier 2: category-to-namespace inference
    if ($Category -ne '') {
        $categoryNamespace = $script:PAOperationMap.categoryToNamespace.$Category
        if ($categoryNamespace) {
            return $categoryNamespace
        }
    }

    # Tier 3: unmapped
    return $null
}
