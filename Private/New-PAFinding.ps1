#Requires -Version 7.0

function New-PAFinding {
    <#
    .SYNOPSIS
        Creates an actionable finding object with a deterministic FindingId.
    .DESCRIPTION
        Factory function that returns a PA.Finding object representing a single
        actionable recommendation from the analysis phase. The FindingId is a
        deterministic SHA256-based hash of the composite key
        (Category + PrincipalId + RoleDefinitionId + Scope) so that identical
        conditions always produce the same identifier for deduplication and
        tracking across runs.
    .PARAMETER Category
        Classification of the finding.
    .PARAMETER Severity
        Impact severity of the finding.
    .PARAMETER Title
        Human-readable summary of the finding.
    .PARAMETER PrincipalId
        Entra object ID of the affected principal.
    .PARAMETER PrincipalDisplayName
        Display name of the affected principal.
    .PARAMETER PrincipalType
        Type of the affected principal.
    .PARAMETER RoleName
        Display name of the role involved in the finding.
    .PARAMETER RoleDefinitionId
        Identifier of the role involved in the finding.
    .PARAMETER Scope
        Target scope of the assignment involved in the finding.
    .PARAMETER Source
        Which collector produced the underlying assignment data.
    .PARAMETER ActivityTier
        Activity tier from the activity profile. Null for findings that do not
        depend on activity analysis (e.g. GroupConsolidation).
    .PARAMETER DaysSinceActive
        Days since the principal last showed relevant activity. Null when not
        applicable.
    .PARAMETER Recommendation
        What action should be taken to remediate this finding.
    .PARAMETER RemediationAction
        Structured remediation action type for script generation.
    .PARAMETER Details
        Category-specific supplementary data as a hashtable.
    .PARAMETER CreatedAt
        UTC timestamp when the finding was generated. Defaults to current UTC time.
    .EXAMPLE
        $findingParams = @{
            Category          = 'UnusedAssignment'
            Severity          = 'High'
            Title             = 'User has Global Administrator role with no sign-in in 90 days'
            PrincipalId       = '<principal-id>'
            RoleDefinitionId  = '<role-definition-id>'
            Scope             = '/'
            Recommendation    = 'Remove the Global Administrator assignment'
            RemediationAction = 'Remove'
        }
        $finding = New-PAFinding @findingParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.Finding)
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
        [ValidateSet('UnusedAssignment', 'OverPrivileged', 'GroupConsolidation')]
        [string]$Category,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PrincipalId,

        [Parameter()]
        [string]$PrincipalDisplayName = '',

        [Parameter()]
        [string]$PrincipalType = '',

        [Parameter()]
        [string]$RoleName = '',

        [Parameter()]
        [string]$RoleDefinitionId = '',

        [Parameter()]
        [string]$Scope = '',

        [Parameter()]
        [string]$Source = '',

        [Parameter()]
        [AllowNull()]
        [System.Nullable[int]]$ActivityTier,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[int]]$DaysSinceActive,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Recommendation,

        [Parameter(Mandatory)]
        [ValidateSet('Remove', 'Downgrade', 'ConsolidateToGroup', 'ReviewEligible', 'ReduceScope')]
        [string]$RemediationAction,

        [Parameter()]
        [hashtable]$Details = @{},

        [Parameter()]
        [datetime]$CreatedAt = [datetime]::UtcNow
    )

    # Compute deterministic FindingId from composite key
    $hashInput = "$Category|$PrincipalId|$RoleDefinitionId|$Scope".ToLower()
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($hashInput)
    )
    $findingId = [System.Convert]::ToHexString($hashBytes).Substring(0, 16).ToLower()

    Write-Verbose "Creating PA.Finding [$Severity] $Category for '$PrincipalId' (FindingId: $findingId)"

    $result = [PSCustomObject]@{
        PSTypeName          = 'PA.Finding'
        FindingId           = $findingId
        Category            = $Category
        Severity            = $Severity
        Title               = $Title
        PrincipalId         = $PrincipalId
        PrincipalDisplayName = $PrincipalDisplayName
        PrincipalType       = $PrincipalType
        RoleName            = $RoleName
        RoleDefinitionId    = $RoleDefinitionId
        Scope               = $Scope
        Source              = $Source
        ActivityTier        = $ActivityTier
        DaysSinceActive     = $DaysSinceActive
        Recommendation      = $Recommendation
        RemediationAction   = $RemediationAction
        Details             = $Details
        CreatedAt           = $CreatedAt
    }

    return $result
}
