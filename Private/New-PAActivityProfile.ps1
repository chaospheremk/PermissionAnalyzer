#Requires -Version 7.0

function New-PAActivityProfile {
    <#
    .SYNOPSIS
        Creates an activity profile object for a principal.
    .DESCRIPTION
        Factory function that returns a PA.ActivityProfile object summarising
        a principal's activity evidence across the three analysis tiers.
        Tier 0 = active, Tier 1 = no sign-in, Tier 2 = no role-related
        activity, Tier 3 = granted-vs-used action gap.

        DaysSinceLastSignIn and DaysSinceLastRoleActivity are computed
        automatically from the respective datetime parameters.
    .PARAMETER PrincipalId
        Entra object ID of the principal.
    .PARAMETER PrincipalDisplayName
        Display name of the principal.
    .PARAMETER PrincipalType
        Type of the principal.
    .PARAMETER LastSignInDateTime
        Most recent sign-in across all sign-in log tables. Null if no sign-in
        was found in the lookback window.
    .PARAMETER LastRoleActivityDateTime
        Most recent role-related operation from AuditLogs or AzureActivity.
        Null if no activity was found in the lookback window.
    .PARAMETER GrantedActions
        Role definition allowedResourceActions for the principal's assignments.
    .PARAMETER UsedActions
        Actions observed in audit and activity logs during the lookback window.
    .PARAMETER ActivityTier
        Computed activity tier: 0 = Active, 1 = NoSignIn, 2 = NoRoleActivity,
        3 = ActionGap.
    .PARAMETER SignInCount
        Number of sign-in events in the lookback window.
    .PARAMETER RoleActivityCount
        Number of role-related operations in the lookback window.
    .PARAMETER LookbackDays
        Number of days in the activity lookback window.
    .PARAMETER DataSource
        Which data source was used for activity analysis.
    .PARAMETER EvaluatedAt
        UTC timestamp when the activity profile was generated. Defaults to
        current UTC time.
    .EXAMPLE
        $profileParams = @{
            PrincipalId              = '<principal-id>'
            PrincipalType            = 'User'
            LastSignInDateTime       = (Get-Date).AddDays(-45)
            LastRoleActivityDateTime = $null
            ActivityTier             = 2
            LookbackDays             = 90
            DataSource               = 'LogAnalytics'
        }
        $profile = New-PAActivityProfile @profileParams
    .OUTPUTS
        PSCustomObject (PA.ActivityProfile)
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure data constructor — no system state change')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PrincipalId,

        [Parameter()]
        [string]$PrincipalDisplayName = '',

        [Parameter(Mandatory)]
        [ValidateSet('User', 'Group', 'ServicePrincipal', 'ManagedIdentity')]
        [string]$PrincipalType,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[datetime]]$LastSignInDateTime,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[datetime]]$LastRoleActivityDateTime,

        [Parameter()]
        [string[]]$GrantedActions = @(),

        [Parameter()]
        [string[]]$UsedActions = @(),

        [Parameter(Mandatory)]
        [ValidateRange(0, 3)]
        [int]$ActivityTier,

        [Parameter()]
        [int]$SignInCount = 0,

        [Parameter()]
        [int]$RoleActivityCount = 0,

        [Parameter(Mandatory)]
        [ValidateRange(1, 365)]
        [int]$LookbackDays,

        [Parameter(Mandatory)]
        [ValidateSet('LogAnalytics', 'GraphApi')]
        [string]$DataSource,

        [Parameter()]
        [datetime]$EvaluatedAt = [datetime]::UtcNow
    )

    # Compute days-since fields from nullable datetimes
    $daysSinceSignIn = if ($null -eq $LastSignInDateTime) {
        $null
    }
    else {
        [int][math]::Floor(([datetime]::UtcNow - $LastSignInDateTime).TotalDays)
    }

    $daysSinceRoleActivity = if ($null -eq $LastRoleActivityDateTime) {
        $null
    }
    else {
        [int][math]::Floor(([datetime]::UtcNow - $LastRoleActivityDateTime).TotalDays)
    }

    Write-Verbose "Creating PA.ActivityProfile for '$PrincipalId' (Tier $ActivityTier, Source: $DataSource)"

    $result = [PSCustomObject]@{
        PSTypeName                 = 'PA.ActivityProfile'
        PrincipalId                = $PrincipalId
        PrincipalDisplayName       = $PrincipalDisplayName
        PrincipalType              = $PrincipalType
        LastSignInDateTime         = $LastSignInDateTime
        DaysSinceLastSignIn        = $daysSinceSignIn
        LastRoleActivityDateTime   = $LastRoleActivityDateTime
        DaysSinceLastRoleActivity  = $daysSinceRoleActivity
        GrantedActions             = $GrantedActions
        UsedActions                = $UsedActions
        ActivityTier               = $ActivityTier
        SignInCount                = $SignInCount
        RoleActivityCount          = $RoleActivityCount
        LookbackDays               = $LookbackDays
        DataSource                 = $DataSource
        EvaluatedAt                = $EvaluatedAt
    }

    return $result
}
