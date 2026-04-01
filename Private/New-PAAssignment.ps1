#Requires -Version 7.0

function New-PAAssignment {
    <#
    .SYNOPSIS
        Creates a normalized permission assignment object.
    .DESCRIPTION
        Factory function that returns a PA.Assignment object representing a
        single permission assignment from any of the five collection sources.
        All collectors normalize their output into this WHO/WHAT/WHERE/HOW/WHEN
        shape for consistent downstream analysis.
    .PARAMETER PrincipalId
        Entra object ID of the assigned principal.
    .PARAMETER PrincipalDisplayName
        Display name of the principal. Resolved separately by Resolve-PAPrincipal.
    .PARAMETER PrincipalType
        Type of the assigned principal.
    .PARAMETER RoleDefinitionId
        Identifier of the role or permission granted. For Entra/Azure roles this
        is the roleDefinitionId; for app permissions it is the appRoleId or a
        synthetic ID for delegated grants.
    .PARAMETER RoleName
        Display name of the role or permission.
    .PARAMETER RoleType
        Classification of the role. Empty string when not yet classified.
    .PARAMETER Scope
        Target scope of the assignment. '/' for tenant-wide Entra roles,
        AU path for admin-unit-scoped roles, Azure resource path for RBAC,
        or application identifier for app permissions.
    .PARAMETER ScopeType
        Classification of the scope path. Empty string when not yet classified.
    .PARAMETER Source
        Which collector produced this assignment.
    .PARAMETER AssignmentType
        How the permission was granted.
    .PARAMETER Status
        Current status of the assignment. Defaults to Active.
    .PARAMETER CreatedDateTime
        When the assignment was created. Null if not available from the source.
    .PARAMETER StartDateTime
        Effective start for time-bound assignments (PIM). Null if permanent.
    .PARAMETER EndDateTime
        Expiration for time-bound assignments (PIM). Null if permanent.
    .PARAMETER ResourceDisplayName
        Display name of the target application (app permissions only).
    .PARAMETER ConsentType
        OAuth2 consent type (app permissions only). AllPrincipals for
        admin-consented grants, Principal for user-consented grants.
    .EXAMPLE
        $assignmentParams = @{
            PrincipalId      = '<principal-id>'
            PrincipalType    = 'User'
            RoleDefinitionId = '<role-definition-id>'
            Scope            = '/'
            Source           = 'EntraRole'
            AssignmentType   = 'Direct'
        }
        $assignment = New-PAAssignment @assignmentParams
    .OUTPUTS
        PSCustomObject (PA.Assignment)
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure data constructor — no system state change')]
    [CmdletBinding()]
    param(
        # WHO
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PrincipalId,

        [Parameter()]
        [string]$PrincipalDisplayName = '',

        [Parameter(Mandatory)]
        [ValidateSet('User', 'Group', 'ServicePrincipal', 'ManagedIdentity')]
        [string]$PrincipalType,

        # WHAT
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RoleDefinitionId,

        [Parameter()]
        [string]$RoleName = '',

        [Parameter()]
        [ValidateSet('', 'BuiltIn', 'Custom', 'AppRole', 'DelegatedGrant')]
        [string]$RoleType = '',

        # WHERE
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Scope,

        [Parameter()]
        [ValidateSet('', 'Tenant', 'AdministrativeUnit', 'ManagementGroup',
            'Subscription', 'ResourceGroup', 'Resource', 'Application')]
        [string]$ScopeType = '',

        # HOW
        [Parameter(Mandatory)]
        [ValidateSet('EntraRole', 'PimEntra', 'PimAzure', 'AzureRbac', 'AppPermission')]
        [string]$Source,

        [Parameter(Mandatory)]
        [ValidateSet('Direct', 'Eligible', 'Activated', 'AppRole', 'DelegatedGrant')]
        [string]$AssignmentType,

        [Parameter()]
        [ValidateSet('Active', 'Eligible', 'Provisioned')]
        [string]$Status = 'Active',

        # WHEN
        [Parameter()]
        [AllowNull()]
        [System.Nullable[datetime]]$CreatedDateTime,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[datetime]]$StartDateTime,

        [Parameter()]
        [AllowNull()]
        [System.Nullable[datetime]]$EndDateTime,

        # META
        [Parameter()]
        [string]$ResourceDisplayName = '',

        [Parameter()]
        [ValidateSet('', 'AllPrincipals', 'Principal')]
        [string]$ConsentType = ''
    )

    Write-Verbose "Creating PA.Assignment: $PrincipalType '$PrincipalId' -> '$RoleName' ($Source/$AssignmentType)"

    $result = [PSCustomObject]@{
        PSTypeName          = 'PA.Assignment'
        PrincipalId         = $PrincipalId
        PrincipalDisplayName = $PrincipalDisplayName
        PrincipalType       = $PrincipalType
        RoleDefinitionId    = $RoleDefinitionId
        RoleName            = $RoleName
        RoleType            = $RoleType
        Scope               = $Scope
        ScopeType           = $ScopeType
        Source              = $Source
        AssignmentType      = $AssignmentType
        Status              = $Status
        CreatedDateTime     = $CreatedDateTime
        StartDateTime       = $StartDateTime
        EndDateTime         = $EndDateTime
        ResourceDisplayName = $ResourceDisplayName
        ConsentType         = $ConsentType
    }

    return $result
}
