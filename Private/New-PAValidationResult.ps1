#Requires -Version 7.0

function New-PAValidationResult {
    <#
    .SYNOPSIS
        Creates a validation result object for a previously reported finding.
    .DESCRIPTION
        Factory function that returns a PA.ValidationResult object representing
        the outcome of re-validating a finding against current tenant state.
        Used by Test-PAFindingAccuracy to confirm or invalidate prior findings.
    .PARAMETER FindingId
        The deterministic FindingId of the original finding being validated.
    .PARAMETER OriginalCategory
        Category of the original finding.
    .PARAMETER OriginalSeverity
        Severity of the original finding.
    .PARAMETER IsStillValid
        Whether the finding still applies to the current tenant state.
    .PARAMETER CurrentState
        Brief description of the current state observed during validation.
    .PARAMETER ValidatedAt
        UTC timestamp when validation was performed. Defaults to current UTC time.
    .PARAMETER Notes
        Optional notes about the validation outcome.
    .EXAMPLE
        $validationParams = @{
            FindingId        = 'a1b2c3d4e5f6a7b8'
            OriginalCategory = 'UnusedAssignment'
            OriginalSeverity = 'High'
            IsStillValid     = $true
            CurrentState     = 'Principal still has no sign-in activity'
        }
        $validation = New-PAValidationResult @validationParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.ValidationResult)
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
        [string]$FindingId,

        [Parameter(Mandatory)]
        [ValidateSet('UnusedAssignment', 'OverPrivileged', 'GroupConsolidation')]
        [string]$OriginalCategory,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$OriginalSeverity,

        [Parameter(Mandatory)]
        [bool]$IsStillValid,

        [Parameter()]
        [string]$CurrentState = '',

        [Parameter()]
        [datetime]$ValidatedAt = [datetime]::UtcNow,

        [Parameter()]
        [string]$Notes = ''
    )

    Write-Verbose "Creating PA.ValidationResult for FindingId '$FindingId' (StillValid: $IsStillValid)"

    $result = [PSCustomObject]@{
        PSTypeName       = 'PA.ValidationResult'
        FindingId        = $FindingId
        OriginalCategory = $OriginalCategory
        OriginalSeverity = $OriginalSeverity
        IsStillValid     = $IsStillValid
        CurrentState     = $CurrentState
        ValidatedAt      = $ValidatedAt
        Notes            = $Notes
    }

    return $result
}
