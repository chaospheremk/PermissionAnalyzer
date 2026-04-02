---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Get-PAActivitySignal/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Get-PAActivitySignal
---

# Get-PAActivitySignal

## SYNOPSIS

Collects activity signals per principal from Log Analytics or Graph API.

## SYNTAX

### __AllParameterSets

```
Get-PAActivitySignal [-Session] <psobject> [-Assignments] <psobject[]> [[-LookbackDays] <int>]
 [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Queries sign-in and role-related activity for each unique principal
found in the supplied assignments.
Returns PA.ActivityProfile objects
with last sign-in datetime, role activity evidence, and computed
activity tier (0–2).

Two data paths are supported:
- Log Analytics (preferred): KQL queries across SigninLogs,
  AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs,
  AADManagedIdentitySignInLogs, AuditLogs, and AzureActivity.
  Supports up to 365-day lookback.
- Graph API (fallback): user.signInActivity property and
  directoryAudits endpoint.
Limited to 30-day lookback for audit
  data.
No SP sign-in coverage in v1.0.

Activity tiers: 0 = Active (sign-in + role activity), 1 = NoSignIn,
2 = NoRoleActivity.
Tier 3 (action gap) is computed by
Find-PALeastPrivilegeGap.

## EXAMPLES

### EXAMPLE 1

$sessionParams = @{
    TenantId    = '<tenant-id>'
    WorkspaceId = '<workspace-id>'
}
$session = Connect-PASession @sessionParams
$assignments = ($entraResult.Items + $rbacResult.Items)
$result = Get-PAActivitySignal -Session $session -Assignments $assignments
$result.Items.Where({ $_.ActivityTier -ge 1 })

Collects activity signals and filters to inactive principals.

### EXAMPLE 2

$signalParams = @{
    Session      = $session
    Assignments  = $allAssignments
    LookbackDays = 180
}
$result = Get-PAActivitySignal @signalParams
$result.Items | Group-Object ActivityTier | Select-Object Name, Count

Collects with 180-day lookback and shows tier distribution.

## PARAMETERS

### -Assignments

Array of PA.Assignment objects from collectors.
Used to extract
unique principal IDs and types.

```yaml
Type: System.Management.Automation.PSObject[]
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -LookbackDays

Number of days for the activity lookback window.
Defaults to 90.
Capped at 30 for Graph API path (directoryAudits limitation).

```yaml
Type: System.Int32
DefaultValue: 90
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 2
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -Session

PA.Session object from Connect-PASession.
If WorkspaceId is set,
Log Analytics path is used; otherwise Graph API fallback.

```yaml
Type: System.Management.Automation.PSObject
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 0
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None.



## OUTPUTS

### PSCustomObject (PA.CollectorResult)



## NOTES

Part of the PermissionAnalyzer module.


## RELATED LINKS

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Get-PAActivitySignal/)
