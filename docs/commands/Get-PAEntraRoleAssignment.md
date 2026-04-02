---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: ''
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Get-PAEntraRoleAssignment
---

# Get-PAEntraRoleAssignment

## SYNOPSIS

Collects Entra ID directory role assignments from a tenant.

## SYNTAX

### __AllParameterSets

```
Get-PAEntraRoleAssignment [-Session] <psobject> [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Queries Microsoft Graph for all active directory role assignments
(unifiedRoleAssignment), enriches each with role definition metadata
and principal display names, normalizes into PA.Assignment objects,
and wraps the result in a PA.CollectorResult.

Uses $expand=principal to resolve principal types and display names
in a single paginated call.
Falls back to batch resolution via
Resolve-PAPrincipal if the expand is not available.

All returned assignments have Source='EntraRole' and
AssignmentType='Direct'.
PIM eligible assignments are collected
separately by Get-PAPimEligibility.

## EXAMPLES

### EXAMPLE 1

'
$result = Get-PAEntraRoleAssignment -Session $session
$result.Items | Format-Table PrincipalDisplayName, RoleName, Scope

Collects all Entra role assignments and displays them in a table.

### EXAMPLE 2

'
$result = Get-PAEntraRoleAssignment -Session $session
$result.Status    # Complete, Partial, or Failed
$result.ItemCount # number of assignments found

Checks the collection status and item count.

## PARAMETERS

### -Session

PA.Session object from Connect-PASession.
Provides auth context
for Graph API calls.

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

## OUTPUTS

### PSCustomObject (PA.CollectorResult)



## NOTES

## RELATED LINKS



