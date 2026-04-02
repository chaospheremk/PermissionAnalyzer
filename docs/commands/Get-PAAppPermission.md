---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: ''
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Get-PAAppPermission
---

# Get-PAAppPermission

## SYNOPSIS

Collects application permissions and delegated permission grants from a tenant.

## SYNTAX

### __AllParameterSets

```
Get-PAAppPermission [-Session] <psobject> [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Queries Microsoft Graph for all application permissions (appRoleAssignments)
and delegated permission grants (oauth2PermissionGrants).
Resolves permission
names from resource service principal appRoles collections, normalizes into
PA.Assignment objects, and wraps the result in a PA.CollectorResult.

appRoleAssignments require per-service-principal iteration (no tenant-wide
endpoint).
oauth2PermissionGrants use a single tenant-wide call.

All returned assignments have Source='AppPermission'.
AppRole assignments
use AssignmentType='AppRole', delegated grants use
AssignmentType='DelegatedGrant'.

## EXAMPLES

### EXAMPLE 1

'
$result = Get-PAAppPermission -Session $session
$result.Items | Where-Object AssignmentType -eq 'AppRole'

Collects all app permissions and filters to application role assignments.

### EXAMPLE 2

'
$result = Get-PAAppPermission -Session $session
$result.Items | Group-Object AssignmentType | Select-Object Name, Count

Shows the count of permissions by assignment type.

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



