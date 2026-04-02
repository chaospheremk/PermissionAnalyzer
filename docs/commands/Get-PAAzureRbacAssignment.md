---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Get-PAAzureRbacAssignment/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Get-PAAzureRbacAssignment
---

# Get-PAAzureRbacAssignment

## SYNOPSIS

Collects Azure RBAC role assignments across in-scope subscriptions.

## SYNTAX

### __AllParameterSets

```
Get-PAAzureRbacAssignment [-Session] <psobject> [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Queries Azure RBAC for all role assignments across the subscriptions
specified in the PA.Session object.
Enriches each assignment with
BuiltIn/Custom classification from role definitions, maps scope
types, normalizes into PA.Assignment objects, and wraps the result
in a PA.CollectorResult.

Iterates per subscription with independent error handling so that
a failure on one subscription does not prevent collection from
others.
Deduplicates inherited management group assignments that
appear under multiple subscriptions.

All returned assignments have Source='AzureRbac',
AssignmentType='Direct', and Status='Active'.

## EXAMPLES

### EXAMPLE 1

'
$result = Get-PAAzureRbacAssignment -Session $session
$result.Items | Format-Table PrincipalDisplayName, RoleName, Scope

Collects all Azure RBAC assignments and displays them in a table.

### EXAMPLE 2

'
$result = Get-PAAzureRbacAssignment -Session $session
$result.Items | Group-Object ScopeType | Select-Object Name, Count

Shows the count of assignments by scope type.

## PARAMETERS

### -Session

PA.Session object from Connect-PASession.
Provides SubscriptionIds
for RBAC iteration.

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

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Get-PAAzureRbacAssignment/)
