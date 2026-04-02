---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: ''
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Get-PAPimEligibility
---

# Get-PAPimEligibility

## SYNOPSIS

Collects PIM eligible assignments from Entra ID and Azure RBAC.

## SYNTAX

### __AllParameterSets

```
Get-PAPimEligibility [-Session] <psobject> [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Queries two independent sources for PIM eligible assignments:

1.
Entra PIM — Microsoft Graph roleEligibilityScheduleInstances
   for directory role eligibilities.
Uses $expand=principal to
   resolve principal types and display names.

2.
Azure PIM — Get-AzRoleEligibilityScheduleInstance for Azure
   RBAC eligibilities across all in-scope subscriptions.

All returned assignments have AssignmentType='Eligible' and
Status='Eligible'.
Entra assignments use Source='PimEntra',
Azure assignments use Source='PimAzure'.

Failure of one source does not prevent collection from the other.
Both failing produces a Failed result; one failing produces Partial.

## EXAMPLES

### EXAMPLE 1

'
$result = Get-PAPimEligibility -Session $session
$result.Items | Where-Object Source -eq 'PimEntra'

Collects all PIM eligible assignments and filters to Entra PIM.

### EXAMPLE 2

'
$result = Get-PAPimEligibility -Session $session
$result.Items | Group-Object Source | Select-Object Name, Count

Shows the count of eligible assignments by source.

## PARAMETERS

### -Session

PA.Session object from Connect-PASession.
Provides auth context
and SubscriptionIds for Azure PIM iteration.

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



