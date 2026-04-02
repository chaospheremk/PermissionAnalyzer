---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PAGroupConsolidation/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Find-PAGroupConsolidation
---

# Find-PAGroupConsolidation

## SYNOPSIS

Identifies opportunities to consolidate individual role assignments into groups.

## SYNTAX

### __AllParameterSets

```
Find-PAGroupConsolidation [-Assignments] <psobject[]> [[-MinimumGroupSize] <int>]
 [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Analyzes PA.Assignment objects to find patterns where multiple principals
share the same role at the same scope, indicating that a group-based
assignment would simplify management.
Only considers User and
ServicePrincipal assignments (groups are already consolidated).
Generates one PA.Finding per consolidation opportunity.

## EXAMPLES

### EXAMPLE 1

$findings = Find-PAGroupConsolidation -Assignments $assignments

### EXAMPLE 2

$findings = Find-PAGroupConsolidation -Assignments $assignments -MinimumGroupSize 5

## PARAMETERS

### -Assignments

Array of PA.Assignment objects from collectors.

```yaml
Type: System.Management.Automation.PSObject[]
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

### -MinimumGroupSize

Minimum number of distinct principals sharing the same role+scope before
a consolidation finding is generated.
Defaults to 3.

```yaml
Type: System.Int32
DefaultValue: 3
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 1
  IsRequired: false
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

### PSCustomObject (PA.CollectorResult) wrapping PA.Finding items.



## NOTES

Part of the PermissionAnalyzer module.


## RELATED LINKS

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PAGroupConsolidation/)
