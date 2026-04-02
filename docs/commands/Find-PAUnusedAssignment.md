---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PAUnusedAssignment/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Find-PAUnusedAssignment
---

# Find-PAUnusedAssignment

## SYNOPSIS

Identifies unused role assignments based on activity analysis.

## SYNTAX

### __AllParameterSets

```
Find-PAUnusedAssignment [-Assignments] <psobject[]> [-ActivityProfiles] <psobject[]>
 [[-InactivityThresholdDays] <int>] [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Analyzes PA.Assignment objects against PA.ActivityProfile data to identify
assignments where the principal shows no sign-in (Tier 1), no role-related
activity (Tier 2), or stale role usage exceeding the inactivity threshold
(Tier 0 threshold breach).
Each unused assignment produces a PA.Finding with
severity scaled by activity tier and role criticality.

## EXAMPLES

### EXAMPLE 1

$findings = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles $actProfiles

### EXAMPLE 2

$findingParams = @{
    Assignments            = $assignments
    ActivityProfiles       = $actProfiles
    InactivityThresholdDays = 30
}
$findings = Find-PAUnusedAssignment @findingParams

## PARAMETERS

### -ActivityProfiles

Array of PA.ActivityProfile objects from Get-PAActivitySignal.

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

### -InactivityThresholdDays

Number of days without role activity before a Tier 0 principal triggers a
finding.
Defaults to 90.

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

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PAUnusedAssignment/)
