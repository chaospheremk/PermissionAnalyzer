---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PALeastPrivilegeGap/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Find-PALeastPrivilegeGap
---

# Find-PALeastPrivilegeGap

## SYNOPSIS

Identifies over-privileged access by comparing granted vs used permissions.

## SYNTAX

### __AllParameterSets

```
Find-PALeastPrivilegeGap [-Assignments] <psobject[]> [-ActivityProfiles] <psobject[]>
 [[-GapThreshold] <double>] [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Analyzes PA.Assignment objects against PA.ActivityProfile data to identify
assignments where the principal uses only a fraction of their granted
permissions.
Compares granted and used actions at the namespace level
(first two path segments) and generates PA.Finding objects when the gap
ratio meets or exceeds the threshold.

Requires GrantedActions and UsedActions to be populated in the activity
profiles.
Profiles with empty action data are skipped with a warning.

## EXAMPLES

### EXAMPLE 1

$findings = Find-PALeastPrivilegeGap -Assignments $assignments -ActivityProfiles $actProfiles

### EXAMPLE 2

$findingParams = @{
    Assignments      = $assignments
    ActivityProfiles = $actProfiles
    GapThreshold     = 0.3
}
$findings = Find-PALeastPrivilegeGap @findingParams

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

### -GapThreshold

Minimum gap ratio (0.0–1.0) to generate a finding.
A value of 0.5 means
the principal must be using less than 50% of their granted namespaces.
Defaults to 0.5.

```yaml
Type: System.Double
DefaultValue: 0.5
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

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Find-PALeastPrivilegeGap/)
