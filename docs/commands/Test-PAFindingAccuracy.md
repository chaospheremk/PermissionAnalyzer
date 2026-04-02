---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Test-PAFindingAccuracy/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Test-PAFindingAccuracy
---

# Test-PAFindingAccuracy

## SYNOPSIS

Re-validates findings against current tenant state.

## SYNTAX

### __AllParameterSets

```
Test-PAFindingAccuracy [-Findings] <psobject[]> [-Session] <psobject> [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Takes an array of PA.Finding objects and checks whether each finding's
underlying assignment still exists by querying live data.
Groups findings
by Source, pre-fetches current assignments in batch, then validates each
finding against the fetched data.
Returns a PA.CollectorResult wrapping
PA.ValidationResult items.

## EXAMPLES

### EXAMPLE 1

$validation = Test-PAFindingAccuracy -Findings $findings -Session $session

### EXAMPLE 2

$validationParams = @{
    Findings = $allFindings
    Session  = $session
}
$validation = Test-PAFindingAccuracy @validationParams

## PARAMETERS

### -Findings

Array of PA.Finding objects to re-validate.

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

### -Session

PA.Session object from Connect-PASession providing auth context.

```yaml
Type: System.Management.Automation.PSObject
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable,
-InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable,
-ProgressAction, -Verbose, -WarningAction, and -WarningVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None.



## OUTPUTS

### PSCustomObject (PA.CollectorResult) wrapping PA.ValidationResult items.



## NOTES

Part of the PermissionAnalyzer module.


## RELATED LINKS

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Test-PAFindingAccuracy/)
