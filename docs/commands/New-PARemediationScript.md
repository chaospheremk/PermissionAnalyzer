---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/New-PARemediationScript/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: New-PARemediationScript
---

# New-PARemediationScript

## SYNOPSIS

Generates runnable remediation scripts from analysis findings.

## SYNTAX

### __AllParameterSets

```
New-PARemediationScript [-Findings] <psobject[]> [-OutputDirectory] <string> [[-RunId] <string>]
 [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Takes an array of PA.Finding objects and generates PowerShell remediation
scripts grouped by RemediationAction type.
Each script includes -WhatIf
support and has destructive commands commented out by default for safe
manual review.
Returns a PA.RemediationResult with script paths and
operation counts.

## EXAMPLES

### EXAMPLE 1

$result = New-PARemediationScript -Findings $findings -OutputDirectory './remediation'

### EXAMPLE 2

$scriptParams = @{
    Findings        = $allFindings
    OutputDirectory = './remediation'
    RunId           = $session.RunId
}
$result = New-PARemediationScript @scriptParams

## PARAMETERS

### -Findings

Array of PA.Finding objects from Find-PAUnusedAssignment,
Find-PALeastPrivilegeGap, and/or Find-PAGroupConsolidation.

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

### -OutputDirectory

Directory path where remediation scripts will be written.
Created if
it does not exist.

```yaml
Type: System.String
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

### -RunId

Identifier used in output file names for uniqueness.
Defaults to a
UTC timestamp (yyyyMMdd-HHmmss).
Pass the session RunId for
correlation with other pipeline outputs.

```yaml
Type: System.String
DefaultValue: "[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')"
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

### PSCustomObject (PA.RemediationResult)



## NOTES

Part of the PermissionAnalyzer module.


## RELATED LINKS

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/New-PARemediationScript/)
