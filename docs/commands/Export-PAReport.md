---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Export-PAReport/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Export-PAReport
---

# Export-PAReport

## SYNOPSIS

Exports findings to CSV, JSON, and/or HTML report files.

## SYNTAX

### __AllParameterSets

```
Export-PAReport [-Findings] <psobject[]> [-OutputDirectory] <string> [[-Format] <string[]>]
 [[-RunId] <string>] [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Takes an array of PA.Finding objects from the analysis phase and writes
structured report files to the specified output directory.
Computes
summary statistics (counts by severity and category) and generates one
file per requested format.
Returns a PA.ReportResult object containing
output file paths and summary counts.

## EXAMPLES

### EXAMPLE 1

$report = Export-PAReport -Findings $findings -OutputDirectory './reports'

### EXAMPLE 2

$reportParams = @{
    Findings        = $allFindings
    OutputDirectory = './reports'
    Format          = @('CSV', 'JSON', 'HTML')
    RunId           = $session.RunId
}
$report = Export-PAReport @reportParams

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

### -Format

One or more output formats to generate.
Defaults to CSV and JSON.

```yaml
Type: System.String[]
DefaultValue: "@('CSV', 'JSON')"
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

### -OutputDirectory

Directory path where report files will be written.
Created if it does
not exist.

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
  Position: 3
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

### PSCustomObject (PA.ReportResult)



## NOTES

Part of the PermissionAnalyzer module.


## RELATED LINKS

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Export-PAReport/)
