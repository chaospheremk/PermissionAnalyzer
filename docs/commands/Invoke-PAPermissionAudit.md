---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: https://chaospheremk.github.io/PermissionAnalyzer/commands/Invoke-PAPermissionAudit/
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Invoke-PAPermissionAudit
---

# Invoke-PAPermissionAudit

## SYNOPSIS

Runs a complete permission audit pipeline.

## SYNTAX

### __AllParameterSets

```
Invoke-PAPermissionAudit [-TenantId] <string> [[-Environment] <string>]
 [[-SubscriptionId] <string[]>] [[-WorkspaceId] <string>] [-OutputDirectory] <string>
 [[-LookbackDays] <int>] [[-InactivityThresholdDays] <int>] [[-GapThreshold] <double>]
 [[-MinimumGroupSize] <int>] [[-Format] <string[]>] [-SkipRemediation] [-SkipValidation]
 [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

End-to-end orchestrator that connects to a tenant, collects all permission
assignments across four planes (Entra roles, PIM, Azure RBAC, app permissions),
gathers activity signals, runs three analyzers (unused assignments, least
privilege gaps, group consolidation), generates reports and remediation scripts,
and optionally re-validates findings.
Each stage is independently error-isolated
so a single failure does not prevent the remaining pipeline from completing.
The module never executes changes — it produces findings, reports, and scripts
for manual review.

## EXAMPLES

### EXAMPLE 1

' -OutputDirectory './audit-output'

### EXAMPLE 2

$auditParams = @{
    TenantId        = '<tenant-id>'
    WorkspaceId     = '<workspace-id>'
    OutputDirectory = './audit-output'
    Format          = @('CSV', 'JSON', 'HTML')
    LookbackDays    = 180
}
$audit = Invoke-PAPermissionAudit @auditParams

### EXAMPLE 3

$auditParams = @{
    TenantId              = '<tenant-id>'
    OutputDirectory       = './audit-output'
    InactivityThresholdDays = 30
    GapThreshold          = 0.3
    MinimumGroupSize      = 2
    SkipValidation        = $true
}
$audit = Invoke-PAPermissionAudit @auditParams

## PARAMETERS

### -Environment

Cloud environment.
Defaults to Global.

```yaml
Type: System.String
DefaultValue: Global
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

### -Format

Output formats for the report.
Defaults to CSV and JSON.

```yaml
Type: System.String[]
DefaultValue: "@('CSV', 'JSON')"
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 9
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -GapThreshold

Minimum gap ratio (0.0–1.0) for least privilege gap findings.
Defaults to 0.5.

```yaml
Type: System.Double
DefaultValue: 0.5
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 7
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -InactivityThresholdDays

Days without role activity before a Tier 0 principal triggers an unused
assignment finding.
Defaults to 90.

```yaml
Type: System.Int32
DefaultValue: 90
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 6
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -LookbackDays

Activity lookback window in days.
Defaults to 90.

```yaml
Type: System.Int32
DefaultValue: 90
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 5
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -MinimumGroupSize

Minimum principals sharing a role+scope for group consolidation.
Defaults to 3.

```yaml
Type: System.Int32
DefaultValue: 3
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 8
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -OutputDirectory

Directory path where reports and remediation scripts are written.

```yaml
Type: System.String
DefaultValue: ''
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: 4
  IsRequired: true
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SkipRemediation

Skip remediation script generation.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: False
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SkipValidation

Skip finding re-validation against live data.

```yaml
Type: System.Management.Automation.SwitchParameter
DefaultValue: False
SupportsWildcards: false
Aliases: []
ParameterSets:
- Name: (All)
  Position: Named
  IsRequired: false
  ValueFromPipeline: false
  ValueFromPipelineByPropertyName: false
  ValueFromRemainingArguments: false
DontShow: false
AcceptedValues: []
HelpMessage: ''
```

### -SubscriptionId

Explicit list of Azure subscription IDs to scope.
If empty, all enabled
subscriptions are auto-discovered.

```yaml
Type: System.String[]
DefaultValue: '@()'
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

### -TenantId

Entra ID tenant identifier.

```yaml
Type: System.String
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

### -WorkspaceId

Log Analytics workspace ID for activity signal collection.
If empty, falls
back to Graph API direct queries (30-day cap).

```yaml
Type: System.String
DefaultValue: ''
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

### PSCustomObject (PA.AuditResult)



## NOTES

Part of the PermissionAnalyzer module.


## RELATED LINKS

- [](https://chaospheremk.github.io/PermissionAnalyzer/commands/Invoke-PAPermissionAudit/)
