---
document type: cmdlet
external help file: PermissionAnalyzer-Help.xml
HelpUri: ''
Locale: en-US
Module Name: PermissionAnalyzer
ms.date: 01/01/1970
PlatyPS schema version: 2024-05-01
title: Connect-PASession
---

# Connect-PASession

## SYNOPSIS

Establishes Graph and Azure connections and returns a PA.Session object.

## SYNTAX

### __AllParameterSets

```
Connect-PASession [-TenantId] <string> [[-WorkspaceId] <string>] [[-SubscriptionId] <string[]>]
 [[-Environment] <string>] [<CommonParameters>]
```

## ALIASES

None.
## DESCRIPTION

Entry point for all PermissionAnalyzer operations.
Validates or
establishes connections to Microsoft Graph and Azure, discovers
in-scope subscriptions, and returns a session object that downstream
functions use for auth context.

If an existing Graph or Azure connection is detected, it is reused
after validating the TenantId matches.
If no connection exists, an
interactive login is initiated.

GCC High and DoD environments are supported via the -Environment
parameter (ADR-003).

## EXAMPLES

### EXAMPLE 1

'

Connects to the default (Global) environment and discovers all
enabled subscriptions.

### EXAMPLE 2

$sessionParams = @{
    TenantId    = '<tenant-id>'
    WorkspaceId = '<workspace-id>'
    Environment = 'USGov'
}
$session = Connect-PASession @sessionParams

Connects to a GCC High environment with a Log Analytics workspace.

### EXAMPLE 3

$sessionParams = @{
    TenantId       = '<tenant-id>'
    SubscriptionId = @('<sub-id-1>', '<sub-id-2>')
}
$session = Connect-PASession @sessionParams

Scopes the audit to two specific subscriptions.

## PARAMETERS

### -Environment

Cloud environment for Graph and Azure connections.
Defaults to
Global for broadest compatibility.

```yaml
Type: System.String
DefaultValue: Global
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

### -SubscriptionId

One or more Azure subscription IDs to scope the RBAC audit.
When
omitted, all enabled subscriptions in the tenant are discovered
automatically.

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

Entra tenant ID to audit.
Must match the connected Graph and Azure
contexts.
If no connection exists, this tenant is used for the
initial login.

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
When
omitted, activity signals fall back to Graph API direct queries
(30-day lookback limit).

```yaml
Type: System.String
DefaultValue: ''
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

## OUTPUTS

### PSCustomObject (PA.Session)



## NOTES

## RELATED LINKS



