---
external help file:
Module Name:
online version:
schema: 2.0.0
---

# Find-PAGroupConsolidation

## SYNOPSIS
Identifies opportunities to consolidate individual role assignments into groups.

## SYNTAX

```
Find-PAGroupConsolidation [-Assignments] <PSObject[]> [[-MinimumGroupSize] <Int32>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Analyzes PA.Assignment objects to find patterns where multiple principals
share the same role at the same scope, indicating that a group-based
assignment would simplify management.
Only considers User and
ServicePrincipal assignments (groups are already consolidated).
Generates one PA.Finding per consolidation opportunity.

## EXAMPLES

### EXAMPLE 1
```
$findings = Find-PAGroupConsolidation -Assignments $assignments
```

### EXAMPLE 2
```
$findings = Find-PAGroupConsolidation -Assignments $assignments -MinimumGroupSize 5
```

## PARAMETERS

### -Assignments
Array of PA.Assignment objects from collectors.

```yaml
Type: PSObject[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MinimumGroupSize
Minimum number of distinct principals sharing the same role+scope before
a consolidation finding is generated.
Defaults to 3.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 3
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### PSCustomObject (PA.CollectorResult) wrapping PA.Finding items.
## NOTES

## RELATED LINKS
