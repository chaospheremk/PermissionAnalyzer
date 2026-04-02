---
external help file:
Module Name:
online version:
schema: 2.0.0
---

# Find-PAUnusedAssignment

## SYNOPSIS
Identifies unused role assignments based on activity analysis.

## SYNTAX

```
Find-PAUnusedAssignment [-Assignments] <PSObject[]> [-ActivityProfiles] <PSObject[]>
 [[-InactivityThresholdDays] <Int32>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Analyzes PA.Assignment objects against PA.ActivityProfile data to identify
assignments where the principal shows no sign-in (Tier 1), no role-related
activity (Tier 2), or stale role usage exceeding the inactivity threshold
(Tier 0 threshold breach).
Each unused assignment produces a PA.Finding with
severity scaled by activity tier and role criticality.

## EXAMPLES

### EXAMPLE 1
```
$findings = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles $profiles
```

### EXAMPLE 2
```
$findings = Find-PAUnusedAssignment -Assignments $assignments -ActivityProfiles $profiles -InactivityThresholdDays 30
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

### -ActivityProfiles
Array of PA.ActivityProfile objects from Get-PAActivitySignal.

```yaml
Type: PSObject[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InactivityThresholdDays
Number of days without role activity before a Tier 0 principal triggers a
finding.
Defaults to 90.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: 90
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
