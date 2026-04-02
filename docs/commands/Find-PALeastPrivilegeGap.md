---
external help file:
Module Name:
online version:
schema: 2.0.0
---

# Find-PALeastPrivilegeGap

## SYNOPSIS
Identifies over-privileged access by comparing granted vs used permissions.

## SYNTAX

```
Find-PALeastPrivilegeGap [-Assignments] <PSObject[]> [-ActivityProfiles] <PSObject[]>
 [[-GapThreshold] <Double>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

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
```
$findings = Find-PALeastPrivilegeGap -Assignments $assignments -ActivityProfiles $profiles
```

### EXAMPLE 2
```
$findings = Find-PALeastPrivilegeGap -Assignments $assignments -ActivityProfiles $profiles -GapThreshold 0.3
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

### -GapThreshold
Minimum gap ratio (0.0-1.0) to generate a finding.
A value of 0.5 means
the principal must be using less than 50% of their granted namespaces.
Defaults to 0.5.

```yaml
Type: Double
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: 0.5
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
