# User Guide

This guide walks through running a permission audit from start to finish, interpreting results, and taking action on findings.

## Before You Start

### Install Required Modules

```powershell
Install-Module Microsoft.Graph.Authentication, Az.Accounts, Az.Resources, Az.OperationalInsights -Scope CurrentUser
```

### Grant Permissions

The module needs read-only access to your tenant:

**Microsoft Graph** -- grant these application or delegated permissions:

- `AuditLog.Read.All`
- `Directory.Read.All`
- `RoleManagement.Read.All`
- `Application.Read.All`
- `User.Read.All`

**Azure RBAC** -- assign these roles:

- `Reader` on all subscriptions you want to audit
- `Log Analytics Reader` on your workspace (if using Log Analytics)

### Log Analytics Setup (Recommended)

Log Analytics provides **365-day lookback** and **service principal sign-in coverage**. Without it, the module falls back to Graph API with a 30-day cap and no SP sign-in data.

To verify your setup:

1. **Entra admin center** > **Identity** > **Monitoring & health** > **Diagnostic settings**
2. Ensure these categories are sending to your workspace:
    - `SignInLogs`
    - `NonInteractiveUserSignInLogs`
    - `ServicePrincipalSignInLogs`
    - `ManagedIdentitySignInLogs`
    - `AuditLogs`
3. **Azure Monitor** > **Activity log** > **Diagnostic settings** -- ensure `AzureActivity` is routed to the same workspace

## Running an Audit

### One-Command Audit

```powershell
Import-Module ./PermissionAnalyzer.psd1

$auditParams = @{
    TenantId        = '<tenant-id>'
    WorkspaceId     = '<workspace-customer-id>'
    OutputDirectory = './audit-output'
    Format          = @('CSV', 'JSON', 'HTML')
}
$audit = Invoke-PAPermissionAudit @auditParams -Verbose
```

The orchestrator runs 7 stages automatically:

1. **Connect** -- validates Graph and Azure connections
2. **Collect** -- gathers assignments from all 4 permission planes
3. **Activity Signals** -- queries sign-in and audit logs
4. **Analyze** -- runs 3 analyzers to produce findings
5. **Report** -- generates CSV, JSON, and HTML files
6. **Remediate** -- generates remediation scripts (use `-SkipRemediation` to skip)
7. **Validate** -- re-checks findings against live data (use `-SkipValidation` to skip)

### Connecting Manually

If you prefer to connect before running the audit:

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All","RoleManagement.Read.All","Application.Read.All","User.Read.All"
Connect-AzAccount -TenantId '<tenant-id>'
```

The orchestrator will detect existing connections and reuse them.

### Tuning Parameters

| Parameter | Default | What it controls |
|---|---|---|
| `-LookbackDays` | 90 | How far back to check for activity |
| `-InactivityThresholdDays` | 90 | Days of inactivity before a Tier 0 principal triggers a finding |
| `-GapThreshold` | 0.5 | How much of a role must be unused to trigger an over-privileged finding (0.5 = 50%) |
| `-MinimumGroupSize` | 3 | How many principals must share a role+scope before suggesting group consolidation |

Example with aggressive thresholds:

```powershell
$auditParams = @{
    TenantId                = '<tenant-id>'
    WorkspaceId             = '<workspace-customer-id>'
    OutputDirectory         = './audit-output'
    LookbackDays            = 180
    InactivityThresholdDays = 30
    GapThreshold            = 0.3
    MinimumGroupSize        = 2
}
$audit = Invoke-PAPermissionAudit @auditParams -Verbose
```

## Understanding Results

### The Audit Result

```powershell
$audit.TotalAssignments
$audit.TotalFindings
$audit.FindingsBySeverity
$audit.FindingsByCategory
$audit.Warnings
$audit.Errors
```

### Findings

Each finding represents an actionable recommendation:

```powershell
# View all findings
$audit.AnalyzerResults.UnusedAssignment.Items

# Filter to critical/high
$allFindings = @(
    $audit.AnalyzerResults.UnusedAssignment.Items
    $audit.AnalyzerResults.LeastPrivilegeGap.Items
    $audit.AnalyzerResults.GroupConsolidation.Items
)
$allFindings.Where({ $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' })
```

### Severity Levels

| Severity | Meaning |
|---|---|
| **Critical** | No sign-in + critical role (e.g., Global Admin with no sign-in in 90 days) |
| **High** | No sign-in + standard role, or no role activity + critical role |
| **Medium** | No role activity + standard role, or stale activity + critical role |
| **Low** | Stale activity + standard role, or group consolidation opportunity |
| **Info** | Informational (e.g., small group consolidation opportunities) |

### Activity Tiers

| Tier | Condition | Implication |
|---|---|---|
| **Tier 0** | Active -- recent sign-in AND role activity | Assignment is in use |
| **Tier 1** | No sign-in in the lookback window | Strongest signal of an unused assignment |
| **Tier 2** | Signs in but no role-related operations | Assignment may be unused |
| **Tier 3** | Action gap -- uses some permissions but not all | Over-privileged |

## Reports

### HTML Report

```powershell
start (Get-ChildItem ./audit-output/*.html | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

Features: dark mode toggle, resizable columns, severity badges, sorted by severity.

### CSV Report

```powershell
$csv = Import-Csv ./audit-output/PA-Report-*.csv
$csv.Where({ $_.Severity -eq 'Critical' })
```

The `DetailsJson` column contains serialized JSON with additional context.

### JSON Report

```powershell
$json = Get-Content ./audit-output/PA-Report-*.json -Raw | ConvertFrom-Json
$json.FindingCount
$json.SeverityCounts
```

## Remediation Scripts

Generated scripts are grouped by action type:

| Script | Content |
|---|---|
| `PA-Remediation-Remove-*.ps1` | Commented-out removal commands per source type |
| `PA-Remediation-Downgrade-*.ps1` | Advisory with namespace analysis |
| `PA-Remediation-ConsolidateToGroup-*.ps1` | Group creation + member addition |
| `PA-Remediation-ReviewEligible-*.ps1` | Advisory for manual PIM review |

**All destructive commands are commented out by default.** Review the WhatIf preview before uncommenting.

```powershell
# Review
./audit-output/PA-Remediation-Remove-*.ps1 -WhatIf

# After review, edit to uncomment specific commands, then run
./audit-output/PA-Remediation-Remove-*.ps1
```

## Re-Validating Findings

Before acting on old findings, re-validate them:

```powershell
$session = Connect-PASession -TenantId '<tenant-id>'
$validationParams = @{
    Findings = $allFindings
    Session  = $session
}
$validation = Test-PAFindingAccuracy @validationParams

$validation.Items.Where({ $_.IsStillValid })
$validation.Items.Where({ -not $_.IsStillValid })
```

## GCC High and DoD

```powershell
$auditParams = @{
    TenantId        = '<tenant-id>'
    Environment     = 'USGov'
    OutputDirectory = './audit-output'
}
$audit = Invoke-PAPermissionAudit @auditParams -Verbose
```

Supported values: `Global` (default), `USGov`, `USGovDoD`.

## Troubleshooting

### "No enabled subscriptions found"

Run `Connect-AzAccount -TenantId '<tenant-id>'` with MFA before the audit, or pass explicit IDs: `-SubscriptionId @('<sub-id-1>')`.

### "SPs have no sign-in data on Graph API path"

Use `-WorkspaceId` to enable Log Analytics which queries `AADServicePrincipalSignInLogs`.

### Partial collector results

Check `$audit.Warnings` for details. Common causes: insufficient permissions, rate limiting, network timeouts.

### Pre-flight check

```powershell
./scripts/Test-IntegrationReadiness.ps1
```
