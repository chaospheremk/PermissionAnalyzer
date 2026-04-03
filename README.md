# PermissionAnalyzer

PowerShell 7+ module that audits Entra ID and Azure RBAC permissions across a single tenant, correlates them with activity signals, identifies unused assignments, over-privileged access, and group consolidation opportunities, then generates structured reports and runnable remediation scripts.

**The module never executes changes** — it produces findings, reports, and scripts for manual review.

## Features

- **Four permission planes**: Entra ID directory roles (built-in + custom, AU-scoped), PIM eligible assignments (Entra + Azure), Azure RBAC (management group through resource level), app registrations/API permissions (appRoles + OAuth2 grants)
- **Three analysis tiers**: no sign-in (Tier 1), no role-related activity (Tier 2), granted-vs-used action gap (Tier 3)
- **Activity signals**: Log Analytics (6 tables, up to 365-day lookback) or Graph API direct queries (30-day fallback)
- **Reports**: CSV, JSON, and HTML with dark mode toggle, severity badges, and resizable columns
- **Remediation scripts**: grouped by action type with `-WhatIf` support and commented-out destructive commands
- **Finding re-validation**: re-checks findings against live data to confirm they're still accurate
- **GCC High support**: `-Environment` parameter for USGov and USGovDoD clouds

## Prerequisites

- **PowerShell 7.0+**
- **Required modules:**
  - `Microsoft.Graph.Authentication`
  - `Az.Accounts`
  - `Az.Resources`
  - `Az.OperationalInsights`

Install them:

```powershell
Install-Module Microsoft.Graph.Authentication, Az.Accounts, Az.Resources, Az.OperationalInsights -Scope CurrentUser
```

### Required Permissions

**Microsoft Graph (application or delegated):**

| Permission | Purpose |
|---|---|
| `AuditLog.Read.All` | Sign-in and audit log queries |
| `Directory.Read.All` | Directory object resolution |
| `RoleManagement.Read.All` | Entra role assignments and PIM |
| `Application.Read.All` | App registrations and service principals |
| `User.Read.All` | User sign-in activity |

**Azure RBAC:**

| Role | Scope | Purpose |
|---|---|---|
| `Reader` | All in-scope subscriptions | Role assignments and resource enumeration |
| `Log Analytics Reader` | Workspace | Activity signal queries (if using Log Analytics) |

## Installation

```powershell
# Clone the repository
git clone https://github.com/chaospheremk/PermissionAnalyzer.git
cd PermissionAnalyzer

# Import the module
Import-Module ./PermissionAnalyzer.psd1
```

## Quick Start

### Full Audit (One Command)

```powershell
# Connect and run the complete pipeline
$auditParams = @{
    TenantId        = '<tenant-id>'
    OutputDirectory = './audit-output'
    Format          = @('CSV', 'JSON', 'HTML')
}
$audit = Invoke-PAPermissionAudit @auditParams -Verbose

# View results
$audit
$audit.FindingsBySeverity
```

### With Log Analytics (Recommended)

Log Analytics provides 365-day lookback and service principal sign-in coverage. Without it, the module falls back to Graph API with a 30-day cap and no SP sign-in data.

```powershell
$auditParams = @{
    TenantId        = '<tenant-id>'
    WorkspaceId     = '<workspace-customer-id>'
    OutputDirectory = './audit-output'
    Format          = @('CSV', 'JSON', 'HTML')
    LookbackDays    = 180
}
$audit = Invoke-PAPermissionAudit @auditParams -Verbose
```

### Individual Functions

Each pipeline stage can be run independently:

```powershell
# Connect
$session = Connect-PASession -TenantId '<tenant-id>'

# Collect (run any or all)
$entra = Get-PAEntraRoleAssignment -Session $session
$pim   = Get-PAPimEligibility -Session $session
$rbac  = Get-PAAzureRbacAssignment -Session $session
$apps  = Get-PAAppPermission -Session $session

# Merge assignments
$allAssignments = @($entra.Items) + @($pim.Items) + @($rbac.Items) + @($apps.Items)

# Activity signals
$activityParams = @{
    Session     = $session
    Assignments = $allAssignments
}
$activity = Get-PAActivitySignal @activityParams

# Analyze
$unusedParams = @{
    Assignments      = $allAssignments
    ActivityProfiles = $activity.Items
}
$unused = Find-PAUnusedAssignment @unusedParams
$gaps   = Find-PALeastPrivilegeGap @unusedParams
$groups = Find-PAGroupConsolidation -Assignments $allAssignments

# Report
$allFindings = @($unused.Items) + @($gaps.Items) + @($groups.Items)
$reportParams = @{
    Findings        = $allFindings
    OutputDirectory = './audit-output'
    Format          = @('CSV', 'JSON', 'HTML')
}
Export-PAReport @reportParams
```

## Output Types

| Type | Description |
|---|---|
| `PA.Session` | Auth context, tenant, subscriptions, run ID |
| `PA.Assignment` | Normalized WHO/WHAT/WHERE/HOW/WHEN shape from all collectors |
| `PA.ActivityProfile` | 3-tier activity evidence per principal |
| `PA.Finding` | Actionable recommendation with deterministic FindingId |
| `PA.CollectorResult` | Complete/Partial/Failed wrapper with errors and duration |
| `PA.ValidationResult` | Re-validation outcome per finding |
| `PA.ReportResult` | Output file paths and summary counts |
| `PA.RemediationResult` | Generated script paths and operation counts |
| `PA.AuditResult` | End-to-end orchestrator summary |

## Severity Matrix

### Unused Assignments (Find-PAUnusedAssignment)

| Activity Tier | Critical Role | Other Role |
|---|---|---|
| Tier 1 (no sign-in) | Critical | High |
| Tier 2 (no role activity) | High | Medium |
| Tier 0 + stale role usage | Medium | Low |

Critical roles: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Application Administrator, Cloud Application Administrator, Exchange Administrator, SharePoint Administrator, Security Administrator, User Access Administrator, Owner, Contributor.

## Known Limitations

- **Service principal sign-in data requires Log Analytics.** The Graph API v1.0 does not expose `servicePrincipalId` on the signIn resource. Without `-WorkspaceId`, SPs default to Tier 1 (no sign-in) which may produce false positives. Use Log Analytics with `AADServicePrincipalSignInLogs` enabled for accurate SP coverage.
- **Read-only app permissions appear as Tier 2.** SPs that only use read-only Graph API permissions (e.g., `Directory.Read.All`) will show as "sign-in confirmed, no role activity" because AuditLogs only capture write/modify operations. This is expected behavior, not a false positive (ADR-006).
- **Tier 3 gap analysis requires GrantedActions/UsedActions enrichment.** `Find-PALeastPrivilegeGap` gracefully degrades when `Get-PAActivitySignal` has not populated these fields (planned enhancement).
- **30-day lookback cap on Graph API path.** Without Log Analytics, activity signals are limited to 30 days via Graph API direct queries.

## Configuration Parameters

| Parameter | Default | Range | Description |
|---|---|---|---|
| `-LookbackDays` | 90 | 1-365 | Activity lookback window |
| `-InactivityThresholdDays` | 90 | 1-365 | Days before Tier 0 stale finding |
| `-GapThreshold` | 0.5 | 0.0-1.0 | Minimum gap ratio for over-privileged finding |
| `-MinimumGroupSize` | 3 | 2-100 | Principals needed for group consolidation |
| `-Format` | CSV, JSON | CSV, JSON, HTML | Report output formats |
| `-SkipRemediation` | false | — | Skip remediation script generation |
| `-SkipValidation` | false | — | Skip finding re-validation |

## Documentation

Full command reference: [chaospheremk.github.io/PermissionAnalyzer](https://chaospheremk.github.io/PermissionAnalyzer/)

## License

(c) 2026 Doug Johnson. All rights reserved.
