# PermissionAnalyzer Documentation

PowerShell 7+ module that audits Entra ID and Azure RBAC permissions across a single tenant, correlates them with activity signals from Log Analytics or Microsoft Graph, identifies unused assignments, over-privileged access, and group consolidation opportunities, then generates structured reports and runnable remediation scripts. The module never executes changes — it produces findings and scripts for manual review.

## Quick Start

```powershell
# Full audit with reports and remediation scripts
$auditParams = @{
    TenantId        = '<tenant-id>'
    WorkspaceId     = '<workspace-customer-id>'
    OutputDirectory = './audit-output'
    Format          = @('CSV', 'JSON', 'HTML')
}
$audit = Invoke-PAPermissionAudit @auditParams -Verbose

# View results
$audit.FindingsBySeverity
```

See the [User Guide](guide.md) for detailed walkthrough, parameter tuning, and troubleshooting.

## Functions

| Category | Functions |
|----------|-----------|
| Auth | `Connect-PASession` |
| Collectors | `Get-PAEntraRoleAssignment`, `Get-PAPimEligibility`, `Get-PAAzureRbacAssignment`, `Get-PAAppPermission`, `Get-PAActivitySignal` |
| Analyzers | `Find-PAUnusedAssignment`, `Find-PALeastPrivilegeGap`, `Find-PAGroupConsolidation` |
| Report | `Export-PAReport` |
| Generators | `New-PARemediationScript` |
| Validation | `Test-PAFindingAccuracy` |
| Orchestrator | `Invoke-PAPermissionAudit` |

See the [command reference](commands/) for detailed parameter documentation.

## Permission Planes

PermissionAnalyzer audits four distinct permission planes:

| Plane | Source | Collector |
|-------|--------|-----------|
| Entra ID directory roles | Built-in and custom roles, including AU-scoped | `Get-PAEntraRoleAssignment` |
| PIM eligible assignments | Entra ID and Azure PIM schedules | `Get-PAPimEligibility` |
| Azure RBAC | Management group through resource level | `Get-PAAzureRbacAssignment` |
| App registrations | appRoles and OAuth2 delegated grants | `Get-PAAppPermission` |

## Activity Analysis Tiers

Activity signals from Log Analytics (preferred) or Graph API (30-day fallback) are correlated against assignments to classify usage:

| Tier | Condition | Example Finding |
|------|-----------|-----------------|
| Tier 1 | No sign-in activity in lookback window | User hasn't signed in for 90 days |
| Tier 2 | Signed in but no role-related operations | User signs in but never uses admin privileges |
| Tier 3 | Active but granted-vs-used action gap | User has Global Admin but only performs user resets |

## Requirements

- PowerShell 7.0 or later
- `Microsoft.Graph.Authentication` — `Connect-MgGraph`, `Invoke-MgGraphRequest`
- `Az.Accounts` — `Connect-AzAccount`
- `Az.Resources` — `Get-AzRoleAssignment`, PIM schedule cmdlets
- `Az.OperationalInsights` — `Invoke-AzOperationalInsightsQuery`

### Graph Permissions

`AuditLog.Read.All`, `Directory.Read.All`, `RoleManagement.Read.All`, `Application.Read.All`, `User.Read.All`

### Azure RBAC

`Reader` on all in-scope subscriptions, `Log Analytics Reader` on the workspace

## GCC High Support

PermissionAnalyzer supports GCC High and DoD environments from v0.1.0 via the `-Environment` parameter on `Connect-PASession`:

```powershell
Connect-PASession -TenantId '<tenant-id>' -Environment USGov
```
