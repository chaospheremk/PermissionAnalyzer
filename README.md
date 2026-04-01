# PermissionAnalyzer

[![CI](https://github.com/chaospheremk/PermissionAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/chaospheremk/PermissionAnalyzer/actions/workflows/ci.yml)
[![Docs](https://github.com/chaospheremk/PermissionAnalyzer/actions/workflows/docs.yml/badge.svg)](https://github.com/chaospheremk/PermissionAnalyzer/actions/workflows/docs.yml)

**[Documentation](https://chaospheremk.github.io/PermissionAnalyzer/)** | **[Changelog](CHANGELOG.md)**

PowerShell 7+ module that audits Entra ID and Azure RBAC permissions, correlates them with activity signals, identifies unused/over-privileged assignments, and generates remediation scripts. The module never executes changes — it produces findings and runnable scripts for manual review.

## Quick Start

```powershell
# Interactive mode — full audit with HTML report
$session = Connect-PASession -TenantId '<tenant-id>' -WorkspaceId '<workspace-id>'
Invoke-PAPermissionAudit -Session $session -ExportFormat HTML -GenerateRemediation

# Pipeline mode — filter critical findings
Invoke-PAPermissionAudit -TenantId '<tenant-id>' |
    Where-Object Severity -eq 'Critical'
```

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

See the [command reference](https://chaospheremk.github.io/PermissionAnalyzer/commands/) for full documentation.

## Development Setup

```bash
# Install pre-commit hooks (one-time per clone)
pip install pre-commit
pre-commit install
```

This enables TruffleHog secret scanning on every commit. See `.pre-commit-config.yaml` for configuration.

## Requirements

- PowerShell 7.0 or later
- Microsoft.Graph.Authentication
- Az.Accounts, Az.Resources, Az.OperationalInsights
