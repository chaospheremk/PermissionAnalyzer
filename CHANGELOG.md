# Changelog

All notable changes to the PermissionAnalyzer module are documented in this file.

## [0.1.0] — 2026-04-03

Initial release. Complete permission audit pipeline for Entra ID and Azure RBAC.

### Added

**Core Pipeline**
- `Connect-PASession` — auth entry point validating Graph and Azure connections (#10)
- `Invoke-PAPermissionAudit` — end-to-end orchestrator with per-stage error isolation (#22)

**Collectors**
- `Get-PAEntraRoleAssignment` — Entra ID directory role assignments with $expand fallback (#12)
- `Get-PAPimEligibility` — PIM eligible assignments from Entra ID and Azure RBAC (#13)
- `Get-PAAzureRbacAssignment` — Azure RBAC assignments with per-subscription error isolation (#14)
- `Get-PAAppPermission` — app role assignments and OAuth2 delegated grants (#15)
- `Get-PAActivitySignal` — activity signals from Log Analytics (6 tables) or Graph API fallback (#16)

**Analyzers**
- `Find-PAUnusedAssignment` — 3-tier unused assignment detection with severity matrix (#17)
- `Find-PALeastPrivilegeGap` — namespace-level granted-vs-used permission comparison (#17)
- `Find-PAGroupConsolidation` — group consolidation opportunity detection (#17)

**Reporting and Remediation**
- `Export-PAReport` — CSV, JSON, and HTML reports with dark mode toggle and resizable columns (#19, #23, #25, #26, #27)
- `New-PARemediationScript` — remediation scripts grouped by action type with -WhatIf support (#20)
- `Test-PAFindingAccuracy` — finding re-validation against live tenant data (#21)

**Data Model**
- 8 private constructor functions for PA.Assignment, PA.ActivityProfile, PA.Finding, PA.CollectorResult, PA.ValidationResult (#7)
- 3 internal utilities: Invoke-PAGraphRequest, Invoke-PALogAnalyticsQuery, Resolve-PAPrincipal (#8)
- Resolve-PAOperationNamespace with EntraOperationMap.json for Tier 3 analysis (#11)

**Infrastructure**
- Format.ps1xml with 6 console views (TableControl + ListControl) (#24)
- CI/CD with Pester, PSScriptAnalyzer, PlatyPS doc verification, TruffleHog secret scan
- Docs site on GitHub Pages via Zensical
- Pre-flight readiness check script (#25)
- GCC High/DoD support via -Environment parameter (ADR-003)

### Fixed
- SP sign-in false positives on Graph API path — honest warning with Log Analytics recommendation (#26, #27, #28)
- HTML report cell overflow with truncation and drag-to-resize columns (#25, #26, #27)
- PSScriptAnalyzer automatic variable warnings ($profile → $actProfile) (#18)
- PowerShell house rules enforcement across all source files (#18)

### Known Limitations
- Service principal sign-in data requires Log Analytics (AADServicePrincipalSignInLogs)
- Read-only app permissions appear as Tier 2 findings (ADR-006)
- Tier 3 gap analysis requires future GrantedActions/UsedActions enrichment
- 30-day lookback cap on Graph API fallback path

### Stats
- 21 functions (13 public + 8 private)
- 578 Pester tests
- 6 ADRs
- 29 PRs merged
