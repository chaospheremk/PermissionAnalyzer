@{
    RootModule        = 'PermissionAnalyzer.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'e328e535-8003-4ce8-b3d6-01614d39ce95'
    Author            = 'Doug Johnson'
    CompanyName       = ''
    Copyright         = '(c) 2026 Doug Johnson. All rights reserved.'
    Description       = 'Entra ID and Azure RBAC permission analysis module for PowerShell 7+. Identifies unused assignments, over-privileged access, and group consolidation opportunities.'
    PowerShellVersion = '7.0'

    RequiredModules   = @(
        'Microsoft.Graph.Authentication'
        'Az.Accounts'
        'Az.Resources'
        'Az.OperationalInsights'
    )

    FormatsToProcess  = @('PermissionAnalyzer.Format.ps1xml')

    FunctionsToExport = @(
        'Connect-PASession'
        'Get-PAEntraRoleAssignment'
        'Get-PAPimEligibility'
        'Get-PAAzureRbacAssignment'
        'Get-PAAppPermission'
        'Get-PAActivitySignal'
        'Find-PAUnusedAssignment'
        'Find-PALeastPrivilegeGap'
        'Find-PAGroupConsolidation'
        'Export-PAReport'
        'New-PARemediationScript'
        'Test-PAFindingAccuracy'
        'Invoke-PAPermissionAudit'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('EntraID', 'Azure', 'RBAC', 'Permissions', 'PIM', 'Audit')
            ProjectUri = 'https://github.com/chaospheremk/PermissionAnalyzer'
        }
    }
}
