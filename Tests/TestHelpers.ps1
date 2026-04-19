#Requires -Version 7.0

<#
Shared factories used by PermissionAnalyzer Pester tests. Dot-source this file
from any Tests/**/*.Tests.ps1 that needs canonical PA.Session or
PA.CollectorResult stubs. Centralizing prevents drift between the unit suite
and the integration suite when the underlying schemas evolve.
#>

function New-MockSession {
    [CmdletBinding()]
    param(
        [string]$TenantId = '<tenant-id>',
        [string]$Environment = 'Global',
        [string[]]$SubscriptionIds = @('<sub-id-1>'),
        [string]$WorkspaceId = '<workspace-id>',
        [string]$RunId = 'test-run-001'
    )

    [PSCustomObject]@{
        PSTypeName      = 'PA.Session'
        TenantId        = $TenantId
        Environment     = $Environment
        AccountId       = '<account-id>'
        AuthMethod      = 'AppOnly'
        SubscriptionIds = $SubscriptionIds
        WorkspaceId     = $WorkspaceId
        RunId           = $RunId
        StartTime       = [datetime]::UtcNow
    }
}

function New-MockCollectorResult {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Collector,

        [ValidateSet('Complete', 'Partial', 'Failed')]
        [string]$Status = 'Complete',

        [object[]]$Items = @(),

        [string[]]$Errors = @(),

        [string[]]$Warnings = @(),

        [timespan]$Duration = [timespan]::FromSeconds(1)
    )

    [PSCustomObject]@{
        PSTypeName = 'PA.CollectorResult'
        Collector  = $Collector
        Status     = $Status
        Items      = $Items
        ItemCount  = $Items.Count
        Errors     = $Errors
        Warnings   = $Warnings
        Duration   = $Duration
        Timestamp  = [datetime]::UtcNow
    }
}
