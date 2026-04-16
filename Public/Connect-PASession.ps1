#Requires -Version 7.0

function Connect-PASession {
    <#
    .SYNOPSIS
        Establishes Graph and Azure connections and returns a PA.Session object.
    .DESCRIPTION
        Entry point for all PermissionAnalyzer operations. Validates or
        establishes connections to Microsoft Graph and Azure, discovers
        in-scope subscriptions, and returns a session object that downstream
        functions use for auth context.

        If an existing Graph or Azure connection is detected, it is reused
        after validating the TenantId matches. If no connection exists, an
        interactive login is initiated.

        GCC High and DoD environments are supported via the -Environment
        parameter (ADR-003).
    .PARAMETER TenantId
        Entra tenant ID to audit. Must match the connected Graph and Azure
        contexts. If no connection exists, this tenant is used for the
        initial login.
    .PARAMETER WorkspaceId
        Log Analytics workspace ID for activity signal collection. When
        omitted, activity signals fall back to Graph API direct queries
        (30-day lookback limit).
    .PARAMETER SubscriptionId
        One or more Azure subscription IDs to scope the RBAC audit. When
        omitted, all enabled subscriptions in the tenant are discovered
        automatically.
    .PARAMETER Environment
        Cloud environment for Graph and Azure connections. Defaults to
        Global for broadest compatibility.
    .EXAMPLE
        $session = Connect-PASession -TenantId '<tenant-id>'

        Connects to the default (Global) environment and discovers all
        enabled subscriptions.
    .EXAMPLE
        $sessionParams = @{
            TenantId    = '<tenant-id>'
            WorkspaceId = '<workspace-id>'
            Environment = 'USGov'
        }
        $session = Connect-PASession @sessionParams

        Connects to a GCC High environment with a Log Analytics workspace.
    .EXAMPLE
        $sessionParams = @{
            TenantId       = '<tenant-id>'
            SubscriptionId = @('<sub-id-1>', '<sub-id-2>')
        }
        $session = Connect-PASession @sessionParams

        Scopes the audit to two specific subscriptions.
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.Session)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Connect-PASession/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter()]
        [string]$WorkspaceId = '',

        [Parameter()]
        [string[]]$SubscriptionId = @(),

        [Parameter()]
        [ValidateSet('Global', 'USGov', 'USGovDoD')]
        [string]$Environment = 'Global'
    )

    $requiredScopes = @(
        'AuditLog.Read.All'
        'Directory.Read.All'
        'RoleManagement.Read.All'
        'Application.Read.All'
        'User.Read.All'
    )

    # --- Graph connection ---------------------------------------------------

    $graphContext = Get-MgContext

    if ($graphContext) {
        Write-Verbose "Connect-PASession: existing Graph connection detected ($($graphContext.Account))"

        if ($graphContext.TenantId -ne $TenantId) {
            throw "Connect-PASession: Graph context tenant '$($graphContext.TenantId)' does not match -TenantId '$TenantId'. Run Disconnect-MgGraph and retry."
        }

        # Best-effort scope check — app-only auth may not list scopes
        if ($graphContext.Scopes) {
            $missingScopes = $requiredScopes.Where({ $_ -notin $graphContext.Scopes })
            if ($missingScopes) {
                Write-Warning "Connect-PASession: missing Graph scopes: $($missingScopes -join ', '). Some collectors may fail."
            }
        }
    }
    else {
        Write-Verbose "Connect-PASession: no Graph connection — connecting to tenant $TenantId ($Environment)"

        $connectGraphParams = @{
            TenantId    = $TenantId
            Scopes      = $requiredScopes
            Environment = $Environment
            ErrorAction = 'Stop'
        }
        Connect-MgGraph @connectGraphParams

        $graphContext = Get-MgContext
        if (-not $graphContext) {
            throw 'Connect-PASession: Connect-MgGraph succeeded but Get-MgContext returned null.'
        }
    }

    # --- Azure connection ----------------------------------------------------

    $azContext = Get-AzContext

    if ($azContext) {
        Write-Verbose "Connect-PASession: existing Azure connection detected ($($azContext.Account.Id))"

        if ($azContext.Tenant.Id -ne $TenantId) {
            throw "Connect-PASession: Azure context tenant '$($azContext.Tenant.Id)' does not match -TenantId '$TenantId'. Run Disconnect-AzAccount and retry."
        }
    }
    else {
        Write-Verbose "Connect-PASession: no Azure connection — connecting to tenant $TenantId ($Environment)"

        $connectAzParams = @{
            TenantId    = $TenantId
            Environment = $Environment
            ErrorAction = 'Stop'
        }
        Connect-AzAccount @connectAzParams | Out-Null

        $azContext = Get-AzContext
        if (-not $azContext) {
            throw 'Connect-PASession: Connect-AzAccount succeeded but Get-AzContext returned null.'
        }
    }

    # --- Subscription discovery ----------------------------------------------

    if ($SubscriptionId.Count -gt 0) {
        $subscriptionIds = $SubscriptionId
        Write-Verbose "Connect-PASession: using $($subscriptionIds.Count) explicitly provided subscription(s)"
    }
    else {
        Write-Verbose 'Connect-PASession: discovering enabled subscriptions'
        $subscriptions = @(Get-AzSubscription -TenantId $TenantId).Where({ $_.State -eq 'Enabled' })
        $subscriptionIds = @(foreach ($sub in $subscriptions) { $sub.Id })
    }

    if ($subscriptionIds.Count -eq 0) {
        Write-Warning 'Connect-PASession: no enabled subscriptions found. Azure RBAC collection will be skipped.'
    }
    else {
        Write-Verbose "Connect-PASession: $($subscriptionIds.Count) subscription(s) in scope"
    }

    # --- Build session -------------------------------------------------------

    $authMethod = if ($graphContext.AuthType) { $graphContext.AuthType } else { 'Unknown' }

    $session = [PSCustomObject]@{
        PSTypeName      = 'PA.Session'
        TenantId        = $TenantId
        Environment     = $Environment
        AccountId       = $graphContext.Account
        AuthMethod      = $authMethod
        SubscriptionIds = $subscriptionIds
        WorkspaceId     = $WorkspaceId
        RunId           = [guid]::NewGuid().ToString()
        StartTime       = [datetime]::UtcNow
    }

    Write-Verbose "Connect-PASession: session created (RunId: $($session.RunId), Auth: $authMethod, Subscriptions: $($subscriptionIds.Count))"

    $session
}
