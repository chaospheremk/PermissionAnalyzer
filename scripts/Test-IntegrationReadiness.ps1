#Requires -Version 7.0
<#
    .SYNOPSIS
        Pre-flight check for PermissionAnalyzer integration testing.
    .DESCRIPTION
        Verifies that all prerequisites are in place before running
        Invoke-PAPermissionAudit against a live tenant. Run interactively
        and follow the prompts.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host '  PermissionAnalyzer Pre-Flight Check' -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$allChecks = [ordered]@{}

# ============================================================
# Check 1: PowerShell version
# ============================================================
Write-Host '[1/7] PowerShell version...' -ForegroundColor Yellow
if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "  PASS: PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Green
    $allChecks['PowerShell 7+'] = $true
}
else {
    Write-Host "  FAIL: PowerShell $($PSVersionTable.PSVersion) — need 7.0+" -ForegroundColor Red
    $allChecks['PowerShell 7+'] = $false
}

# ============================================================
# Check 2: Required modules installed
# ============================================================
Write-Host "`n[2/7] Required modules..." -ForegroundColor Yellow
$requiredModules = @(
    'Microsoft.Graph.Authentication'
    'Az.Accounts'
    'Az.Resources'
    'Az.OperationalInsights'
)

foreach ($mod in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $mod | Select-Object -First 1
    if ($installed) {
        Write-Host "  PASS: $mod v$($installed.Version)" -ForegroundColor Green
        $allChecks[$mod] = $true
    }
    else {
        Write-Host "  FAIL: $mod not installed — run: Install-Module $mod -Scope CurrentUser" -ForegroundColor Red
        $allChecks[$mod] = $false
    }
}

# ============================================================
# Check 3: Graph connection and permissions
# ============================================================
Write-Host "`n[3/7] Microsoft Graph connection..." -ForegroundColor Yellow
try {
    $graphContext = Get-MgContext -ErrorAction Stop
    if ($graphContext) {
        Write-Host "  PASS: Connected as $($graphContext.Account) to tenant $($graphContext.TenantId)" -ForegroundColor Green
        $allChecks['Graph Connected'] = $true

        # Check scopes
        $requiredScopes = @(
            'AuditLog.Read.All'
            'Directory.Read.All'
            'RoleManagement.Read.All'
            'Application.Read.All'
            'User.Read.All'
        )
        $grantedScopes = $graphContext.Scopes
        Write-Host "`n  Graph permission scopes:" -ForegroundColor Yellow
        foreach ($scope in $requiredScopes) {
            if ($grantedScopes -contains $scope) {
                Write-Host "    PASS: $scope" -ForegroundColor Green
                $allChecks["Scope: $scope"] = $true
            }
            else {
                Write-Host "    WARN: $scope not in current scopes (may work with app-only auth)" -ForegroundColor DarkYellow
                $allChecks["Scope: $scope"] = $null
            }
        }
    }
    else {
        Write-Host '  NOT CONNECTED — run:' -ForegroundColor Red
        Write-Host '    Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All","RoleManagement.Read.All","Application.Read.All","User.Read.All"' -ForegroundColor White
        $allChecks['Graph Connected'] = $false
    }
}
catch {
    Write-Host '  NOT CONNECTED — run:' -ForegroundColor Red
    Write-Host '    Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All","RoleManagement.Read.All","Application.Read.All","User.Read.All"' -ForegroundColor White
    $allChecks['Graph Connected'] = $false
}

# ============================================================
# Check 4: Azure connection
# ============================================================
Write-Host "`n[4/7] Azure connection..." -ForegroundColor Yellow
try {
    $azContext = Get-AzContext -ErrorAction Stop
    if ($azContext) {
        Write-Host "  PASS: Connected as $($azContext.Account.Id) to tenant $($azContext.Tenant.Id)" -ForegroundColor Green
        Write-Host "  Subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -ForegroundColor Gray
        $allChecks['Azure Connected'] = $true

        # Check for enabled subscriptions
        Write-Host "`n  Discovering subscriptions..." -ForegroundColor Yellow
        $subs = Get-AzSubscription -TenantId $azContext.Tenant.Id -ErrorAction Stop |
            Where-Object { $_.State -eq 'Enabled' }
        Write-Host "  Found $($subs.Count) enabled subscription(s):" -ForegroundColor Green
        foreach ($sub in $subs) {
            Write-Host "    - $($sub.Name) ($($sub.Id))" -ForegroundColor Gray
        }
        $allChecks['Subscriptions Found'] = ($subs.Count -gt 0)
    }
    else {
        Write-Host '  NOT CONNECTED — run: Connect-AzAccount' -ForegroundColor Red
        $allChecks['Azure Connected'] = $false
    }
}
catch {
    Write-Host '  NOT CONNECTED — run: Connect-AzAccount' -ForegroundColor Red
    $allChecks['Azure Connected'] = $false
}

# ============================================================
# Check 5: Tenant ID match
# ============================================================
Write-Host "`n[5/7] Tenant ID alignment..." -ForegroundColor Yellow
if ($allChecks['Graph Connected'] -and $allChecks['Azure Connected']) {
    $graphTenant = (Get-MgContext).TenantId
    $azTenant = (Get-AzContext).Tenant.Id
    if ($graphTenant -eq $azTenant) {
        Write-Host "  PASS: Both connected to same tenant ($graphTenant)" -ForegroundColor Green
        $allChecks['Tenant Match'] = $true
    }
    else {
        Write-Host "  FAIL: Graph tenant ($graphTenant) does not match Azure tenant ($azTenant)" -ForegroundColor Red
        $allChecks['Tenant Match'] = $false
    }
}
else {
    Write-Host '  SKIP: Need both Graph and Azure connections first' -ForegroundColor DarkYellow
    $allChecks['Tenant Match'] = $null
}

# ============================================================
# Check 6: Log Analytics workspace
# ============================================================
Write-Host "`n[6/7] Log Analytics workspace..." -ForegroundColor Yellow
if ($allChecks['Azure Connected']) {
    try {
        $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction Stop
        if ($workspaces.Count -gt 0) {
            Write-Host "  Found $($workspaces.Count) workspace(s):" -ForegroundColor Green
            foreach ($ws in $workspaces) {
                Write-Host "    - $($ws.Name) (ID: $($ws.CustomerId)) in $($ws.ResourceGroupName)" -ForegroundColor Gray
            }
            Write-Host "`n  To verify sign-in logs are flowing to a workspace, check:" -ForegroundColor Yellow
            Write-Host '    1. Entra admin center > Monitoring > Diagnostic settings' -ForegroundColor White
            Write-Host '    2. Look for a setting sending SignInLogs and AuditLogs to a workspace' -ForegroundColor White
            Write-Host '    3. Copy the Workspace ID (CustomerId) from above for the integration test' -ForegroundColor White

            # Quick KQL test
            Write-Host "`n  Testing KQL query against first workspace..." -ForegroundColor Yellow
            $testWs = $workspaces[0]
            try {
                $queryParams = @{
                    WorkspaceId = $testWs.CustomerId
                    Query       = 'SigninLogs | take 1'
                    Timespan    = [timespan]::FromDays(7)
                    ErrorAction = 'Stop'
                }
                $testResult = Invoke-AzOperationalInsightsQuery @queryParams
                if ($testResult.Results.Count -gt 0) {
                    Write-Host "  PASS: SigninLogs table has data in $($testWs.Name)" -ForegroundColor Green
                    $allChecks['Log Analytics'] = $true
                }
                else {
                    Write-Host "  WARN: SigninLogs table is empty in $($testWs.Name) — Graph API fallback will be used" -ForegroundColor DarkYellow
                    $allChecks['Log Analytics'] = $null
                }
            }
            catch {
                if ($_.Exception.Message -like '*BadArgumentError*' -or $_.Exception.Message -like '*does not exist*') {
                    Write-Host "  WARN: SigninLogs table not found in $($testWs.Name) — sign-in logs may not be routed here" -ForegroundColor DarkYellow
                }
                else {
                    Write-Host "  WARN: KQL query failed — $($_.Exception.Message)" -ForegroundColor DarkYellow
                }
                $allChecks['Log Analytics'] = $null
            }
        }
        else {
            Write-Host '  No Log Analytics workspaces found in current subscription' -ForegroundColor DarkYellow
            Write-Host '  The module will fall back to Graph API direct queries (30-day lookback cap)' -ForegroundColor Gray
            $allChecks['Log Analytics'] = $null
        }
    }
    catch {
        Write-Host "  WARN: Could not list workspaces — $($_.Exception.Message)" -ForegroundColor DarkYellow
        $allChecks['Log Analytics'] = $null
    }
}
else {
    Write-Host '  SKIP: Need Azure connection first' -ForegroundColor DarkYellow
    $allChecks['Log Analytics'] = $null
}

# ============================================================
# Check 7: RBAC Reader access
# ============================================================
Write-Host "`n[7/7] Azure RBAC read access..." -ForegroundColor Yellow
if ($allChecks['Azure Connected'] -and $allChecks['Subscriptions Found']) {
    $azContext = Get-AzContext
    $testSubId = (Get-AzSubscription -TenantId $azContext.Tenant.Id |
        Where-Object { $_.State -eq 'Enabled' } |
        Select-Object -First 1).Id
    try {
        $assignments = Get-AzRoleAssignment -Scope "/subscriptions/$testSubId" -ErrorAction Stop |
            Select-Object -First 3
        Write-Host "  PASS: Can read role assignments (found $($assignments.Count)+ in first subscription)" -ForegroundColor Green
        $allChecks['RBAC Read'] = $true
    }
    catch {
        Write-Host "  FAIL: Cannot read role assignments — $($_.Exception.Message)" -ForegroundColor Red
        Write-Host '  You need Reader role on the subscription' -ForegroundColor Gray
        $allChecks['RBAC Read'] = $false
    }
}
else {
    Write-Host '  SKIP: Need Azure connection with subscriptions first' -ForegroundColor DarkYellow
    $allChecks['RBAC Read'] = $null
}

# ============================================================
# Summary
# ============================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host '  Pre-Flight Summary' -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$passed = 0
$failed = 0
$warned = 0

foreach ($check in $allChecks.GetEnumerator()) {
    $icon = switch ($check.Value) {
        $true  { '[PASS]'; $passed++ }
        $false { '[FAIL]'; $failed++ }
        default { '[WARN]'; $warned++ }
    }
    $color = switch ($check.Value) {
        $true   { 'Green' }
        $false  { 'Red' }
        default { 'DarkYellow' }
    }
    Write-Host "  $icon $($check.Key)" -ForegroundColor $color
}

Write-Host "`n  $passed passed, $failed failed, $warned warnings`n" -ForegroundColor White

if ($failed -eq 0) {
    Write-Host '  Ready for integration testing!' -ForegroundColor Green
    Write-Host ''

    # Output the command they should run
    $tenantId = if ($allChecks['Graph Connected']) { (Get-MgContext).TenantId } else { '<tenant-id>' }
    $wsId = ''
    if ($allChecks['Log Analytics']) {
        $ws = Get-AzOperationalInsightsWorkspace | Select-Object -First 1
        $wsId = $ws.CustomerId
    }

    Write-Host '  Next step — run the integration test:' -ForegroundColor Yellow
    Write-Host ''
    if ($wsId) {
        Write-Host "    `$auditParams = @{" -ForegroundColor White
        Write-Host "        TenantId        = '$tenantId'" -ForegroundColor White
        Write-Host "        WorkspaceId     = '$wsId'" -ForegroundColor White
        Write-Host "        OutputDirectory = './integration-test-output'" -ForegroundColor White
        Write-Host "        Format          = @('CSV', 'JSON', 'HTML')" -ForegroundColor White
        Write-Host '    }' -ForegroundColor White
        Write-Host '    $audit = Invoke-PAPermissionAudit @auditParams -Verbose' -ForegroundColor White
    }
    else {
        Write-Host "    `$auditParams = @{" -ForegroundColor White
        Write-Host "        TenantId        = '$tenantId'" -ForegroundColor White
        Write-Host "        OutputDirectory = './integration-test-output'" -ForegroundColor White
        Write-Host "        Format          = @('CSV', 'JSON', 'HTML')" -ForegroundColor White
        Write-Host '    }' -ForegroundColor White
        Write-Host '    $audit = Invoke-PAPermissionAudit @auditParams -Verbose' -ForegroundColor White
    }
    Write-Host ''
}
else {
    Write-Host '  Fix the failures above before running the integration test.' -ForegroundColor Red
    Write-Host ''
}
