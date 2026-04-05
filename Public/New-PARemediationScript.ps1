#Requires -Version 7.0

function New-PARemediationScript {
    <#
    .SYNOPSIS
        Generates runnable remediation scripts from analysis findings.
    .DESCRIPTION
        Takes an array of PA.Finding objects and generates PowerShell remediation
        scripts grouped by RemediationAction type. Each script includes -WhatIf
        support and has destructive commands commented out by default for safe
        manual review. Returns a PA.RemediationResult with script paths and
        operation counts.
    .PARAMETER Findings
        Array of PA.Finding objects from Find-PAUnusedAssignment,
        Find-PALeastPrivilegeGap, and/or Find-PAGroupConsolidation.
    .PARAMETER OutputDirectory
        Directory path where remediation scripts will be written. Created if
        it does not exist.
    .PARAMETER RunId
        Identifier used in output file names for uniqueness. Defaults to a
        UTC timestamp (yyyyMMdd-HHmmss). Pass the session RunId for
        correlation with other pipeline outputs.
    .EXAMPLE
        $result = New-PARemediationScript -Findings $findings -OutputDirectory './remediation'
    .EXAMPLE
        $scriptParams = @{
            Findings        = $allFindings
            OutputDirectory = './remediation'
            RunId           = $session.RunId
        }
        $result = New-PARemediationScript @scriptParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.RemediationResult)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/New-PARemediationScript/
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Generates script files for review — does not modify permissions')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$RunId = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    )

    # --- Nested helper functions for script body generation ---

    function Get-ScriptHeader {
        param([string]$ActionType, [int]$Count, [string]$Id)
        $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss UTC')
        @"
#Requires -Version 7.0
# ============================================================
# PA Remediation Script — $ActionType
# Generated: $timestamp | RunId: $Id
# Findings: $Count
#
# IMPORTANT: Review all operations before executing.
# Destructive commands are COMMENTED OUT by default.
# Run with -WhatIf first, then uncomment to execute.
# ============================================================

[CmdletBinding(SupportsShouldProcess)]
param()


"@
    }

    function Get-RemoveScriptBody {
        param([PSCustomObject[]]$ActionFindings)

        $sb = [System.Text.StringBuilder]::new()

        # Group by source for organized output
        $bySource = @{}
        foreach ($f in $ActionFindings) {
            $src = $f.Source
            if (-not $bySource.ContainsKey($src)) {
                $bySource[$src] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $bySource[$src].Add($f)
        }

        # WhatIf preview
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('# WhatIf Preview')
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('')

        foreach ($f in $ActionFindings) {
            $escapedName = $f.PrincipalDisplayName -replace "'", "''"
            [void]$sb.AppendLine("# Finding: $($f.FindingId) — $($f.Title)")
            [void]$sb.AppendLine("Write-Host `"Would remove $($f.RoleName) from $escapedName at $($f.Scope)`" -ForegroundColor Yellow")
            [void]$sb.AppendLine('')
        }

        # Execution section
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('# Execution Section')
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('')

        foreach ($entry in $bySource.GetEnumerator()) {
            $src = $entry.Key
            [void]$sb.AppendLine("# --- $src Removals ---")
            [void]$sb.AppendLine('')

            foreach ($f in $entry.Value) {
                [void]$sb.AppendLine("# Finding: $($f.FindingId)")
                [void]$sb.AppendLine("# Principal: $($f.PrincipalDisplayName) ($($f.PrincipalId))")
                [void]$sb.AppendLine("# Role: $($f.RoleName) at $($f.Scope)")

                switch ($src) {
                    'AzureRbac' {
                        [void]$sb.AppendLine('# UNCOMMENT TO EXECUTE:')
                        [void]$sb.AppendLine("# `$removeParams = @{")
                        [void]$sb.AppendLine("#     ObjectId           = '$($f.PrincipalId)'")
                        [void]$sb.AppendLine("#     RoleDefinitionName = '$($f.RoleName)'")
                        [void]$sb.AppendLine("#     Scope              = '$($f.Scope)'")
                        [void]$sb.AppendLine("# }")
                        [void]$sb.AppendLine('# Remove-AzRoleAssignment @removeParams')
                    }
                    'PimAzure' {
                        [void]$sb.AppendLine('# UNCOMMENT TO EXECUTE:')
                        [void]$sb.AppendLine("# `$removeParams = @{")
                        [void]$sb.AppendLine("#     ObjectId           = '$($f.PrincipalId)'")
                        [void]$sb.AppendLine("#     RoleDefinitionName = '$($f.RoleName)'")
                        [void]$sb.AppendLine("#     Scope              = '$($f.Scope)'")
                        [void]$sb.AppendLine("# }")
                        [void]$sb.AppendLine('# Remove-AzRoleAssignment @removeParams')
                    }
                    { $_ -eq 'EntraRole' -or $_ -eq 'PimEntra' } {
                        [void]$sb.AppendLine('# UNCOMMENT TO EXECUTE:')
                        [void]$sb.AppendLine("# `$assignment = Get-MgRoleManagementDirectoryRoleAssignment -Filter `"principalId eq '$($f.PrincipalId)' and roleDefinitionId eq '$($f.RoleDefinitionId)'`"")
                        [void]$sb.AppendLine('# Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id')
                    }
                    'AppPermission' {
                        [void]$sb.AppendLine('# UNCOMMENT TO EXECUTE:')
                        [void]$sb.AppendLine("# `$spAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId '$($f.PrincipalId)' |")
                        [void]$sb.AppendLine("#     Where-Object { `$_.AppRoleId -eq '$($f.RoleDefinitionId)' }")
                        [void]$sb.AppendLine("# Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId '$($f.PrincipalId)' -AppRoleAssignmentId `$spAssignment.Id")
                    }
                }
                [void]$sb.AppendLine('')
            }
        }

        $sb.ToString()
    }

    function Get-DowngradeScriptBody {
        param([PSCustomObject[]]$ActionFindings)

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('# ADVISORY: Role Downgrade Recommendations')
        [void]$sb.AppendLine('# These require manual role selection — no auto-remediation.')
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('')

        foreach ($f in $ActionFindings) {
            [void]$sb.AppendLine("# Finding: $($f.FindingId)")
            [void]$sb.AppendLine("# Principal: $($f.PrincipalDisplayName) ($($f.PrincipalId))")
            [void]$sb.AppendLine("# Current Role: $($f.RoleName) at $($f.Scope)")

            if ($f.Details.GapRatio) {
                $usedPercent = [int]((1 - $f.Details.GapRatio) * 100)
                [void]$sb.AppendLine("# Gap Ratio: $($f.Details.GapRatio) — using ${usedPercent}% of granted permissions")
            }
            if ($f.Details.UsedNamespaces) {
                [void]$sb.AppendLine("# Used Namespaces: $($f.Details.UsedNamespaces -join ', ')")
            }
            if ($f.Details.UnusedNamespaces) {
                [void]$sb.AppendLine("# Unused Namespaces: $($f.Details.UnusedNamespaces -join ', ')")
            }

            [void]$sb.AppendLine('#')
            [void]$sb.AppendLine('# TODO: Identify a built-in role covering only the used namespaces,')
            [void]$sb.AppendLine('#       then remove the current assignment and create the new one.')
            [void]$sb.AppendLine('#')
            [void]$sb.AppendLine("# Step 1 — Remove over-privileged assignment:")
            [void]$sb.AppendLine("# Remove-AzRoleAssignment -ObjectId '$($f.PrincipalId)' -RoleDefinitionName '$($f.RoleName)' -Scope '$($f.Scope)'")
            [void]$sb.AppendLine('#')
            [void]$sb.AppendLine("# Step 2 — Assign replacement role:")
            [void]$sb.AppendLine("# New-AzRoleAssignment -ObjectId '$($f.PrincipalId)' -RoleDefinitionName '<replacement-role>' -Scope '$($f.Scope)'")
            [void]$sb.AppendLine('')
        }

        $sb.ToString()
    }

    function Get-ConsolidateScriptBody {
        param([PSCustomObject[]]$ActionFindings)

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('# Group Consolidation Scripts')
        [void]$sb.AppendLine('# Creates security groups and assigns roles to groups.')
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('')

        foreach ($f in $ActionFindings) {
            $principalCount = if ($f.Details.PrincipalCount) { $f.Details.PrincipalCount } else { 0 }
            $principalIds = if ($f.Details.PrincipalIds) { $f.Details.PrincipalIds } else { @() }

            [void]$sb.AppendLine("# Finding: $($f.FindingId)")
            [void]$sb.AppendLine("# $principalCount principals share $($f.RoleName) at $($f.Scope)")
            [void]$sb.AppendLine('')

            # Sanitize role name for group naming
            $groupSuffix = ($f.RoleName -replace '[^a-zA-Z0-9]', '-').ToLower()
            [void]$sb.AppendLine('# Step 1: Create security group')
            [void]$sb.AppendLine('# UNCOMMENT TO EXECUTE:')
            [void]$sb.AppendLine("# `$groupParams = @{")
            [void]$sb.AppendLine("#     DisplayName     = 'PA-$($f.RoleName)-Group'")
            [void]$sb.AppendLine("#     MailEnabled     = `$false")
            [void]$sb.AppendLine("#     MailNickname    = 'pa-$groupSuffix'")
            [void]$sb.AppendLine("#     SecurityEnabled = `$true")
            [void]$sb.AppendLine("# }")
            [void]$sb.AppendLine('# $newGroup = New-MgGroup @groupParams')
            [void]$sb.AppendLine('')

            [void]$sb.AppendLine('# Step 2: Add members')
            foreach ($memberId in $principalIds) {
                [void]$sb.AppendLine("# New-MgGroupMember -GroupId `$newGroup.Id -DirectoryObjectId '$memberId'")
            }
            [void]$sb.AppendLine('')

            [void]$sb.AppendLine("# Step 3: Assign $($f.RoleName) to the group at $($f.Scope)")
            switch ($f.Source) {
                'AzureRbac' {
                    [void]$sb.AppendLine("# New-AzRoleAssignment -ObjectId `$newGroup.Id -RoleDefinitionName '$($f.RoleName)' -Scope '$($f.Scope)'")
                }
                { $_ -eq 'EntraRole' -or $_ -eq 'PimEntra' } {
                    [void]$sb.AppendLine("# Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Body @{")
                    [void]$sb.AppendLine("#     principalId      = `$newGroup.Id")
                    [void]$sb.AppendLine("#     roleDefinitionId = '$($f.RoleDefinitionId)'")
                    [void]$sb.AppendLine("#     directoryScopeId = '$($f.Scope)'")
                    [void]$sb.AppendLine('# }')
                }
            }
            [void]$sb.AppendLine('')

            [void]$sb.AppendLine('# Step 4: Remove individual assignments (after verifying group assignment)')
            foreach ($memberId in $principalIds) {
                [void]$sb.AppendLine("# Remove individual assignment for $memberId")
            }
            [void]$sb.AppendLine('')
        }

        $sb.ToString()
    }

    function Get-ReviewEligibleScriptBody {
        param([PSCustomObject[]]$ActionFindings)

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('# ADVISORY: Eligible Assignment Review')
        [void]$sb.AppendLine('# These are PIM-eligible assignments that appear unused.')
        [void]$sb.AppendLine('# Manual review is required before removal.')
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('')

        foreach ($f in $ActionFindings) {
            [void]$sb.AppendLine("# Finding: $($f.FindingId)")
            [void]$sb.AppendLine("# Principal: $($f.PrincipalDisplayName) ($($f.PrincipalId))")
            [void]$sb.AppendLine("# Eligible Role: $($f.RoleName) at $($f.Scope)")
            if ($null -ne $f.DaysSinceActive) {
                [void]$sb.AppendLine("# Days Since Active: $($f.DaysSinceActive)")
            }
            [void]$sb.AppendLine('#')
            [void]$sb.AppendLine('# To remove this eligible assignment, use the Entra admin center')
            [void]$sb.AppendLine('# or submit a roleEligibilityScheduleRequest via Graph API.')
            [void]$sb.AppendLine('')
        }

        $sb.ToString()
    }

    function Get-ReduceScopeScriptBody {
        param([PSCustomObject[]]$ActionFindings)

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('# ADVISORY: Scope Reduction Recommendations')
        [void]$sb.AppendLine('# These assignments could be scoped to a narrower resource.')
        [void]$sb.AppendLine('# ============================================================')
        [void]$sb.AppendLine('')

        foreach ($f in $ActionFindings) {
            [void]$sb.AppendLine("# Finding: $($f.FindingId)")
            [void]$sb.AppendLine("# Principal: $($f.PrincipalDisplayName) ($($f.PrincipalId))")
            [void]$sb.AppendLine("# Role: $($f.RoleName)")
            [void]$sb.AppendLine("# Current Scope: $($f.Scope)")
            [void]$sb.AppendLine('#')
            [void]$sb.AppendLine('# TODO: Determine the narrowest scope covering actual usage.')
            [void]$sb.AppendLine('# Then create a new assignment at the reduced scope and remove the broad one.')
            [void]$sb.AppendLine('')
        }

        $sb.ToString()
    }

    # --- Main function body ---

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $scriptPaths = [System.Collections.Generic.List[string]]::new()
    $operationCounts = [ordered]@{
        Remove             = 0
        Downgrade          = 0
        ConsolidateToGroup = 0
        ReviewEligible     = 0
        ReduceScope        = 0
    }

    try {
        # Create output directory if needed
        if (-not (Test-Path -Path $OutputDirectory -PathType Container)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
            Write-Verbose "New-PARemediationScript: created output directory '$OutputDirectory'"
        }
        $resolvedDir = (Resolve-Path -Path $OutputDirectory).ProviderPath

        # Early return for empty findings
        if ($Findings.Count -eq 0) {
            $stopwatch.Stop()
            $result = [PSCustomObject]@{
                PSTypeName      = 'PA.RemediationResult'
                RunId           = $RunId
                OutputDirectory = $resolvedDir
                ScriptPaths     = @()
                OperationCounts = $operationCounts
                FindingCount    = 0
                GeneratedAt     = [datetime]::UtcNow
                Duration        = $stopwatch.Elapsed
            }
            $result
            return
        }

        # Group findings by RemediationAction
        $grouped = @{}
        foreach ($finding in $Findings) {
            $action = $finding.RemediationAction
            if (-not $grouped.ContainsKey($action)) {
                $grouped[$action] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $grouped[$action].Add($finding)
            if ($operationCounts.Contains($action)) {
                $operationCounts[$action]++
            }
        }

        # Generate one script per action type
        foreach ($entry in $grouped.GetEnumerator()) {
            try {
                $action = $entry.Key
                $actionFindings = $entry.Value.ToArray()

                $header = Get-ScriptHeader -ActionType $action -Count $actionFindings.Count -Id $RunId

                $body = switch ($action) {
                    'Remove'             { Get-RemoveScriptBody -ActionFindings $actionFindings }
                    'Downgrade'          { Get-DowngradeScriptBody -ActionFindings $actionFindings }
                    'ConsolidateToGroup' { Get-ConsolidateScriptBody -ActionFindings $actionFindings }
                    'ReviewEligible'     { Get-ReviewEligibleScriptBody -ActionFindings $actionFindings }
                    'ReduceScope'        { Get-ReduceScopeScriptBody -ActionFindings $actionFindings }
                }

                $scriptContent = $header + $body
                $scriptPath = Join-Path $resolvedDir "PA-Remediation-$action-$RunId.ps1"
                $scriptContent | Set-Content -Path $scriptPath -Encoding utf8
                $scriptPaths.Add($scriptPath)
                Write-Verbose "New-PARemediationScript: $action script written to '$scriptPath'"
            }
            catch {
                $ex = $_
                Write-Warning "New-PARemediationScript: $action script generation failed — $($ex.Exception.Message)"
            }
        }

        # Build and return PA.RemediationResult
        $stopwatch.Stop()

        $result = [PSCustomObject]@{
            PSTypeName      = 'PA.RemediationResult'
            RunId           = $RunId
            OutputDirectory = $resolvedDir
            ScriptPaths     = $scriptPaths.ToArray()
            OperationCounts = $operationCounts
            FindingCount    = $Findings.Count
            GeneratedAt     = [datetime]::UtcNow
            Duration        = $stopwatch.Elapsed
        }

        Write-Verbose "New-PARemediationScript: $($scriptPaths.Count) script(s) written in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

        $result
    }
    catch {
        $ex = $_
        Write-Warning "New-PARemediationScript: failed — $($ex.Exception.Message)"
        throw
    }
}
