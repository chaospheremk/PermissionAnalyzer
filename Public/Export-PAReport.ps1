#Requires -Version 7.0

function Export-PAReport {
    <#
    .SYNOPSIS
        Exports findings to CSV, JSON, and/or HTML report files.
    .DESCRIPTION
        Takes an array of PA.Finding objects from the analysis phase and writes
        structured report files to the specified output directory. Computes
        summary statistics (counts by severity and category) and generates one
        file per requested format. Returns a PA.ReportResult object containing
        output file paths and summary counts.
    .PARAMETER Findings
        Array of PA.Finding objects from Find-PAUnusedAssignment,
        Find-PALeastPrivilegeGap, and/or Find-PAGroupConsolidation.
    .PARAMETER OutputDirectory
        Directory path where report files will be written. Created if it does
        not exist.
    .PARAMETER Format
        One or more output formats to generate. Defaults to CSV and JSON.
    .PARAMETER RunId
        Identifier used in output file names for uniqueness. Defaults to a
        UTC timestamp (yyyyMMdd-HHmmss). Pass the session RunId for
        correlation with other pipeline outputs.
    .EXAMPLE
        $report = Export-PAReport -Findings $findings -OutputDirectory './reports'
    .EXAMPLE
        $reportParams = @{
            Findings        = $allFindings
            OutputDirectory = './reports'
            Format          = @('CSV', 'JSON', 'HTML')
            RunId           = $session.RunId
        }
        $report = Export-PAReport @reportParams
    .INPUTS
        None.
    .OUTPUTS
        PSCustomObject (PA.ReportResult)
    .NOTES
        Part of the PermissionAnalyzer module.
    .LINK
        https://chaospheremk.github.io/PermissionAnalyzer/commands/Export-PAReport/
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory,

        [Parameter()]
        [ValidateSet('CSV', 'JSON', 'HTML')]
        [string[]]$Format = @('CSV', 'JSON'),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$RunId = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $outputFiles = [System.Collections.Generic.List[string]]::new()

    try {
        # Create output directory if needed
        if (-not (Test-Path -Path $OutputDirectory -PathType Container)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
            Write-Verbose "Export-PAReport: created output directory '$OutputDirectory'"
        }
        $resolvedDir = (Resolve-Path -Path $OutputDirectory).ProviderPath

        # Compute summary statistics
        $severityCounts = [ordered]@{
            Critical = 0
            High     = 0
            Medium   = 0
            Low      = 0
            Info     = 0
        }
        $categoryCounts = [ordered]@{
            UnusedAssignment   = 0
            OverPrivileged     = 0
            GroupConsolidation = 0
        }

        foreach ($finding in $Findings) {
            if ($severityCounts.Contains($finding.Severity)) {
                $severityCounts[$finding.Severity]++
            }
            if ($categoryCounts.Contains($finding.Category)) {
                $categoryCounts[$finding.Category]++
            }
        }

        # Export each requested format
        foreach ($fmt in $Format) {
            try {
                switch ($fmt) {
                    'CSV' {
                        $csvPath = Join-Path $resolvedDir "PA-Report-$RunId.csv"

                        $csvData = foreach ($f in $Findings) {
                            [PSCustomObject]@{
                                FindingId            = $f.FindingId
                                Category             = $f.Category
                                Severity             = $f.Severity
                                Title                = $f.Title
                                PrincipalId          = $f.PrincipalId
                                PrincipalDisplayName = $f.PrincipalDisplayName
                                PrincipalType        = $f.PrincipalType
                                RoleName             = $f.RoleName
                                RoleDefinitionId     = $f.RoleDefinitionId
                                Scope                = $f.Scope
                                Source               = $f.Source
                                ActivityTier         = $f.ActivityTier
                                DaysSinceActive      = $f.DaysSinceActive
                                Recommendation       = $f.Recommendation
                                RemediationAction    = $f.RemediationAction
                                DetailsJson          = ($f.Details | ConvertTo-Json -Compress -Depth 5)
                                CreatedAt            = $f.CreatedAt
                            }
                        }

                        if ($Findings.Count -eq 0) {
                            # Write header-only CSV for empty findings
                            $header = 'FindingId,Category,Severity,Title,PrincipalId,PrincipalDisplayName,PrincipalType,RoleName,RoleDefinitionId,Scope,Source,ActivityTier,DaysSinceActive,Recommendation,RemediationAction,DetailsJson,CreatedAt'
                            $header | Set-Content -Path $csvPath -Encoding utf8
                        }
                        else {
                            $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
                        }

                        $outputFiles.Add($csvPath)
                        Write-Verbose "Export-PAReport: CSV written to '$csvPath'"
                    }
                    'JSON' {
                        $jsonPath = Join-Path $resolvedDir "PA-Report-$RunId.json"

                        $jsonReport = [PSCustomObject]@{
                            ReportId       = $RunId
                            GeneratedAt    = [datetime]::UtcNow.ToString('o')
                            FindingCount   = $Findings.Count
                            SeverityCounts = $severityCounts
                            CategoryCounts = $categoryCounts
                            Findings       = @($Findings)
                        }

                        $jsonReport | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8
                        $outputFiles.Add($jsonPath)
                        Write-Verbose "Export-PAReport: JSON written to '$jsonPath'"
                    }
                    'HTML' {
                        $htmlPath = Join-Path $resolvedDir "PA-Report-$RunId.html"

                        # Human-friendly label mappings
                        $categoryLabels = @{
                            UnusedAssignment   = 'Unused Assignment'
                            OverPrivileged     = 'Over-Privileged'
                            GroupConsolidation = 'Group Consolidation'
                        }
                        $remediationLabels = @{
                            Remove             = 'Remove'
                            Downgrade          = 'Downgrade Role'
                            ConsolidateToGroup = 'Consolidate to Group'
                            ReviewEligible     = 'Review Eligible'
                            ReduceScope        = 'Reduce Scope'
                        }

                        # Sort findings by severity (Critical first)
                        $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
                        $sortedFindings = @($Findings | Sort-Object { $severityOrder[$_.Severity] })

                        $sb = [System.Text.StringBuilder]::new()
                        [void]$sb.AppendLine('<!DOCTYPE html>')
                        [void]$sb.AppendLine('<html lang="en">')
                        [void]$sb.AppendLine('<head>')
                        [void]$sb.AppendLine('    <meta charset="utf-8" />')
                        [void]$sb.AppendLine('    <meta name="viewport" content="width=device-width, initial-scale=1" />')
                        [void]$sb.AppendLine("    <title>PermissionAnalyzer Report &mdash; $RunId</title>")
                        [void]$sb.AppendLine('    <style>')
                        # CSS custom properties for light/dark themes
                        [void]$sb.AppendLine('        :root { --bg: #f7fafc; --bg-surface: #fff; --bg-header: #edf2f7; --text: #1a202c; --text-secondary: #4a5568; --text-muted: #718096; --text-faint: #a0aec0; --border: #e2e8f0; --shadow: rgba(0,0,0,0.08); --hover: #edf2f7; --heading: #1a1a2e; --heading2: #2d3748; }')
                        [void]$sb.AppendLine('        [data-theme="dark"] { --bg: #1a202c; --bg-surface: #2d3748; --bg-header: #2d3748; --text: #e2e8f0; --text-secondary: #cbd5e0; --text-muted: #a0aec0; --text-faint: #718096; --border: #4a5568; --shadow: rgba(0,0,0,0.3); --hover: #4a5568; --heading: #e2e8f0; --heading2: #cbd5e0; }')
                        [void]$sb.AppendLine('        *, *::before, *::after { box-sizing: border-box; }')
                        [void]$sb.AppendLine('        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2em; color: var(--text); background: var(--bg); max-width: 1400px; margin: 0 auto; transition: background 0.2s, color 0.2s; }')
                        [void]$sb.AppendLine('        h1 { color: var(--heading); margin-bottom: 0.25em; }')
                        [void]$sb.AppendLine('        h2 { color: var(--heading2); border-bottom: 2px solid var(--border); padding-bottom: 0.4em; margin-top: 2em; }')
                        [void]$sb.AppendLine('        .header-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }')
                        [void]$sb.AppendLine('        .theme-toggle { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 6px; padding: 6px 14px; cursor: pointer; font-size: 0.85em; color: var(--text-muted); transition: background 0.2s, border-color 0.2s; }')
                        [void]$sb.AppendLine('        .theme-toggle:hover { border-color: var(--text-secondary); }')
                        [void]$sb.AppendLine('        .subtitle { color: var(--text-muted); margin-top: 0; margin-bottom: 2em; font-size: 0.95em; }')
                        [void]$sb.AppendLine('        table { border-collapse: collapse; margin-bottom: 2em; background: var(--bg-surface); border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px var(--shadow); }')
                        [void]$sb.AppendLine('        th, td { border: 1px solid var(--border); padding: 10px 14px; text-align: left; font-size: 0.9em; }')
                        [void]$sb.AppendLine('        th { background-color: var(--bg-header); font-weight: 600; color: var(--heading2); white-space: nowrap; }')
                        [void]$sb.AppendLine('        tbody tr:hover { background-color: var(--hover); }')
                        [void]$sb.AppendLine('        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; white-space: nowrap; }')
                        [void]$sb.AppendLine('        .severity-Critical { background-color: #fed7d7; color: #9b2c2c; }')
                        [void]$sb.AppendLine('        .severity-High { background-color: #feebc8; color: #c05621; }')
                        [void]$sb.AppendLine('        .severity-Medium { background-color: #fefcbf; color: #975a16; }')
                        [void]$sb.AppendLine('        .severity-Low { background-color: #bee3f8; color: #2a69ac; }')
                        [void]$sb.AppendLine('        .severity-Info { background-color: #e2e8f0; color: #4a5568; }')
                        # Dark theme severity badge adjustments
                        [void]$sb.AppendLine('        [data-theme="dark"] .severity-Critical { background-color: #742a2a; color: #feb2b2; }')
                        [void]$sb.AppendLine('        [data-theme="dark"] .severity-High { background-color: #7b341e; color: #fbd38d; }')
                        [void]$sb.AppendLine('        [data-theme="dark"] .severity-Medium { background-color: #744210; color: #fefcbf; }')
                        [void]$sb.AppendLine('        [data-theme="dark"] .severity-Low { background-color: #2a4365; color: #bee3f8; }')
                        [void]$sb.AppendLine('        [data-theme="dark"] .severity-Info { background-color: #4a5568; color: #e2e8f0; }')
                        [void]$sb.AppendLine('        .summary-grid { display: flex; gap: 2em; flex-wrap: wrap; margin-bottom: 1em; }')
                        [void]$sb.AppendLine('        .summary-grid table { width: auto; min-width: 220px; }')
                        [void]$sb.AppendLine('        .summary-grid td.count { text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }')
                        [void]$sb.AppendLine('        .findings-table { width: 100%; table-layout: fixed; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(1) { width: 7%; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(2) { width: 11%; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(3) { width: 22%; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(4) { width: 12%; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(5) { width: 10%; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(6) { width: 14%; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(7) { width: 16%; }')
                        [void]$sb.AppendLine('        .findings-table th:nth-child(8) { width: 8%; }')
                        [void]$sb.AppendLine('        .findings-table .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 0; cursor: help; }')
                        [void]$sb.AppendLine('        .findings-table td.col-scope { font-family: "Cascadia Code", "Fira Code", "Consolas", monospace; font-size: 0.82em; color: var(--text-secondary); }')
                        [void]$sb.AppendLine('        .findings-table td.col-rec { font-size: 0.88em; color: var(--text-secondary); }')
                        [void]$sb.AppendLine('        footer { margin-top: 3em; padding-top: 1.5em; border-top: 1px solid var(--border); color: var(--text-faint); font-size: 0.85em; }')
                        [void]$sb.AppendLine('    </style>')
                        [void]$sb.AppendLine('</head>')
                        [void]$sb.AppendLine('<body>')
                        [void]$sb.AppendLine('    <div class="header-row">')
                        [void]$sb.AppendLine('        <h1>PermissionAnalyzer Report</h1>')
                        [void]$sb.AppendLine('        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle dark mode">Light / Dark</button>')
                        [void]$sb.AppendLine('    </div>')

                        $generatedAt = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss UTC')
                        [void]$sb.AppendLine("    <p class=`"subtitle`">Run ID: <strong>$RunId</strong> &middot; Generated: $generatedAt &middot; Total findings: <strong>$($Findings.Count)</strong></p>")

                        # Summary tables
                        [void]$sb.AppendLine('    <h2>Summary</h2>')
                        [void]$sb.AppendLine('    <div class="summary-grid">')

                        # Severity table with badges
                        [void]$sb.AppendLine('        <table>')
                        [void]$sb.AppendLine('            <thead><tr><th>Severity</th><th>Count</th></tr></thead>')
                        [void]$sb.AppendLine('            <tbody>')
                        foreach ($sev in $severityCounts.GetEnumerator()) {
                            [void]$sb.AppendLine("            <tr><td><span class=`"badge severity-$($sev.Key)`">$($sev.Key)</span></td><td class=`"count`">$($sev.Value)</td></tr>")
                        }
                        [void]$sb.AppendLine('            </tbody>')
                        [void]$sb.AppendLine('        </table>')

                        # Category table with human-friendly labels
                        [void]$sb.AppendLine('        <table>')
                        [void]$sb.AppendLine('            <thead><tr><th>Category</th><th>Count</th></tr></thead>')
                        [void]$sb.AppendLine('            <tbody>')
                        foreach ($cat in $categoryCounts.GetEnumerator()) {
                            $catLabel = if ($categoryLabels.ContainsKey($cat.Key)) { $categoryLabels[$cat.Key] } else { $cat.Key }
                            [void]$sb.AppendLine("            <tr><td>$catLabel</td><td class=`"count`">$($cat.Value)</td></tr>")
                        }
                        [void]$sb.AppendLine('            </tbody>')
                        [void]$sb.AppendLine('        </table>')

                        [void]$sb.AppendLine('    </div>')

                        # Findings table — sorted by severity, human-friendly labels
                        [void]$sb.AppendLine('    <h2>Findings</h2>')
                        [void]$sb.AppendLine('    <table class="findings-table">')
                        [void]$sb.AppendLine('        <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Principal</th><th>Role</th><th>Scope</th><th>Recommendation</th><th>Remediation</th></tr></thead>')
                        [void]$sb.AppendLine('        <tbody>')

                        if ($Findings.Count -eq 0) {
                            [void]$sb.AppendLine('        <tr><td colspan="8" style="text-align:center;color:#a0aec0;padding:2em;">No findings</td></tr>')
                        }
                        else {
                            foreach ($f in $sortedFindings) {
                                $title = [System.Net.WebUtility]::HtmlEncode($f.Title)
                                $principal = [System.Net.WebUtility]::HtmlEncode($f.PrincipalDisplayName)
                                $role = [System.Net.WebUtility]::HtmlEncode($f.RoleName)
                                $scope = [System.Net.WebUtility]::HtmlEncode($f.Scope)
                                $rec = [System.Net.WebUtility]::HtmlEncode($f.Recommendation)
                                $catLabel = if ($categoryLabels.ContainsKey($f.Category)) { $categoryLabels[$f.Category] } else { $f.Category }
                                $remLabel = if ($remediationLabels.ContainsKey($f.RemediationAction)) { $remediationLabels[$f.RemediationAction] } else { $f.RemediationAction }
                                [void]$sb.AppendLine("        <tr><td><span class=`"badge severity-$($f.Severity)`">$($f.Severity)</span></td><td class=`"truncate`" title=`"$catLabel`">$catLabel</td><td class=`"truncate`" title=`"$title`">$title</td><td class=`"truncate`" title=`"$principal`">$principal</td><td class=`"truncate`" title=`"$role`">$role</td><td class=`"truncate col-scope`" title=`"$scope`">$scope</td><td class=`"truncate col-rec`" title=`"$rec`">$rec</td><td>$remLabel</td></tr>")
                            }
                        }

                        [void]$sb.AppendLine('        </tbody>')
                        [void]$sb.AppendLine('    </table>')

                        # Footer with summary
                        $critCount = $severityCounts['Critical']
                        $highCount = $severityCounts['High']
                        [void]$sb.AppendLine("    <footer>Generated by PermissionAnalyzer v0.1.0 &middot; $($Findings.Count) findings ($critCount critical, $highCount high) &middot; $generatedAt</footer>")
                        [void]$sb.AppendLine('    <script>')
                        [void]$sb.AppendLine('        function toggleTheme() {')
                        [void]$sb.AppendLine('            var html = document.documentElement;')
                        [void]$sb.AppendLine('            var current = html.getAttribute("data-theme");')
                        [void]$sb.AppendLine('            var next = current === "dark" ? "light" : "dark";')
                        [void]$sb.AppendLine('            html.setAttribute("data-theme", next);')
                        [void]$sb.AppendLine('            try { localStorage.setItem("pa-theme", next); } catch(e) {}')
                        [void]$sb.AppendLine('        }')
                        [void]$sb.AppendLine('        (function() {')
                        [void]$sb.AppendLine('            try { var t = localStorage.getItem("pa-theme"); if (t) document.documentElement.setAttribute("data-theme", t); } catch(e) {}')
                        [void]$sb.AppendLine('        })();')
                        [void]$sb.AppendLine('    </script>')
                        [void]$sb.AppendLine('</body>')
                        [void]$sb.AppendLine('</html>')

                        $sb.ToString() | Set-Content -Path $htmlPath -Encoding utf8 -NoNewline
                        $outputFiles.Add($htmlPath)
                        Write-Verbose "Export-PAReport: HTML written to '$htmlPath'"
                    }
                }
            }
            catch {
                $ex = $_
                Write-Warning "Export-PAReport: $fmt export failed — $($ex.Exception.Message)"
            }
        }

        # Build and return PA.ReportResult
        $stopwatch.Stop()

        $result = [PSCustomObject]@{
            PSTypeName      = 'PA.ReportResult'
            RunId           = $RunId
            OutputDirectory = $resolvedDir
            OutputFiles     = $outputFiles.ToArray()
            Formats         = $Format
            FindingCount    = $Findings.Count
            SeverityCounts  = $severityCounts
            CategoryCounts  = $categoryCounts
            GeneratedAt     = [datetime]::UtcNow
            Duration        = $stopwatch.Elapsed
        }

        Write-Verbose "Export-PAReport: $($outputFiles.Count) file(s) written in $($stopwatch.Elapsed.TotalSeconds.ToString('F1'))s"

        return $result
    }
    catch {
        $ex = $_
        Write-Warning "Export-PAReport: failed — $($ex.Exception.Message)"
        throw
    }
}
