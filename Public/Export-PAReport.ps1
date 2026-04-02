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

                        $sb = [System.Text.StringBuilder]::new()
                        [void]$sb.AppendLine('<!DOCTYPE html>')
                        [void]$sb.AppendLine('<html lang="en">')
                        [void]$sb.AppendLine('<head>')
                        [void]$sb.AppendLine('    <meta charset="utf-8" />')
                        [void]$sb.AppendLine("    <title>PermissionAnalyzer Report - $RunId</title>")
                        [void]$sb.AppendLine('    <style>')
                        [void]$sb.AppendLine('        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2em; color: #333; }')
                        [void]$sb.AppendLine('        h1 { color: #1a1a2e; }')
                        [void]$sb.AppendLine('        h2 { color: #16213e; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.3em; }')
                        [void]$sb.AppendLine('        table { border-collapse: collapse; width: 100%; margin-bottom: 2em; }')
                        [void]$sb.AppendLine('        th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }')
                        [void]$sb.AppendLine('        th { background-color: #f7fafc; font-weight: 600; }')
                        [void]$sb.AppendLine('        tr:nth-child(even) { background-color: #f7fafc; }')
                        [void]$sb.AppendLine('        .severity-Critical { background-color: #fed7d7; color: #9b2c2c; font-weight: 600; }')
                        [void]$sb.AppendLine('        .severity-High { background-color: #feebc8; color: #c05621; font-weight: 600; }')
                        [void]$sb.AppendLine('        .severity-Medium { background-color: #fefcbf; color: #975a16; }')
                        [void]$sb.AppendLine('        .severity-Low { background-color: #bee3f8; color: #2a69ac; }')
                        [void]$sb.AppendLine('        .severity-Info { background-color: #e2e8f0; color: #4a5568; }')
                        [void]$sb.AppendLine('        .summary-grid { display: flex; gap: 2em; margin-bottom: 2em; }')
                        [void]$sb.AppendLine('        .summary-grid table { width: auto; }')
                        [void]$sb.AppendLine('        footer { margin-top: 2em; color: #a0aec0; font-size: 0.85em; }')
                        [void]$sb.AppendLine('    </style>')
                        [void]$sb.AppendLine('</head>')
                        [void]$sb.AppendLine('<body>')
                        [void]$sb.AppendLine('    <h1>PermissionAnalyzer Report</h1>')

                        $generatedAt = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss UTC')
                        [void]$sb.AppendLine("    <p>Run ID: $RunId | Generated: $generatedAt | Total findings: $($Findings.Count)</p>")

                        # Summary tables
                        [void]$sb.AppendLine('    <h2>Summary</h2>')
                        [void]$sb.AppendLine('    <div class="summary-grid">')

                        # Severity table
                        [void]$sb.AppendLine('        <table>')
                        [void]$sb.AppendLine('            <tr><th>Severity</th><th>Count</th></tr>')
                        foreach ($sev in $severityCounts.GetEnumerator()) {
                            [void]$sb.AppendLine("            <tr><td class=`"severity-$($sev.Key)`">$($sev.Key)</td><td>$($sev.Value)</td></tr>")
                        }
                        [void]$sb.AppendLine('        </table>')

                        # Category table
                        [void]$sb.AppendLine('        <table>')
                        [void]$sb.AppendLine('            <tr><th>Category</th><th>Count</th></tr>')
                        foreach ($cat in $categoryCounts.GetEnumerator()) {
                            [void]$sb.AppendLine("            <tr><td>$($cat.Key)</td><td>$($cat.Value)</td></tr>")
                        }
                        [void]$sb.AppendLine('        </table>')

                        [void]$sb.AppendLine('    </div>')

                        # Findings table
                        [void]$sb.AppendLine('    <h2>Findings</h2>')
                        [void]$sb.AppendLine('    <table>')
                        [void]$sb.AppendLine('        <tr><th>Severity</th><th>Category</th><th>Title</th><th>Principal</th><th>Role</th><th>Scope</th><th>Recommendation</th><th>Remediation</th></tr>')

                        if ($Findings.Count -eq 0) {
                            [void]$sb.AppendLine('        <tr><td colspan="8" style="text-align:center;color:#a0aec0;">No findings</td></tr>')
                        }
                        else {
                            foreach ($f in $Findings) {
                                $sevClass = "severity-$($f.Severity)"
                                $title = [System.Net.WebUtility]::HtmlEncode($f.Title)
                                $principal = [System.Net.WebUtility]::HtmlEncode($f.PrincipalDisplayName)
                                $role = [System.Net.WebUtility]::HtmlEncode($f.RoleName)
                                $scope = [System.Net.WebUtility]::HtmlEncode($f.Scope)
                                $rec = [System.Net.WebUtility]::HtmlEncode($f.Recommendation)
                                [void]$sb.AppendLine("        <tr><td class=`"$sevClass`">$($f.Severity)</td><td>$($f.Category)</td><td>$title</td><td>$principal</td><td>$role</td><td>$scope</td><td>$rec</td><td>$($f.RemediationAction)</td></tr>")
                            }
                        }

                        [void]$sb.AppendLine('    </table>')
                        [void]$sb.AppendLine('    <footer>Generated by PermissionAnalyzer v0.1.0</footer>')
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
