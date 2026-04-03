#Requires -Version 7.0
#Requires -Modules InvokeBuild

<#
.SYNOPSIS
    Build script for PermissionAnalyzer. Run with: Invoke-Build [Task] [-Configuration <Debug|Release>]
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',

    # Injected by release workflow from the git tag (e.g. '1.4.2')
    # Not set during local development or CI runs
    [string] $Version = ''
)

# --- Config -----------------------------------------------------------------

$Config       = Import-PowerShellDataFile "$PSScriptRoot/build.config.psd1"
$ModuleName   = $Config.ModuleName
$AcrRepo      = $Config.AcrRepoName
$ManifestPath = Join-Path $PSScriptRoot $Config.ManifestPath
$TestsDir     = Join-Path $PSScriptRoot $Config.TestsDir
$DocsDir      = Join-Path $PSScriptRoot $Config.DocsDir
$OutputDir    = Join-Path $PSScriptRoot $Config.OutputDir
$PackageDir   = Join-Path $OutputDir $ModuleName

# --- Tasks ------------------------------------------------------------------

task Clean {
    if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
    New-Item $OutputDir -ItemType Directory | Out-Null
}

task Lint {
    # Scan module source directories — excludes .build.ps1 (Invoke-Build DSL aliases
    # like task/assert/exec trigger PSAvoidUsingCmdletAliases false positives)
    # and scripts/ (interactive utilities that legitimately use Write-Host)
    $scanPaths = @(
        Join-Path $PSScriptRoot $Config.PublicDir
        Join-Path $PSScriptRoot $Config.PrivateDir
        $ManifestPath
        Join-Path $PSScriptRoot "$ModuleName.psm1"
    ) | Where-Object { Test-Path $_ }

    $settingsPath = Join-Path $PSScriptRoot $Config.PSSASettingsPath
    $results = foreach ($scanPath in $scanPaths) {
        $pssaParams = @{
            Path     = $scanPath
            Recurse  = $true
            Settings = $settingsPath
        }
        Invoke-ScriptAnalyzer @pssaParams
    }
    if ($results) {
        foreach ($r in $results) {
            Write-Warning "[$($r.Severity)] $($r.RuleName) — $($r.ScriptName):$($r.Line)"
        }
        throw "PSScriptAnalyzer found $($results.Count) issue(s). Fix before proceeding."
    }
}

task Test {
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $TestsDir
    $pesterConfig.Run.PassThru = $true
    $pesterConfig.Output.Verbosity = 'Detailed'

    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputFormat = 'JUnitXml'
    $pesterConfig.TestResult.OutputPath = Join-Path $PSScriptRoot 'TestResults.xml'

    $pesterConfig.CodeCoverage.Enabled = ($Configuration -eq 'Release')
    $pesterConfig.CodeCoverage.OutputFormat = $Config.CoverageFormat
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $PSScriptRoot 'CoverageResults.xml'
    $pesterConfig.CodeCoverage.Path = $Config.CoveragePaths | ForEach-Object {
        Join-Path $PSScriptRoot $_
    } | Where-Object { Test-Path $_ }

    $result = Invoke-Pester -Configuration $pesterConfig
    assert ($result.FailedCount -eq 0) "Pester: $($result.FailedCount) test(s) failed."

    if ($Configuration -eq 'Release') {
        $threshold = $Config.CoverageThreshold
        $coveragePct = [math]::Round($result.CodeCoverage.CoveragePercent, 2)
        Write-Build Green "Code coverage: $coveragePct% (threshold: $threshold%)"
        assert ($coveragePct -ge $threshold) "Coverage $coveragePct% is below the $threshold% threshold."
    }
}

task Docs {
    Import-Module $ManifestPath -Force
    Import-Module Microsoft.PowerShell.PlatyPS

    if (-not (Test-Path $DocsDir)) {
        New-Item -ItemType Directory -Path $DocsDir -Force | Out-Null
    }

    # Generate markdown for each exported command
    $commands = Get-Command -Module $ModuleName
    foreach ($cmd in $commands) {
        $result = New-MarkdownCommandHelp -Command $cmd -OutputFolder $DocsDir -Force
        # PlatyPS v2 nests under a module subfolder — flatten to docs/commands/
        if ($result.Directory.Name -ne (Split-Path $DocsDir -Leaf)) {
            Move-Item -Path $result.FullName -Destination $DocsDir -Force
        }
    }

    # Clean up the module subfolder if empty
    $subDir = Join-Path $DocsDir $ModuleName
    if ((Test-Path $subDir) -and (Get-ChildItem $subDir | Measure-Object).Count -eq 0) {
        Remove-Item $subDir -Force
    }

    # Post-process: strip PlatyPS v2 placeholder text, normalize date stamps and line endings.
    foreach ($filePath in (Get-ChildItem $DocsDir -Filter *.md).FullName) {
        $content = [System.IO.File]::ReadAllText($filePath)
        $cleaned = $content -replace '(?m)^This cmdlet has the following aliases,\s*\r?\n\s*\{\{Insert list of aliases\}\}\s*$', 'None.'
        $cleaned = $cleaned -replace '\{\{\s*Fill in the related links here\s*\}\}', ''
        $cleaned = $cleaned -replace '\{\{[^}]+\}\}', ''
        $cleaned = $cleaned -replace '(?m)^ms\.date:\s*\d{2}/\d{2}/\d{4}', 'ms.date: 01/01/1970'
        $cleaned = $cleaned -replace '\r\n', "`n"
        [System.IO.File]::WriteAllText($filePath, $cleaned)
    }

    # Generate index page
    $index = [System.Text.StringBuilder]::new()
    [void]$index.AppendLine('# Command Reference')
    [void]$index.AppendLine()
    [void]$index.AppendLine('| Command | Description |')
    [void]$index.AppendLine('|---------|-------------|')
    foreach ($cmd in $commands) {
        $help = Get-Help $cmd.Name
        $synopsis = ($help.Synopsis -split "`n")[0].Trim().TrimEnd('.')
        [void]$index.AppendLine("| [$($cmd.Name)]($($cmd.Name).md) | $synopsis |")
    }
    [void]$index.AppendLine()
    $indexContent = $index.ToString() -replace '\r\n', "`n"
    [System.IO.File]::WriteAllText((Join-Path $DocsDir 'index.md'), $indexContent)

    Remove-Module $ModuleName -Force
    Write-Build Green "Documentation generated for $($commands.Count) commands"
}

task AssertDocsClean {
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "docs-check-$(New-Guid)"
    New-Item $tempDir -ItemType Directory | Out-Null

    try {
        Import-Module $ManifestPath -Force
        Import-Module Microsoft.PowerShell.PlatyPS

        $commands = Get-Command -Module $ModuleName
        foreach ($cmd in $commands) {
            $result = New-MarkdownCommandHelp -Command $cmd -OutputFolder $tempDir -Force
            if ($result.Directory.Name -ne (Split-Path $tempDir -Leaf)) {
                Move-Item -Path $result.FullName -Destination $tempDir -Force
            }
        }

        $subDir = Join-Path $tempDir $ModuleName
        if ((Test-Path $subDir) -and (Get-ChildItem $subDir | Measure-Object).Count -eq 0) {
            Remove-Item $subDir -Force
        }

        foreach ($filePath in (Get-ChildItem $tempDir -Filter *.md).FullName) {
            $content = [System.IO.File]::ReadAllText($filePath)
            $cleaned = $content -replace '(?m)^This cmdlet has the following aliases,\s*\r?\n\s*\{\{Insert list of aliases\}\}\s*$', 'None.'
            $cleaned = $cleaned -replace '\{\{\s*Fill in the related links here\s*\}\}', ''
            $cleaned = $cleaned -replace '\{\{[^}]+\}\}', ''
            $cleaned = $cleaned -replace '(?m)^ms\.date:\s*\d{2}/\d{2}/\d{4}', 'ms.date: 01/01/1970'
            $cleaned = $cleaned -replace '\r\n', "`n"
            [System.IO.File]::WriteAllText($filePath, $cleaned)
        }

        $index = [System.Text.StringBuilder]::new()
        [void]$index.AppendLine('# Command Reference')
        [void]$index.AppendLine()
        [void]$index.AppendLine('| Command | Description |')
        [void]$index.AppendLine('|---------|-------------|')
        foreach ($cmd in $commands) {
            $help = Get-Help $cmd.Name
            $synopsis = ($help.Synopsis -split "`n")[0].Trim().TrimEnd('.')
            [void]$index.AppendLine("| [$($cmd.Name)]($($cmd.Name).md) | $synopsis |")
        }
        [void]$index.AppendLine()
        $indexContent = $index.ToString() -replace '\r\n', "`n"
        [System.IO.File]::WriteAllText((Join-Path $tempDir 'index.md'), $indexContent)

        Remove-Module $ModuleName -Force

        $committedTemp = Join-Path ([System.IO.Path]::GetTempPath()) "docs-committed-$(New-Guid)"
        New-Item $committedTemp -ItemType Directory | Out-Null
        if (Test-Path $DocsDir) {
            $committedMd = Get-ChildItem $DocsDir -Filter *.md
            if ($committedMd) {
                Copy-Item $committedMd.FullName $committedTemp
            }
        }
        foreach ($filePath in (Get-ChildItem $committedTemp -Filter *.md).FullName) {
            $content = [System.IO.File]::ReadAllText($filePath)
            $cleaned = $content -replace '(?m)^ms\.date:\s*\d{2}/\d{2}/\d{4}', 'ms.date: 01/01/1970'
            $cleaned = $cleaned -replace '\r\n', "`n"
            [System.IO.File]::WriteAllText($filePath, $cleaned)
        }

        $committedFiles = Get-ChildItem $committedTemp -Filter *.md |
            Get-FileHash |
            ForEach-Object { "$($_.Hash):$($_.Path | Split-Path -Leaf)" } |
            Sort-Object
        $freshFiles = Get-ChildItem $tempDir -Filter *.md |
            Get-FileHash |
            ForEach-Object { "$($_.Hash):$($_.Path | Split-Path -Leaf)" } |
            Sort-Object

        if (-not $committedFiles -and -not $freshFiles) {
            Write-Build Yellow "Warning: No docs found in either committed or generated directories."
            return
        }
        if (-not $committedFiles) {
            throw "No committed docs found in '$DocsDir'. Run 'Invoke-Build Docs' locally and commit the result."
        }
        if (-not $freshFiles) {
            throw "Committed docs exist but fresh generation produced nothing. Check module import and PlatyPS."
        }

        $diff = Compare-Object $committedFiles $freshFiles
        if ($diff) {
            $added   = ($diff | Where-Object SideIndicator -eq '=>').InputObject
            $removed = ($diff | Where-Object SideIndicator -eq '<=').InputObject
            if ($added)   { Write-Build Red "New/changed in fresh generation: $($added -join ', ')" }
            if ($removed) { Write-Build Red "Missing from fresh generation: $($removed -join ', ')" }
            throw "Committed docs are out of date. Run 'Invoke-Build Docs' locally and commit the result."
        }
    }
    finally {
        Remove-Item $tempDir -Recurse -Force
        if ($committedTemp -and (Test-Path $committedTemp)) {
            Remove-Item $committedTemp -Recurse -Force
        }
    }
}

task BumpVersion {
    $manifest = Import-PowerShellDataFile $ManifestPath
    $version = [version] $manifest.ModuleVersion
    $script:NewVersion = [version]::new($version.Major, $version.Minor, $version.Build + 1)
    Write-Build Green "Bumping version: $version -> $script:NewVersion"
    Update-ModuleManifest -Path $ManifestPath -ModuleVersion $script:NewVersion
}

task Pack Clean, {
    New-Item $PackageDir -ItemType Directory -Force | Out-Null

    $itemsToCopy = @(
        $ManifestPath
        (Join-Path $PSScriptRoot "$ModuleName.psm1")
        (Join-Path $PSScriptRoot $Config.PublicDir)
        (Join-Path $PSScriptRoot $Config.PrivateDir)
        (Join-Path $PSScriptRoot 'Data')
    )

    foreach ($item in $itemsToCopy) {
        if (Test-Path $item) {
            Copy-Item $item $PackageDir -Recurse -Force
        }
    }

    # Include Format.ps1xml
    $formatFile = Join-Path $PSScriptRoot "$ModuleName.Format.ps1xml"
    if (Test-Path $formatFile) {
        Copy-Item $formatFile $PackageDir -Force
    }

    # Include MAML help if it exists
    $mamlDir = Join-Path $PSScriptRoot 'en-US'
    if (Test-Path $mamlDir) {
        Copy-Item $mamlDir (Join-Path $PackageDir 'en-US') -Recurse -Force
    }

    Write-Build Green "Packed $ModuleName to $PackageDir"
}

task SetVersion {
    assert ($Version -match '^\d+\.\d+\.\d+$') (
        "Version '$Version' is not valid SemVer (MAJOR.MINOR.PATCH). Tag must be formatted as v1.2.3."
    )

    $manifestParams = @{
        Path          = $ManifestPath
        ModuleVersion = $Version
        ErrorAction   = 'Stop'
    }
    Update-ModuleManifest @manifestParams
    Write-Build Green "SetVersion: manifest updated to $Version."
}

task RegisterAcr {
    assert ($env:ACR_LOGIN_SERVER) 'ACR_LOGIN_SERVER environment variable is not set.'
    $repoParams = @{
        Name    = $AcrRepo
        Uri     = "https://$env:ACR_LOGIN_SERVER"
        Trusted = $true
        Force   = $true
    }
    Register-PSResourceRepository @repoParams
    Write-Build Green "RegisterAcr: registered $AcrRepo -> https://$env:ACR_LOGIN_SERVER"
}

task Publish {
    assert ($Version -ne '') 'Version must be set. Was SetVersion skipped?'

    $publishParams = @{
        Path                  = $PackageDir
        Repository            = $AcrRepo
        SkipDependenciesCheck = $true
        ErrorAction           = 'Stop'
    }
    Publish-PSResource @publishParams
    Write-Build Green "Publish: $ModuleName v$Version -> $AcrRepo"
}

# ---------------------------------------------------------------------------
# Composite tasks
# ---------------------------------------------------------------------------

task Build   Clean, Lint, Test, Docs
task .       Build
task Release Lint, Test, AssertDocsClean, SetVersion, Pack, RegisterAcr, Publish
