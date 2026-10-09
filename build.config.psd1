# Build configuration for PermissionAnalyzer
# Consumed by PermissionAnalyzer.build.ps1 — all paths are relative to the repo root.
@{
    ModuleName        = 'PermissionAnalyzer'
    ManifestPath      = 'PermissionAnalyzer.psd1'
    PublicDir         = 'Public'
    PrivateDir        = 'Private'
    TestsDir          = 'Tests'
    DocsDir           = 'docs/commands'
    OutputDir         = 'output'
    PSSASettingsPath  = 'PSScriptAnalyzerSettings.psd1'
    CoveragePaths     = @('Public', 'Private')
    CoverageThreshold = 50
    CoverageFormat    = 'JaCoCo'
    AcrRepoName       = 'HomeACR'
    # Exact PlatyPS version for Docs/AssertDocsClean and every workflow that installs it.
    # Minor releases change generated markdown (1.0.2+ drops [<CommonParameters>] from
    # syntax blocks), so local and CI output only match on one version.
    PlatyPSVersion    = '1.0.3'
}
