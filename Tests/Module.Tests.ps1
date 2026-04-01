#Requires -Modules Pester

Describe 'PermissionAnalyzer Module' {

    It 'Module manifest is valid' {
        $manifestPath = Join-Path $PSScriptRoot '../PermissionAnalyzer.psd1'
        { Test-ModuleManifest -Path $manifestPath -ErrorAction Stop } | Should -Not -Throw
    }
}
