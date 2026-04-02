#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/New-PARemediationScript.ps1')

    # --- Helper: build a minimal PA.Finding PSCustomObject ---
    function New-MockFinding {
        [CmdletBinding()]
        param(
            [ValidateNotNullOrEmpty()]
            [string]$FindingId = [System.Guid]::NewGuid().ToString(),

            [string]$Category             = 'UnusedAssignment',
            [string]$Severity             = 'High',
            [string]$Title                = 'Unused role assignment detected',
            [string]$PrincipalId          = '<principal-id>',
            [string]$PrincipalDisplayName = 'Alice Admin',
            [string]$PrincipalType        = 'User',
            [string]$RoleName             = 'Reader',
            [string]$RoleDefinitionId     = '<role-def-reader>',
            [string]$Scope                = '/subscriptions/<sub-id-1>',
            [string]$Source               = 'AzureRbac',
            [int]$ActivityTier            = 1,
            [int]$DaysSinceActive         = 95,
            [string]$Recommendation       = 'Remove the unused role assignment.',
            [string]$RemediationAction    = 'Remove',
            [hashtable]$Details           = @{ LookbackDays = 90; DataSource = 'LogAnalytics' }
        )
        [PSCustomObject]@{
            PSTypeName           = 'PA.Finding'
            FindingId            = $FindingId
            Category             = $Category
            Severity             = $Severity
            Title                = $Title
            PrincipalId          = $PrincipalId
            PrincipalDisplayName = $PrincipalDisplayName
            PrincipalType        = $PrincipalType
            RoleName             = $RoleName
            RoleDefinitionId     = $RoleDefinitionId
            Scope                = $Scope
            Source               = $Source
            ActivityTier         = $ActivityTier
            DaysSinceActive      = $DaysSinceActive
            Recommendation       = $Recommendation
            RemediationAction    = $RemediationAction
            Details              = $Details
            CreatedAt            = [datetime]::UtcNow
        }
    }
}

Describe 'New-PARemediationScript' {

    # -------------------------------------------------------------------------
    Context 'PA.RemediationResult object shape' {

        BeforeAll {
            $finding = New-MockFinding
            $params = @{
                Findings        = @($finding)
                OutputDirectory = 'TestDrive:\shape-test'
                RunId           = 'shape-20260402-120000'
            }
            $result = New-PARemediationScript @params
        }

        It 'PSTypeName is PA.RemediationResult' {
            $result.PSObject.TypeNames[0] | Should -Be 'PA.RemediationResult'
        }

        It 'Has all required properties' {
            $propertyNames = $result.PSObject.Properties.Name
            $propertyNames | Should -Contain 'RunId'
            $propertyNames | Should -Contain 'OutputDirectory'
            $propertyNames | Should -Contain 'ScriptPaths'
            $propertyNames | Should -Contain 'OperationCounts'
            $propertyNames | Should -Contain 'FindingCount'
            $propertyNames | Should -Contain 'GeneratedAt'
            $propertyNames | Should -Contain 'Duration'
        }

        It 'FindingCount matches input count' {
            $result.FindingCount | Should -Be 1
        }

        It 'Duration is populated and non-negative' {
            $result.Duration.TotalMilliseconds | Should -BeGreaterOrEqual 0
        }

        It 'OutputDirectory is an absolute resolved path' {
            [System.IO.Path]::IsPathRooted($result.OutputDirectory) | Should -BeTrue
        }

        It 'ScriptPaths count matches number of distinct RemediationAction types in input' {
            $result.ScriptPaths.Count | Should -Be 1
        }

        It 'GeneratedAt is a UTC datetime' {
            $result.GeneratedAt | Should -BeOfType [datetime]
        }
    }

    # -------------------------------------------------------------------------
    Context 'Script file generation' {

        BeforeAll {
            $runId = 'filegen-20260402-120000'
        }

        It 'Remove findings produce PA-Remediation-Remove-{RunId}.ps1' {
            $finding = New-MockFinding -RemediationAction 'Remove'
            $outDir = 'TestDrive:\filegen-remove'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params

            (Join-Path $outDir "PA-Remediation-Remove-$runId.ps1") | Should -Exist
        }

        It 'Downgrade findings produce PA-Remediation-Downgrade-{RunId}.ps1' {
            $finding = New-MockFinding -RemediationAction 'Downgrade'
            $outDir = 'TestDrive:\filegen-downgrade'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params

            (Join-Path $outDir "PA-Remediation-Downgrade-$runId.ps1") | Should -Exist
        }

        It 'ConsolidateToGroup findings produce PA-Remediation-ConsolidateToGroup-{RunId}.ps1' {
            $finding = New-MockFinding -RemediationAction 'ConsolidateToGroup'
            $outDir = 'TestDrive:\filegen-consolidate'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params

            (Join-Path $outDir "PA-Remediation-ConsolidateToGroup-$runId.ps1") | Should -Exist
        }

        It 'ReviewEligible findings produce PA-Remediation-ReviewEligible-{RunId}.ps1' {
            $finding = New-MockFinding -RemediationAction 'ReviewEligible'
            $outDir = 'TestDrive:\filegen-revieweligible'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params

            (Join-Path $outDir "PA-Remediation-ReviewEligible-$runId.ps1") | Should -Exist
        }

        It 'Only scripts for present action types are created — no extra files written' {
            $finding = New-MockFinding -RemediationAction 'Remove'
            $outDir = 'TestDrive:\filegen-noextras'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params

            $allScripts = Get-ChildItem -Path $outDir -Filter 'PA-Remediation-*.ps1'
            $allScripts.Count | Should -Be 1
        }
    }

    # -------------------------------------------------------------------------
    Context 'OperationCounts' {

        It 'Correct counts with mixed findings' {
            $findings = @(
                (New-MockFinding -FindingId 'f-op-1' -RemediationAction 'Remove'),
                (New-MockFinding -FindingId 'f-op-2' -RemediationAction 'Remove'),
                (New-MockFinding -FindingId 'f-op-3' -RemediationAction 'Downgrade'),
                (New-MockFinding -FindingId 'f-op-4' -RemediationAction 'ConsolidateToGroup')
            )
            $params = @{
                Findings        = $findings
                OutputDirectory = 'TestDrive:\opcounts-mixed'
                RunId           = 'opcounts-20260402'
            }
            $result = New-PARemediationScript @params

            $result.OperationCounts['Remove']             | Should -Be 2
            $result.OperationCounts['Downgrade']          | Should -Be 1
            $result.OperationCounts['ConsolidateToGroup'] | Should -Be 1
        }

        It 'Zero counts for absent action types are present in OperationCounts' {
            $finding = New-MockFinding -RemediationAction 'Remove'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = 'TestDrive:\opcounts-zeros'
                RunId           = 'opcounts-zero-20260402'
            }
            $result = New-PARemediationScript @params

            $result.OperationCounts['Downgrade']          | Should -Be 0
            $result.OperationCounts['ConsolidateToGroup'] | Should -Be 0
            $result.OperationCounts['ReviewEligible']     | Should -Be 0
            $result.OperationCounts['ReduceScope']        | Should -Be 0
        }

        It 'All five OperationCounts keys are always present' {
            $finding = New-MockFinding -RemediationAction 'ReviewEligible'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = 'TestDrive:\opcounts-allkeys'
                RunId           = 'opcounts-keys-20260402'
            }
            $result = New-PARemediationScript @params

            $result.OperationCounts.Keys | Should -Contain 'Remove'
            $result.OperationCounts.Keys | Should -Contain 'Downgrade'
            $result.OperationCounts.Keys | Should -Contain 'ConsolidateToGroup'
            $result.OperationCounts.Keys | Should -Contain 'ReviewEligible'
            $result.OperationCounts.Keys | Should -Contain 'ReduceScope'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Remove script content' {

        BeforeAll {
            $runId = 'remove-content-20260402-120000'
            $outDir = 'TestDrive:\remove-content'
            $azureRbacFinding = New-MockFinding `
                -FindingId 'f-remove-az' `
                -Source 'AzureRbac' `
                -PrincipalId '<principal-id>' `
                -RemediationAction 'Remove'
            $params = @{
                Findings        = @($azureRbacFinding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params
            $scriptPath    = Join-Path $outDir "PA-Remediation-Remove-$runId.ps1"
            $scriptContent = Get-Content -Path $scriptPath -Raw
        }

        It 'Remove script contains #Requires -Version 7.0' {
            $scriptContent | Should -Match '#Requires -Version 7\.0'
        }

        It 'Remove script contains SupportsShouldProcess' {
            $scriptContent | Should -Match 'SupportsShouldProcess'
        }

        It 'Remove script contains UNCOMMENT TO EXECUTE marker' {
            $scriptContent | Should -Match 'UNCOMMENT TO EXECUTE'
        }

        It 'AzureRbac source finding references Remove-AzRoleAssignment' {
            $scriptContent | Should -Match 'Remove-AzRoleAssignment'
        }

        It 'EntraRole source finding references Remove-MgRoleManagement' {
            $entraRunId = 'remove-entra-20260402-120000'
            $entraOutDir = 'TestDrive:\remove-entra'
            $entraFinding = New-MockFinding `
                -FindingId 'f-remove-entra' `
                -Source 'EntraRole' `
                -PrincipalId '<principal-id-entra>' `
                -RemediationAction 'Remove'
            $entraParams = @{
                Findings        = @($entraFinding)
                OutputDirectory = $entraOutDir
                RunId           = $entraRunId
            }
            New-PARemediationScript @entraParams
            $entraScript = Get-Content -Path (Join-Path $entraOutDir "PA-Remediation-Remove-$entraRunId.ps1") -Raw

            $entraScript | Should -Match 'Remove-MgRoleManagement'
        }

        It 'AppPermission source finding references Remove-MgServicePrincipalAppRoleAssignment' {
            $appRunId = 'remove-app-20260402-120000'
            $appOutDir = 'TestDrive:\remove-app'
            $appFinding = New-MockFinding `
                -FindingId 'f-remove-app' `
                -Source 'AppPermission' `
                -PrincipalId '<principal-id-app>' `
                -RemediationAction 'Remove'
            $appParams = @{
                Findings        = @($appFinding)
                OutputDirectory = $appOutDir
                RunId           = $appRunId
            }
            New-PARemediationScript @appParams
            $appScript = Get-Content -Path (Join-Path $appOutDir "PA-Remediation-Remove-$appRunId.ps1") -Raw

            $appScript | Should -Match 'Remove-MgServicePrincipalAppRoleAssignment'
        }

        It 'Remove script contains the PrincipalId from the finding' {
            $scriptContent | Should -Match '<principal-id>'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Downgrade script content' {

        BeforeAll {
            $runId   = 'downgrade-content-20260402-120000'
            $outDir  = 'TestDrive:\downgrade-content'
            $finding = New-MockFinding `
                -FindingId 'f-downgrade-1' `
                -RemediationAction 'Downgrade' `
                -RoleName 'User Access Administrator' `
                -Details @{
                    GapRatio           = 0.75
                    GrantedNamespaces  = @('microsoft.directory/users', 'microsoft.directory/groups')
                    UsedNamespaces     = @('microsoft.directory/users')
                    UnusedNamespaces   = @('microsoft.directory/groups')
                }
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params
            $scriptPath    = Join-Path $outDir "PA-Remediation-Downgrade-$runId.ps1"
            $scriptContent = Get-Content -Path $scriptPath -Raw
        }

        It 'Downgrade script contains ADVISORY text' {
            $scriptContent | Should -Match 'ADVISORY'
        }

        It 'Downgrade script contains the finding RoleName' {
            $scriptContent | Should -Match 'User Access Administrator'
        }

        It 'Downgrade script references gap ratio or namespace information from Details' {
            $scriptContent | Should -Match '(GapRatio|0\.75|microsoft\.directory|GrantedNamespaces|UnusedNamespaces)'
        }
    }

    # -------------------------------------------------------------------------
    Context 'ConsolidateToGroup script content' {

        BeforeAll {
            $runId   = 'consolidate-content-20260402-120000'
            $outDir  = 'TestDrive:\consolidate-content'
            $finding = New-MockFinding `
                -FindingId 'f-consolidate-1' `
                -RemediationAction 'ConsolidateToGroup' `
                -RoleName 'Reader' `
                -Details @{
                    PrincipalCount = 3
                    PrincipalIds   = @('<principal-1>', '<principal-2>', '<principal-3>')
                    PrincipalNames = @('User 1', 'User 2', 'User 3')
                }
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params
            $scriptPath    = Join-Path $outDir "PA-Remediation-ConsolidateToGroup-$runId.ps1"
            $scriptContent = Get-Content -Path $scriptPath -Raw
        }

        It 'ConsolidateToGroup script references New-MgGroup' {
            $scriptContent | Should -Match 'New-MgGroup'
        }

        It 'ConsolidateToGroup script contains PrincipalIds from Details' {
            $scriptContent | Should -Match '<principal-1>'
            $scriptContent | Should -Match '<principal-2>'
            $scriptContent | Should -Match '<principal-3>'
        }

        It 'ConsolidateToGroup script contains the RoleName from the finding' {
            $scriptContent | Should -Match 'Reader'
        }
    }

    # -------------------------------------------------------------------------
    Context 'ReviewEligible script content' {

        BeforeAll {
            $runId   = 'revieweligible-content-20260402-120000'
            $outDir  = 'TestDrive:\revieweligible-content'
            $finding = New-MockFinding `
                -FindingId 'f-revieweligible-1' `
                -RemediationAction 'ReviewEligible' `
                -RoleName 'Privileged Role Administrator' `
                -PrincipalDisplayName 'Bob Builder'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            New-PARemediationScript @params
            $scriptPath    = Join-Path $outDir "PA-Remediation-ReviewEligible-$runId.ps1"
            $scriptContent = Get-Content -Path $scriptPath -Raw
        }

        It 'ReviewEligible script contains manual review or ADVISORY language' {
            $scriptContent | Should -Match '(manual review|ADVISORY)'
        }

        It 'ReviewEligible script contains the finding RoleName and PrincipalDisplayName' {
            $scriptContent | Should -Match 'Privileged Role Administrator'
            $scriptContent | Should -Match 'Bob Builder'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Empty findings' {

        It 'Returns a valid PA.RemediationResult with FindingCount 0' {
            $params = @{
                Findings        = @()
                OutputDirectory = 'TestDrive:\empty-findings'
                RunId           = 'empty-20260402-120000'
            }
            $result = New-PARemediationScript @params

            $result.PSObject.TypeNames[0] | Should -Be 'PA.RemediationResult'
            $result.FindingCount          | Should -Be 0
        }

        It 'ScriptPaths is empty array and no script files are created' {
            $outDir = 'TestDrive:\empty-noscripts'
            $params = @{
                Findings        = @()
                OutputDirectory = $outDir
                RunId           = 'empty-noscripts-20260402-120000'
            }
            $result = New-PARemediationScript @params

            $result.ScriptPaths.Count | Should -Be 0
            $scripts = Get-ChildItem -Path $outDir -Filter 'PA-Remediation-*.ps1' -ErrorAction SilentlyContinue
            $scripts.Count | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Output directory handling' {

        It 'Creates output directory when it does not exist' {
            $newDir = 'TestDrive:\dir-create-test\nested\output'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $newDir
                RunId           = 'dir-create-20260402'
            }
            New-PARemediationScript @params

            $newDir | Should -Exist
        }

        It 'Succeeds when output directory already exists' {
            $existingDir = 'TestDrive:\dir-existing-test'
            New-Item -ItemType Directory -Path $existingDir -Force | Out-Null
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $existingDir
                RunId           = 'dir-existing-20260402'
            }
            { New-PARemediationScript @params } | Should -Not -Throw
        }
    }

    # -------------------------------------------------------------------------
    Context 'RunId parameter' {

        It 'Custom RunId appears in generated script file names' {
            $customRunId = 'CUSTOM-RUN-001'
            $outDir = 'TestDrive:\runid-custom-filenames'
            $params = @{
                Findings        = @(New-MockFinding -RemediationAction 'Remove')
                OutputDirectory = $outDir
                RunId           = $customRunId
            }
            New-PARemediationScript @params

            (Join-Path $outDir "PA-Remediation-Remove-$customRunId.ps1") | Should -Exist
        }

        It 'Custom RunId is reflected in the RunId property of the result' {
            $customRunId = 'MY-RUN-20260402'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = 'TestDrive:\runid-prop-test'
                RunId           = $customRunId
            }
            $result = New-PARemediationScript @params

            $result.RunId | Should -Be $customRunId
        }

        It 'Default RunId matches timestamp pattern yyyyMMdd-HHmmss' {
            $outDir = 'TestDrive:\runid-default-test'
            $params = @{
                Findings        = @(New-MockFinding -RemediationAction 'Remove')
                OutputDirectory = $outDir
            }
            $result = New-PARemediationScript @params

            $result.RunId | Should -Match '^\d{8}-\d{6}$'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Mixed action types' {

        BeforeAll {
            $runId = 'mixed-20260402-120000'
            $outDir = 'TestDrive:\mixed-actions'
            $findings = @(
                (New-MockFinding -FindingId 'f-mix-1' -RemediationAction 'Remove'             -Source 'AzureRbac'),
                (New-MockFinding -FindingId 'f-mix-2' -RemediationAction 'Remove'             -Source 'EntraRole'),
                (New-MockFinding -FindingId 'f-mix-3' -RemediationAction 'Downgrade'          -Details @{
                    GapRatio          = 0.75
                    GrantedNamespaces = @('microsoft.directory/users', 'microsoft.directory/groups')
                    UsedNamespaces    = @('microsoft.directory/users')
                    UnusedNamespaces  = @('microsoft.directory/groups')
                }),
                (New-MockFinding -FindingId 'f-mix-4' -RemediationAction 'ConsolidateToGroup' -Details @{
                    PrincipalCount = 3
                    PrincipalIds   = @('<principal-1>', '<principal-2>', '<principal-3>')
                    PrincipalNames = @('User 1', 'User 2', 'User 3')
                })
            )
            $params = @{
                Findings        = $findings
                OutputDirectory = $outDir
                RunId           = $runId
            }
            $script:mixedResult = New-PARemediationScript @params
        }

        It '4 findings with 3 distinct action types produce exactly 3 script files' {
            $script:mixedResult.ScriptPaths.Count | Should -Be 3
        }

        It 'Each expected script file exists at the expected path' {
            (Join-Path $outDir "PA-Remediation-Remove-$runId.ps1")             | Should -Exist
            (Join-Path $outDir "PA-Remediation-Downgrade-$runId.ps1")          | Should -Exist
            (Join-Path $outDir "PA-Remediation-ConsolidateToGroup-$runId.ps1") | Should -Exist
        }

        It 'OperationCounts reflect the distribution across action types' {
            $script:mixedResult.OperationCounts['Remove']             | Should -Be 2
            $script:mixedResult.OperationCounts['Downgrade']          | Should -Be 1
            $script:mixedResult.OperationCounts['ConsolidateToGroup'] | Should -Be 1
            $script:mixedResult.OperationCounts['ReviewEligible']     | Should -Be 0
            $script:mixedResult.OperationCounts['ReduceScope']        | Should -Be 0
        }
    }
}
