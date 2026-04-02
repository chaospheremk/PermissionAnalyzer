#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Public/Export-PAReport.ps1')

    # --- Helper: build a minimal PA.Finding PSCustomObject ---
    function New-MockFinding {
        [CmdletBinding()]
        param(
            [ValidateNotNullOrEmpty()]
            [string]$FindingId = [System.Guid]::NewGuid().ToString(),

            [string]$Category = 'UnusedAssignment',
            [string]$Severity = 'High',
            [string]$Title = 'Unused role assignment detected',
            [string]$PrincipalId = '<principal-id>',
            [string]$PrincipalDisplayName = 'Alice Admin',
            [string]$PrincipalType = 'User',
            [string]$RoleName = 'Reader',
            [string]$RoleDefinitionId = '<role-def-reader>',
            [string]$Scope = '/subscriptions/<sub-id-1>',
            [string]$Source = 'AzureRbac',
            [int]$ActivityTier = 1,
            [int]$DaysSinceActive = 95,
            [string]$Recommendation = 'Remove the unused role assignment.',
            [string]$RemediationAction = 'Remove',
            [hashtable]$Details = @{ LookbackDays = 90; DataSource = 'LogAnalytics' }
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

Describe 'Export-PAReport' {

    # -------------------------------------------------------------------------
    Context 'PA.ReportResult object shape' {

        BeforeAll {
            $finding = New-MockFinding
            $params = @{
                Findings        = @($finding)
                OutputDirectory = 'TestDrive:\shape-test'
                Format          = @('CSV', 'JSON')
                RunId           = 'shape-20260402-120000'
            }
            $result = Export-PAReport @params
        }

        It 'PSTypeName is PA.ReportResult' {
            $result.PSObject.TypeNames[0] | Should -Be 'PA.ReportResult'
        }

        It 'Has all required properties' {
            $propertyNames = $result.PSObject.Properties.Name
            $propertyNames | Should -Contain 'RunId'
            $propertyNames | Should -Contain 'OutputDirectory'
            $propertyNames | Should -Contain 'OutputFiles'
            $propertyNames | Should -Contain 'Formats'
            $propertyNames | Should -Contain 'FindingCount'
            $propertyNames | Should -Contain 'SeverityCounts'
            $propertyNames | Should -Contain 'CategoryCounts'
            $propertyNames | Should -Contain 'GeneratedAt'
            $propertyNames | Should -Contain 'Duration'
        }

        It 'FindingCount matches input count' {
            $result.FindingCount | Should -Be 1
        }

        It 'OutputFiles count matches Format count' {
            $result.OutputFiles.Count | Should -Be 2
        }

        It 'Duration is populated and non-negative' {
            $result.Duration.TotalMilliseconds | Should -BeGreaterOrEqual 0
        }

        It 'OutputDirectory is an absolute resolved path' {
            [System.IO.Path]::IsPathRooted($result.OutputDirectory) | Should -BeTrue
        }

        It 'Formats matches requested formats' {
            $result.Formats | Should -Contain 'CSV'
            $result.Formats | Should -Contain 'JSON'
            $result.Formats.Count | Should -Be 2
        }
    }

    # -------------------------------------------------------------------------
    Context 'CSV export' {

        BeforeAll {
            $findings = @(
                (New-MockFinding -FindingId 'f-csv-1' -Title 'CSV Finding One' -Details @{ Reason = 'stale'; Days = 95 }),
                (New-MockFinding -FindingId 'f-csv-2' -Title 'CSV Finding Two' -Details @{ Reason = 'inactive' })
            )
            $runId = 'csv-20260402-120000'
            $outDir = 'TestDrive:\csv-test'
            $params = @{
                Findings        = $findings
                OutputDirectory = $outDir
                Format          = @('CSV')
                RunId           = $runId
            }
            Export-PAReport @params
            $csvPath = Join-Path $outDir "PA-Report-$runId.csv"
        }

        It 'Creates CSV file at expected path' {
            $csvPath | Should -Exist
        }

        It 'CSV contains all expected column headers' {
            $csv = Import-Csv -Path $csvPath
            $columns = $csv[0].PSObject.Properties.Name
            $expectedColumns = @(
                'FindingId', 'Category', 'Severity', 'Title',
                'PrincipalId', 'PrincipalDisplayName', 'PrincipalType',
                'RoleName', 'RoleDefinitionId', 'Scope', 'Source',
                'ActivityTier', 'DaysSinceActive', 'Recommendation',
                'RemediationAction', 'DetailsJson', 'CreatedAt'
            )
            foreach ($col in $expectedColumns) {
                $columns | Should -Contain $col
            }
        }

        It 'CSV row count matches finding count' {
            $csv = Import-Csv -Path $csvPath
            $csv.Count | Should -Be 2
        }

        It 'DetailsJson column contains valid JSON' {
            $csv = Import-Csv -Path $csvPath
            foreach ($row in $csv) {
                { $row.DetailsJson | ConvertFrom-Json } | Should -Not -Throw
            }
        }

        It 'DetailsJson round-trips Details hashtable keys' {
            $csv = Import-Csv -Path $csvPath
            $firstRow = $csv | Where-Object { $_.FindingId -eq 'f-csv-1' }
            $parsed = $firstRow.DetailsJson | ConvertFrom-Json
            $parsed.Reason | Should -Be 'stale'
        }

        It 'Empty findings produce a CSV file with headers only' {
            $emptyRunId = 'csv-empty-20260402-120000'
            $emptyDir = 'TestDrive:\csv-empty-test'
            $emptyParams = @{
                Findings        = @()
                OutputDirectory = $emptyDir
                Format          = @('CSV')
                RunId           = $emptyRunId
            }
            Export-PAReport @emptyParams
            $emptyCsvPath = Join-Path $emptyDir "PA-Report-$emptyRunId.csv"
            $emptyCsvPath | Should -Exist
        }
    }

    # -------------------------------------------------------------------------
    Context 'JSON export' {

        BeforeAll {
            $findings = @(
                (New-MockFinding -FindingId 'f-json-1' -Severity 'Critical' -Category 'OverPrivileged' -Details @{ GrantedActions = 100; UsedActions = 2 }),
                (New-MockFinding -FindingId 'f-json-2' -Severity 'High'     -Category 'UnusedAssignment'),
                (New-MockFinding -FindingId 'f-json-3' -Severity 'Medium'   -Category 'UnusedAssignment')
            )
            $runId = 'json-20260402-120000'
            $outDir = 'TestDrive:\json-test'
            $params = @{
                Findings        = $findings
                OutputDirectory = $outDir
                Format          = @('JSON')
                RunId           = $runId
            }
            Export-PAReport @params
            $jsonPath = Join-Path $outDir "PA-Report-$runId.json"
            $envelope = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        }

        It 'Creates JSON file at expected path' {
            $jsonPath | Should -Exist
        }

        It 'JSON is valid and round-trips through ConvertFrom-Json' {
            { Get-Content -Path $jsonPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Envelope FindingCount matches input count' {
            $envelope.FindingCount | Should -Be 3
        }

        It 'Envelope SeverityCounts has correct values for each severity' {
            $envelope.SeverityCounts.Critical | Should -Be 1
            $envelope.SeverityCounts.High     | Should -Be 1
            $envelope.SeverityCounts.Medium   | Should -Be 1
            $envelope.SeverityCounts.Low      | Should -Be 0
            $envelope.SeverityCounts.Info     | Should -Be 0
        }

        It 'Envelope CategoryCounts has correct values for each category' {
            $envelope.CategoryCounts.OverPrivileged      | Should -Be 1
            $envelope.CategoryCounts.UnusedAssignment    | Should -Be 2
            $envelope.CategoryCounts.GroupConsolidation  | Should -Be 0
        }

        It 'Findings array preserves Details as a nested object' {
            $jsonFinding = $envelope.Findings | Where-Object { $_.FindingId -eq 'f-json-1' }
            $jsonFinding.Details.GrantedActions | Should -Be 100
            $jsonFinding.Details.UsedActions    | Should -Be 2
        }
    }

    # -------------------------------------------------------------------------
    Context 'HTML export' {

        BeforeAll {
            $finding = New-MockFinding -Title 'HTML Visibility Test Finding' -Severity 'Critical'
            $runId = 'html-20260402-120000'
            $outDir = 'TestDrive:\html-test'
            $params = @{
                Findings        = @($finding)
                OutputDirectory = $outDir
                Format          = @('HTML')
                RunId           = $runId
            }
            Export-PAReport @params
            $htmlPath = Join-Path $outDir "PA-Report-$runId.html"
            $htmlContent = Get-Content -Path $htmlPath -Raw
        }

        It 'Creates HTML file at expected path' {
            $htmlPath | Should -Exist
        }

        It 'HTML contains a table element' {
            $htmlContent | Should -Match '<table'
        }

        It 'HTML contains severity count values' {
            $htmlContent | Should -Match 'Critical'
        }

        It 'HTML contains the finding title text' {
            $htmlContent | Should -Match 'HTML Visibility Test Finding'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Summary statistics' {

        It 'SeverityCounts correct with mixed severities' {
            $findings = @(
                (New-MockFinding -Severity 'Critical'),
                (New-MockFinding -Severity 'High'),
                (New-MockFinding -Severity 'High'),
                (New-MockFinding -Severity 'Medium')
            )
            $params = @{
                Findings        = $findings
                OutputDirectory = 'TestDrive:\stats-mixed-sev'
                Format          = @('JSON')
                RunId           = 'stats-sev-20260402'
            }
            $result = Export-PAReport @params

            $result.SeverityCounts.Critical | Should -Be 1
            $result.SeverityCounts.High     | Should -Be 2
            $result.SeverityCounts.Medium   | Should -Be 1
            $result.SeverityCounts.Low      | Should -Be 0
            $result.SeverityCounts.Info     | Should -Be 0
        }

        It 'CategoryCounts correct with mixed categories' {
            $findings = @(
                (New-MockFinding -Category 'UnusedAssignment'),
                (New-MockFinding -Category 'UnusedAssignment'),
                (New-MockFinding -Category 'OverPrivileged'),
                (New-MockFinding -Category 'GroupConsolidation')
            )
            $params = @{
                Findings        = $findings
                OutputDirectory = 'TestDrive:\stats-mixed-cat'
                Format          = @('JSON')
                RunId           = 'stats-cat-20260402'
            }
            $result = Export-PAReport @params

            $result.CategoryCounts.UnusedAssignment   | Should -Be 2
            $result.CategoryCounts.OverPrivileged      | Should -Be 1
            $result.CategoryCounts.GroupConsolidation  | Should -Be 1
        }

        It 'Zero-count severities are still present in SeverityCounts' {
            $findings = @(New-MockFinding -Severity 'High')
            $params = @{
                Findings        = $findings
                OutputDirectory = 'TestDrive:\stats-zero-sev'
                Format          = @('JSON')
                RunId           = 'stats-zerosev-20260402'
            }
            $result = Export-PAReport @params

            $result.SeverityCounts.Keys | Should -Contain 'Critical'
            $result.SeverityCounts.Keys | Should -Contain 'Medium'
            $result.SeverityCounts.Keys | Should -Contain 'Low'
            $result.SeverityCounts.Keys | Should -Contain 'Info'
        }

        It 'Zero-count categories are still present in CategoryCounts' {
            $findings = @(New-MockFinding -Category 'UnusedAssignment')
            $params = @{
                Findings        = $findings
                OutputDirectory = 'TestDrive:\stats-zero-cat'
                Format          = @('JSON')
                RunId           = 'stats-zerocat-20260402'
            }
            $result = Export-PAReport @params

            $result.CategoryCounts.Keys | Should -Contain 'OverPrivileged'
            $result.CategoryCounts.Keys | Should -Contain 'GroupConsolidation'
        }

        It 'Empty findings produce all-zero counts' {
            $params = @{
                Findings        = @()
                OutputDirectory = 'TestDrive:\stats-empty'
                Format          = @('JSON')
                RunId           = 'stats-empty-20260402'
            }
            $result = Export-PAReport @params

            $result.FindingCount                      | Should -Be 0
            $result.SeverityCounts.Critical           | Should -Be 0
            $result.SeverityCounts.High               | Should -Be 0
            $result.SeverityCounts.Medium             | Should -Be 0
            $result.SeverityCounts.Low                | Should -Be 0
            $result.SeverityCounts.Info               | Should -Be 0
            $result.CategoryCounts.UnusedAssignment   | Should -Be 0
            $result.CategoryCounts.OverPrivileged      | Should -Be 0
            $result.CategoryCounts.GroupConsolidation  | Should -Be 0
        }
    }

    # -------------------------------------------------------------------------
    Context 'Output directory handling' {

        It 'Creates directory when it does not exist' {
            $newDir = 'TestDrive:\dir-create-test\nested\output'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $newDir
                Format          = @('JSON')
                RunId           = 'dir-create-20260402'
            }
            Export-PAReport @params

            $newDir | Should -Exist
        }

        It 'Succeeds when output directory already exists' {
            $existingDir = 'TestDrive:\dir-existing-test'
            New-Item -ItemType Directory -Path $existingDir -Force | Out-Null
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $existingDir
                Format          = @('JSON')
                RunId           = 'dir-existing-20260402'
            }
            { Export-PAReport @params } | Should -Not -Throw
        }
    }

    # -------------------------------------------------------------------------
    Context 'RunId parameter' {

        It 'Custom RunId appears in output file names' {
            $customRunId = 'CUSTOM-RUN-ID-001'
            $outDir = 'TestDrive:\runid-custom-test'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $outDir
                Format          = @('CSV')
                RunId           = $customRunId
            }
            Export-PAReport @params

            (Join-Path $outDir "PA-Report-$customRunId.csv") | Should -Exist
        }

        It 'Custom RunId is reflected in the RunId property of the result' {
            $customRunId = 'MY-RUN-20260402'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = 'TestDrive:\runid-prop-test'
                Format          = @('JSON')
                RunId           = $customRunId
            }
            $result = Export-PAReport @params

            $result.RunId | Should -Be $customRunId
        }

        It 'Default RunId produces a file with a timestamp-like name when RunId is omitted' {
            $outDir = 'TestDrive:\runid-default-test'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $outDir
                Format          = @('CSV')
            }
            Export-PAReport @params

            $files = Get-ChildItem -Path $outDir -Filter 'PA-Report-*.csv'
            $files.Count | Should -Be 1
            $files[0].Name | Should -Match 'PA-Report-\d{8}-\d{6}\.csv'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Format parameter' {

        It 'Single format CSV produces exactly one output file' {
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = 'TestDrive:\fmt-csv-only'
                Format          = @('CSV')
                RunId           = 'fmt-csv-20260402'
            }
            $result = Export-PAReport @params

            $result.OutputFiles.Count | Should -Be 1
        }

        It 'Default format produces two files (CSV and JSON)' {
            $outDir = 'TestDrive:\fmt-default'
            $runId = 'fmt-default-20260402'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $outDir
                RunId           = $runId
            }
            $result = Export-PAReport @params

            $result.OutputFiles.Count | Should -Be 2
            (Join-Path $outDir "PA-Report-$runId.csv")  | Should -Exist
            (Join-Path $outDir "PA-Report-$runId.json") | Should -Exist
        }

        It 'All three formats produce exactly three output files' {
            $outDir = 'TestDrive:\fmt-all-three'
            $runId = 'fmt-all-20260402'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $outDir
                Format          = @('CSV', 'JSON', 'HTML')
                RunId           = $runId
            }
            $result = Export-PAReport @params

            $result.OutputFiles.Count | Should -Be 3
            (Join-Path $outDir "PA-Report-$runId.csv")  | Should -Exist
            (Join-Path $outDir "PA-Report-$runId.json") | Should -Exist
            (Join-Path $outDir "PA-Report-$runId.html") | Should -Exist
        }

        It 'Only requested formats are written — no extra files present' {
            $outDir = 'TestDrive:\fmt-no-extras'
            $runId = 'fmt-noextra-20260402'
            $params = @{
                Findings        = @(New-MockFinding)
                OutputDirectory = $outDir
                Format          = @('JSON')
                RunId           = $runId
            }
            Export-PAReport @params

            $allFiles = Get-ChildItem -Path $outDir -Filter "PA-Report-$runId.*"
            $allFiles.Count | Should -Be 1
            $allFiles[0].Extension | Should -Be '.json'
        }
    }

    # -------------------------------------------------------------------------
    Context 'Empty findings' {

        It 'Empty findings with CSV format still creates a CSV file' {
            $runId = 'empty-csv-20260402'
            $outDir = 'TestDrive:\empty-csv'
            $params = @{
                Findings        = @()
                OutputDirectory = $outDir
                Format          = @('CSV')
                RunId           = $runId
            }
            Export-PAReport @params

            (Join-Path $outDir "PA-Report-$runId.csv") | Should -Exist
        }

        It 'Empty findings with JSON format produces valid JSON with FindingCount 0' {
            $runId = 'empty-json-20260402'
            $outDir = 'TestDrive:\empty-json'
            $params = @{
                Findings        = @()
                OutputDirectory = $outDir
                Format          = @('JSON')
                RunId           = $runId
            }
            Export-PAReport @params

            $jsonPath = Join-Path $outDir "PA-Report-$runId.json"
            $jsonPath | Should -Exist
            $envelope = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
            $envelope.FindingCount | Should -Be 0
        }
    }
}
