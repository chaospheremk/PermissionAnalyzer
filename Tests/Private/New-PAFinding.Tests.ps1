#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/New-PAFinding.ps1')
}

Describe 'New-PAFinding' {

    BeforeAll {
        $mandatoryParams = @{
            Category          = 'UnusedAssignment'
            Severity          = 'High'
            Title             = 'User has Global Administrator with no sign-in in 90 days'
            PrincipalId       = '<principal-id>'
            RoleDefinitionId  = '<role-definition-id>'
            Scope             = '/'
            Recommendation    = 'Remove the Global Administrator assignment'
            RemediationAction = 'Remove'
        }
    }

    Context 'Object creation' {

        It 'Creates object with correct PSTypeName' {
            $result = New-PAFinding @mandatoryParams

            $result.PSObject.TypeNames[0] | Should -Be 'PA.Finding'
        }

        It 'Returns object with all expected properties' {
            $result = New-PAFinding @mandatoryParams

            $expectedProperties = @(
                'FindingId', 'Category', 'Severity', 'Title',
                'PrincipalId', 'PrincipalDisplayName', 'PrincipalType',
                'RoleName', 'RoleDefinitionId', 'Scope', 'Source',
                'ActivityTier', 'DaysSinceActive',
                'Recommendation', 'RemediationAction', 'Details', 'CreatedAt'
            )
            foreach ($prop in $expectedProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
    }

    Context 'Mandatory fields' {

        It 'Sets mandatory fields correctly' {
            $result = New-PAFinding @mandatoryParams

            $result.Category | Should -Be 'UnusedAssignment'
            $result.Severity | Should -Be 'High'
            $result.Title | Should -Be 'User has Global Administrator with no sign-in in 90 days'
            $result.PrincipalId | Should -Be '<principal-id>'
            $result.Recommendation | Should -Be 'Remove the Global Administrator assignment'
            $result.RemediationAction | Should -Be 'Remove'
        }
    }

    Context 'Default values' {

        It 'Defaults PrincipalDisplayName to empty string' {
            $result = New-PAFinding @mandatoryParams
            $result.PrincipalDisplayName | Should -Be ''
        }

        It 'Defaults PrincipalType to empty string' {
            $result = New-PAFinding @mandatoryParams
            $result.PrincipalType | Should -Be ''
        }

        It 'Defaults RoleName to empty string' {
            $result = New-PAFinding @mandatoryParams
            $result.RoleName | Should -Be ''
        }

        It 'Defaults Source to empty string' {
            $result = New-PAFinding @mandatoryParams
            $result.Source | Should -Be ''
        }

        It 'Defaults ActivityTier to null' {
            $result = New-PAFinding @mandatoryParams
            $result.ActivityTier | Should -BeNullOrEmpty
        }

        It 'Defaults DaysSinceActive to null' {
            $result = New-PAFinding @mandatoryParams
            $result.DaysSinceActive | Should -BeNullOrEmpty
        }

        It 'Defaults Details to empty hashtable' {
            $result = New-PAFinding @mandatoryParams
            $result.Details | Should -BeOfType [hashtable]
            $result.Details.Count | Should -Be 0
        }

        It 'Defaults CreatedAt to approximately UtcNow' {
            $before = [datetime]::UtcNow
            $result = New-PAFinding @mandatoryParams
            $after = [datetime]::UtcNow

            $result.CreatedAt | Should -BeGreaterOrEqual $before
            $result.CreatedAt | Should -BeLessOrEqual $after
        }
    }

    Context 'Validation' {

        It 'Rejects invalid Category' {
            $params = $mandatoryParams.Clone()
            $params.Category = 'MissingPermission'

            { New-PAFinding @params } | Should -Throw
        }

        It 'Rejects invalid Severity' {
            $params = $mandatoryParams.Clone()
            $params.Severity = 'Extreme'

            { New-PAFinding @params } | Should -Throw
        }

        It 'Rejects invalid RemediationAction' {
            $params = $mandatoryParams.Clone()
            $params.RemediationAction = 'Escalate'

            { New-PAFinding @params } | Should -Throw
        }
    }

    Context 'Deterministic FindingId' {

        It 'Produces a 16-character lowercase hex string' {
            $result = New-PAFinding @mandatoryParams

            $result.FindingId | Should -MatchExactly '^[0-9a-f]{16}$'
        }

        It 'Produces the expected hash for known inputs' {
            # Pre-computed: SHA256("unusedassignment|<principal-id>|<role-definition-id>|/")[0:16]
            $result = New-PAFinding @mandatoryParams

            $result.FindingId | Should -Be '3f5deed750c90b0f'
        }

        It 'Is deterministic across calls with same inputs' {
            $result1 = New-PAFinding @mandatoryParams
            $result2 = New-PAFinding @mandatoryParams

            $result1.FindingId | Should -Be $result2.FindingId
        }

        It 'Changes when Scope differs' {
            $params1 = $mandatoryParams.Clone()
            $params1.Scope = '/'

            $params2 = $mandatoryParams.Clone()
            $params2.Scope = '/subscriptions/<sub-id>'

            $result1 = New-PAFinding @params1
            $result2 = New-PAFinding @params2

            $result1.FindingId | Should -Not -Be $result2.FindingId
        }

        It 'Is case-insensitive for composite key inputs' {
            # Category is always PascalCase from ValidateSet, but PrincipalId
            # and RoleDefinitionId could vary in casing from different sources.
            # The hash normalises to lowercase.
            $params1 = $mandatoryParams.Clone()
            $params1.PrincipalId = '<PRINCIPAL-ID>'

            $params2 = $mandatoryParams.Clone()
            $params2.PrincipalId = '<principal-id>'

            $result1 = New-PAFinding @params1
            $result2 = New-PAFinding @params2

            $result1.FindingId | Should -Be $result2.FindingId
        }
    }

    Context 'Nullable parameters' {

        It 'Accepts explicit ActivityTier value' {
            $params = $mandatoryParams.Clone()
            $params['ActivityTier'] = 2

            $result = New-PAFinding @params

            $result.ActivityTier | Should -Be 2
        }

        It 'Accepts explicit DaysSinceActive value' {
            $params = $mandatoryParams.Clone()
            $params['DaysSinceActive'] = 45

            $result = New-PAFinding @params

            $result.DaysSinceActive | Should -Be 45
        }
    }
}
