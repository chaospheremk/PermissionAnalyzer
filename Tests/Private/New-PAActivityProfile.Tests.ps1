#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/New-PAActivityProfile.ps1')
}

Describe 'New-PAActivityProfile' {

    BeforeAll {
        $mandatoryParams = @{
            PrincipalId  = '<principal-id>'
            PrincipalType = 'User'
            ActivityTier  = 1
            LookbackDays  = 90
            DataSource    = 'LogAnalytics'
        }
    }

    Context 'Object creation' {

        It 'Creates object with correct PSTypeName' {
            $result = New-PAActivityProfile @mandatoryParams

            $result.PSObject.TypeNames[0] | Should -Be 'PA.ActivityProfile'
        }

        It 'Returns object with all expected properties' {
            $result = New-PAActivityProfile @mandatoryParams

            $expectedProperties = @(
                'PrincipalId', 'PrincipalDisplayName', 'PrincipalType',
                'LastSignInDateTime', 'DaysSinceLastSignIn',
                'LastRoleActivityDateTime', 'DaysSinceLastRoleActivity',
                'GrantedActions', 'UsedActions',
                'ActivityTier', 'SignInCount', 'RoleActivityCount',
                'LookbackDays', 'DataSource', 'EvaluatedAt'
            )
            foreach ($prop in $expectedProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
    }

    Context 'Mandatory fields' {

        It 'Sets mandatory fields correctly' {
            $result = New-PAActivityProfile @mandatoryParams

            $result.PrincipalId | Should -Be '<principal-id>'
            $result.PrincipalType | Should -Be 'User'
            $result.ActivityTier | Should -Be 1
            $result.LookbackDays | Should -Be 90
            $result.DataSource | Should -Be 'LogAnalytics'
        }
    }

    Context 'Default values' {

        It 'Defaults PrincipalDisplayName to empty string' {
            $result = New-PAActivityProfile @mandatoryParams
            $result.PrincipalDisplayName | Should -Be ''
        }

        It 'Defaults GrantedActions to empty array' {
            $result = New-PAActivityProfile @mandatoryParams
            $result.GrantedActions | Should -Be @()
        }

        It 'Defaults UsedActions to empty array' {
            $result = New-PAActivityProfile @mandatoryParams
            $result.UsedActions | Should -Be @()
        }

        It 'Defaults SignInCount to 0' {
            $result = New-PAActivityProfile @mandatoryParams
            $result.SignInCount | Should -Be 0
        }

        It 'Defaults RoleActivityCount to 0' {
            $result = New-PAActivityProfile @mandatoryParams
            $result.RoleActivityCount | Should -Be 0
        }

        It 'Defaults EvaluatedAt to approximately UtcNow' {
            $before = [datetime]::UtcNow
            $result = New-PAActivityProfile @mandatoryParams
            $after = [datetime]::UtcNow

            $result.EvaluatedAt | Should -BeGreaterOrEqual $before
            $result.EvaluatedAt | Should -BeLessOrEqual $after
        }

        It 'Defaults LastSignInDateTime to null' {
            $result = New-PAActivityProfile @mandatoryParams
            $result.LastSignInDateTime | Should -BeNullOrEmpty
        }

        It 'Defaults LastRoleActivityDateTime to null' {
            $result = New-PAActivityProfile @mandatoryParams
            $result.LastRoleActivityDateTime | Should -BeNullOrEmpty
        }
    }

    Context 'Validation' {

        It 'Rejects invalid DataSource' {
            $params = $mandatoryParams.Clone()
            $params.DataSource = 'EventLog'

            { New-PAActivityProfile @params } | Should -Throw
        }

        It 'Rejects ActivityTier above 3' {
            $params = $mandatoryParams.Clone()
            $params.ActivityTier = 4

            { New-PAActivityProfile @params } | Should -Throw
        }

        It 'Rejects ActivityTier below 0' {
            $params = $mandatoryParams.Clone()
            $params.ActivityTier = -1

            { New-PAActivityProfile @params } | Should -Throw
        }

        It 'Rejects LookbackDays below 1' {
            $params = $mandatoryParams.Clone()
            $params.LookbackDays = 0

            { New-PAActivityProfile @params } | Should -Throw
        }

        It 'Rejects LookbackDays above 365' {
            $params = $mandatoryParams.Clone()
            $params.LookbackDays = 400

            { New-PAActivityProfile @params } | Should -Throw
        }
    }

    Context 'Computed DaysSinceLastSignIn' {

        It 'Computes DaysSinceLastSignIn from LastSignInDateTime' {
            $params = $mandatoryParams.Clone()
            $params['LastSignInDateTime'] = [datetime]::UtcNow.AddDays(-10)

            $result = New-PAActivityProfile @params

            $result.DaysSinceLastSignIn | Should -BeGreaterOrEqual 10
            $result.DaysSinceLastSignIn | Should -BeLessOrEqual 11
        }

        It 'Sets DaysSinceLastSignIn to null when LastSignInDateTime is null' {
            $result = New-PAActivityProfile @mandatoryParams

            $result.DaysSinceLastSignIn | Should -BeNullOrEmpty
        }
    }

    Context 'Computed DaysSinceLastRoleActivity' {

        It 'Computes DaysSinceLastRoleActivity from LastRoleActivityDateTime' {
            $params = $mandatoryParams.Clone()
            $params['LastRoleActivityDateTime'] = [datetime]::UtcNow.AddDays(-25)

            $result = New-PAActivityProfile @params

            $result.DaysSinceLastRoleActivity | Should -BeGreaterOrEqual 25
            $result.DaysSinceLastRoleActivity | Should -BeLessOrEqual 26
        }

        It 'Sets DaysSinceLastRoleActivity to null when LastRoleActivityDateTime is null' {
            $result = New-PAActivityProfile @mandatoryParams

            $result.DaysSinceLastRoleActivity | Should -BeNullOrEmpty
        }
    }
}
