#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/New-PAAssignment.ps1')
}

Describe 'New-PAAssignment' {

    BeforeAll {
        $mandatoryParams = @{
            PrincipalId      = '<principal-id>'
            PrincipalType    = 'User'
            RoleDefinitionId = '<role-definition-id>'
            Scope            = '/'
            Source           = 'EntraRole'
            AssignmentType   = 'Direct'
        }
    }

    Context 'Object creation' {

        It 'Creates object with correct PSTypeName' {
            $result = New-PAAssignment @mandatoryParams

            $result.PSObject.TypeNames[0] | Should -Be 'PA.Assignment'
        }

        It 'Returns object with all expected properties' {
            $result = New-PAAssignment @mandatoryParams

            $expectedProperties = @(
                'PrincipalId', 'PrincipalDisplayName', 'PrincipalType',
                'RoleDefinitionId', 'RoleName', 'RoleType',
                'Scope', 'ScopeType',
                'Source', 'AssignmentType', 'Status',
                'CreatedDateTime', 'StartDateTime', 'EndDateTime',
                'ResourceDisplayName', 'ConsentType'
            )
            foreach ($prop in $expectedProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
    }

    Context 'Mandatory fields' {

        It 'Sets mandatory fields correctly' {
            $result = New-PAAssignment @mandatoryParams

            $result.PrincipalId | Should -Be '<principal-id>'
            $result.PrincipalType | Should -Be 'User'
            $result.RoleDefinitionId | Should -Be '<role-definition-id>'
            $result.Scope | Should -Be '/'
            $result.Source | Should -Be 'EntraRole'
            $result.AssignmentType | Should -Be 'Direct'
        }
    }

    Context 'Default values' {

        It 'Defaults PrincipalDisplayName to empty string' {
            $result = New-PAAssignment @mandatoryParams
            $result.PrincipalDisplayName | Should -Be ''
        }

        It 'Defaults RoleName to empty string' {
            $result = New-PAAssignment @mandatoryParams
            $result.RoleName | Should -Be ''
        }

        It 'Defaults RoleType to empty string' {
            $result = New-PAAssignment @mandatoryParams
            $result.RoleType | Should -Be ''
        }

        It 'Defaults ScopeType to empty string' {
            $result = New-PAAssignment @mandatoryParams
            $result.ScopeType | Should -Be ''
        }

        It 'Defaults Status to Active' {
            $result = New-PAAssignment @mandatoryParams
            $result.Status | Should -Be 'Active'
        }

        It 'Defaults CreatedDateTime to null' {
            $result = New-PAAssignment @mandatoryParams
            $result.CreatedDateTime | Should -BeNullOrEmpty
        }

        It 'Defaults StartDateTime to null' {
            $result = New-PAAssignment @mandatoryParams
            $result.StartDateTime | Should -BeNullOrEmpty
        }

        It 'Defaults EndDateTime to null' {
            $result = New-PAAssignment @mandatoryParams
            $result.EndDateTime | Should -BeNullOrEmpty
        }

        It 'Defaults ResourceDisplayName to empty string' {
            $result = New-PAAssignment @mandatoryParams
            $result.ResourceDisplayName | Should -Be ''
        }

        It 'Defaults ConsentType to empty string' {
            $result = New-PAAssignment @mandatoryParams
            $result.ConsentType | Should -Be ''
        }
    }

    Context 'Validation' {

        It 'Rejects invalid PrincipalType' {
            $params = $mandatoryParams.Clone()
            $params.PrincipalType = 'Computer'

            { New-PAAssignment @params } | Should -Throw
        }

        It 'Rejects invalid Source' {
            $params = $mandatoryParams.Clone()
            $params.Source = 'Manual'

            { New-PAAssignment @params } | Should -Throw
        }

        It 'Rejects invalid AssignmentType' {
            $params = $mandatoryParams.Clone()
            $params.AssignmentType = 'Indirect'

            { New-PAAssignment @params } | Should -Throw
        }

        It 'Rejects invalid RoleType when provided' {
            $params = $mandatoryParams.Clone()
            $params['RoleType'] = 'Invalid'

            { New-PAAssignment @params } | Should -Throw
        }

        It 'Rejects invalid ScopeType when provided' {
            $params = $mandatoryParams.Clone()
            $params['ScopeType'] = 'Invalid'

            { New-PAAssignment @params } | Should -Throw
        }
    }

    Context 'Full parameterization' {

        It 'Accepts all optional parameters via splatting' {
            $now = [datetime]::UtcNow
            $fullParams = @{
                PrincipalId         = '<principal-id>'
                PrincipalDisplayName = 'Test User'
                PrincipalType       = 'ServicePrincipal'
                RoleDefinitionId    = '<role-definition-id>'
                RoleName            = 'Global Administrator'
                RoleType            = 'BuiltIn'
                Scope               = '/administrativeUnits/<au-id>'
                ScopeType           = 'AdministrativeUnit'
                Source              = 'PimEntra'
                AssignmentType      = 'Eligible'
                Status              = 'Provisioned'
                CreatedDateTime     = $now.AddDays(-30)
                StartDateTime       = $now.AddDays(-30)
                EndDateTime         = $now.AddDays(60)
                ResourceDisplayName = 'Microsoft Graph'
                ConsentType         = 'AllPrincipals'
            }
            $result = New-PAAssignment @fullParams

            $result.PrincipalDisplayName | Should -Be 'Test User'
            $result.PrincipalType | Should -Be 'ServicePrincipal'
            $result.RoleName | Should -Be 'Global Administrator'
            $result.RoleType | Should -Be 'BuiltIn'
            $result.ScopeType | Should -Be 'AdministrativeUnit'
            $result.Status | Should -Be 'Provisioned'
            $result.CreatedDateTime | Should -Not -BeNullOrEmpty
            $result.StartDateTime | Should -Not -BeNullOrEmpty
            $result.EndDateTime | Should -Not -BeNullOrEmpty
            $result.ResourceDisplayName | Should -Be 'Microsoft Graph'
            $result.ConsentType | Should -Be 'AllPrincipals'
        }
    }

    Context 'Nullable datetime handling' {

        It 'Accepts explicit datetime values' {
            $testDate = [datetime]::new(2026, 1, 15, 0, 0, 0, [System.DateTimeKind]::Utc)
            $params = $mandatoryParams.Clone()
            $params['CreatedDateTime'] = $testDate

            $result = New-PAAssignment @params

            $result.CreatedDateTime | Should -Be $testDate
        }

        It 'Accepts null for nullable datetime parameters' {
            $params = $mandatoryParams.Clone()
            $params['CreatedDateTime'] = $null

            $result = New-PAAssignment @params

            $result.CreatedDateTime | Should -BeNullOrEmpty
        }
    }
}
