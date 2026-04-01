#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/New-PAValidationResult.ps1')
}

Describe 'New-PAValidationResult' {

    Context 'Object creation' {

        It 'Creates object with correct PSTypeName' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'High'
                IsStillValid     = $true
            }
            $result = New-PAValidationResult @params

            $result.PSObject.TypeNames[0] | Should -Be 'PA.ValidationResult'
        }

        It 'Returns object with all expected properties' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'High'
                IsStillValid     = $false
            }
            $result = New-PAValidationResult @params

            $expectedProperties = @(
                'FindingId', 'OriginalCategory', 'OriginalSeverity',
                'IsStillValid', 'CurrentState', 'ValidatedAt', 'Notes'
            )
            foreach ($prop in $expectedProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
    }

    Context 'Mandatory fields' {

        It 'Sets mandatory fields correctly' {
            $params = @{
                FindingId        = 'abc123def456abc1'
                OriginalCategory = 'OverPrivileged'
                OriginalSeverity = 'Critical'
                IsStillValid     = $false
            }
            $result = New-PAValidationResult @params

            $result.FindingId | Should -Be 'abc123def456abc1'
            $result.OriginalCategory | Should -Be 'OverPrivileged'
            $result.OriginalSeverity | Should -Be 'Critical'
            $result.IsStillValid | Should -BeFalse
        }
    }

    Context 'Default values' {

        It 'Defaults CurrentState to empty string' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'High'
                IsStillValid     = $true
            }
            $result = New-PAValidationResult @params

            $result.CurrentState | Should -Be ''
        }

        It 'Defaults ValidatedAt to approximately UtcNow' {
            $before = [datetime]::UtcNow
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'High'
                IsStillValid     = $true
            }
            $result = New-PAValidationResult @params
            $after = [datetime]::UtcNow

            $result.ValidatedAt | Should -BeGreaterOrEqual $before
            $result.ValidatedAt | Should -BeLessOrEqual $after
        }

        It 'Defaults Notes to empty string' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'High'
                IsStillValid     = $true
            }
            $result = New-PAValidationResult @params

            $result.Notes | Should -Be ''
        }
    }

    Context 'Validation' {

        It 'Rejects invalid OriginalCategory' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'BadCategory'
                OriginalSeverity = 'High'
                IsStillValid     = $true
            }

            { New-PAValidationResult @params } | Should -Throw
        }

        It 'Rejects invalid OriginalSeverity' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'Extreme'
                IsStillValid     = $true
            }

            { New-PAValidationResult @params } | Should -Throw
        }
    }

    Context 'Boolean handling' {

        It 'Accepts IsStillValid as true' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'High'
                IsStillValid     = $true
            }
            $result = New-PAValidationResult @params

            $result.IsStillValid | Should -BeTrue
        }

        It 'Accepts IsStillValid as false' {
            $params = @{
                FindingId        = 'a1b2c3d4e5f6a7b8'
                OriginalCategory = 'UnusedAssignment'
                OriginalSeverity = 'High'
                IsStillValid     = $false
            }
            $result = New-PAValidationResult @params

            $result.IsStillValid | Should -BeFalse
        }
    }
}
