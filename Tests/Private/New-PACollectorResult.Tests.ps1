#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/New-PACollectorResult.ps1')
}

Describe 'New-PACollectorResult' {

    Context 'Object creation' {

        It 'Creates object with correct PSTypeName' {
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Duration  = [timespan]::FromSeconds(5)
            }
            $result = New-PACollectorResult @resultParams

            $result.PSObject.TypeNames[0] | Should -Be 'PA.CollectorResult'
        }

        It 'Returns object with all expected properties' {
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Duration  = [timespan]::FromSeconds(1)
            }
            $result = New-PACollectorResult @resultParams

            $expectedProperties = @(
                'Collector', 'Status', 'Items', 'ItemCount',
                'Errors', 'Warnings', 'Duration', 'Timestamp'
            )
            foreach ($prop in $expectedProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
    }

    Context 'Mandatory fields' {

        It 'Sets mandatory fields correctly' {
            $duration = [timespan]::FromSeconds(12)
            $resultParams = @{
                Collector = 'Get-PAAzureRbacAssignment'
                Status    = 'Partial'
                Duration  = $duration
            }
            $result = New-PACollectorResult @resultParams

            $result.Collector | Should -Be 'Get-PAAzureRbacAssignment'
            $result.Status | Should -Be 'Partial'
            $result.Duration | Should -Be $duration
        }
    }

    Context 'Default values' {

        It 'Defaults Items to empty array' {
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Duration  = [timespan]::FromSeconds(1)
            }
            $result = New-PACollectorResult @resultParams

            $result.Items | Should -Be @()
        }

        It 'Defaults Errors to empty array' {
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Duration  = [timespan]::FromSeconds(1)
            }
            $result = New-PACollectorResult @resultParams

            $result.Errors | Should -Be @()
        }

        It 'Defaults Warnings to empty array' {
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Duration  = [timespan]::FromSeconds(1)
            }
            $result = New-PACollectorResult @resultParams

            $result.Warnings | Should -Be @()
        }

        It 'Defaults Timestamp to approximately UtcNow' {
            $before = [datetime]::UtcNow
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Duration  = [timespan]::FromSeconds(1)
            }
            $result = New-PACollectorResult @resultParams
            $after = [datetime]::UtcNow

            $result.Timestamp | Should -BeGreaterOrEqual $before
            $result.Timestamp | Should -BeLessOrEqual $after
        }
    }

    Context 'Validation' {

        It 'Rejects invalid Status value' {
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Invalid'
                Duration  = [timespan]::FromSeconds(1)
            }

            { New-PACollectorResult @resultParams } | Should -Throw
        }
    }

    Context 'Computed fields' {

        It 'Computes ItemCount from Items array' {
            $mockItems = @(
                [PSCustomObject]@{ Id = 1 },
                [PSCustomObject]@{ Id = 2 },
                [PSCustomObject]@{ Id = 3 }
            )
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Items     = $mockItems
                Duration  = [timespan]::FromSeconds(1)
            }
            $result = New-PACollectorResult @resultParams

            $result.ItemCount | Should -Be 3
        }

        It 'ItemCount is 0 when Items is default' {
            $resultParams = @{
                Collector = 'Get-PAEntraRoleAssignment'
                Status    = 'Complete'
                Duration  = [timespan]::FromSeconds(1)
            }
            $result = New-PACollectorResult @resultParams

            $result.ItemCount | Should -Be 0
        }
    }
}
