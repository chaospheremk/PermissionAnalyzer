#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PAGraphRequest.ps1')

    # Stub for Invoke-MgGraphRequest (module not loaded in test env)
    function Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) }
}

Describe 'Invoke-PAGraphRequest' {

    Context 'Single-page response' {

        It 'Returns items from a single page' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{
                    value             = @(
                        [PSCustomObject]@{ id = '1'; name = 'one' },
                        [PSCustomObject]@{ id = '2'; name = 'two' }
                    )
                    '@odata.nextLink' = $null
                }
            }

            $result = Invoke-PAGraphRequest -Uri '/test'

            $result | Should -HaveCount 2
            Should -Invoke Invoke-MgGraphRequest -Exactly -Times 1
        }
    }

    Context 'Multi-page pagination' {

        It 'Follows nextLink across multiple pages' {
            $script:pageCall = 0
            Mock Invoke-MgGraphRequest {
                $script:pageCall++
                if ($script:pageCall -eq 1) {
                    [PSCustomObject]@{
                        value             = @([PSCustomObject]@{ id = '1' })
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/test?$skip=1'
                    }
                }
                else {
                    [PSCustomObject]@{
                        value             = @([PSCustomObject]@{ id = '2' })
                        '@odata.nextLink' = $null
                    }
                }
            }

            $result = Invoke-PAGraphRequest -Uri '/test'

            $result | Should -HaveCount 2
            Should -Invoke Invoke-MgGraphRequest -Exactly -Times 2
        }
    }

    Context 'MaxPages cap' {

        It 'Stops at MaxPages and emits warning' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{
                    value             = @([PSCustomObject]@{ id = 'item' })
                    '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/test?$skip=999'
                }
            }

            $result = Invoke-PAGraphRequest -Uri '/test' -MaxPages 2 -WarningVariable warnings

            $result | Should -HaveCount 2
            Should -Invoke Invoke-MgGraphRequest -Exactly -Times 2
            $warnings | Should -HaveCount 1
            $warnings[0] | Should -BeLike '*stopped at 2 pages*'
        }
    }

    Context '$select injection' {

        It 'Adds $select query parameter to URI' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            Invoke-PAGraphRequest -Uri '/test' -Select @('id', 'displayName')

            Should -Invoke Invoke-MgGraphRequest -ParameterFilter {
                $Uri -like '*`$select=id,displayName*'
            }
        }
    }

    Context '$filter injection' {

        It 'Adds $filter query parameter to URI' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            Invoke-PAGraphRequest -Uri '/test' -Filter "displayName eq 'Test'"

            Should -Invoke Invoke-MgGraphRequest -ParameterFilter {
                $Uri -like "*`$filter=displayName eq 'Test'*"
            }
        }
    }

    Context '$expand injection' {

        It 'Adds $expand query parameter to URI' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            Invoke-PAGraphRequest -Uri '/test' -Expand 'principal($select=id,displayName)'

            Should -Invoke Invoke-MgGraphRequest -ParameterFilter {
                $Uri -like '*`$expand=principal*'
            }
        }
    }

    Context 'ConsistencyLevel header' {

        It 'Passes ConsistencyLevel header and adds $count=true' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            Invoke-PAGraphRequest -Uri '/test' -ConsistencyLevel 'eventual'

            Should -Invoke Invoke-MgGraphRequest -ParameterFilter {
                $Headers['ConsistencyLevel'] -eq 'eventual' -and
                $Uri -like '*$count=true*'
            }
        }
    }

    Context 'Single-object response' {

        It 'Returns the object directly when no .value property exists' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ id = '123'; displayName = 'Test Object' }
            }

            $result = Invoke-PAGraphRequest -Uri '/test/123'

            $result.id | Should -Be '123'
            $result.displayName | Should -Be 'Test Object'
        }
    }

    Context 'Empty response' {

        It 'Returns empty array when value is empty' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            $result = Invoke-PAGraphRequest -Uri '/test'

            $result | Should -HaveCount 0
        }
    }

    Context 'ApiVersion' {

        It 'Prepends v1.0 by default' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            Invoke-PAGraphRequest -Uri '/test'

            Should -Invoke Invoke-MgGraphRequest -ParameterFilter {
                $Uri -like '/v1.0/test*'
            }
        }

        It 'Prepends beta when specified' {
            Mock Invoke-MgGraphRequest {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            Invoke-PAGraphRequest -Uri '/test' -ApiVersion 'beta'

            Should -Invoke Invoke-MgGraphRequest -ParameterFilter {
                $Uri -like '/beta/test*'
            }
        }
    }
}
