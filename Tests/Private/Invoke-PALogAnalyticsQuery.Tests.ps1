#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/Invoke-PALogAnalyticsQuery.ps1')

    # Stub for Invoke-AzOperationalInsightsQuery (module not loaded in test env)
    function Invoke-AzOperationalInsightsQuery { param($WorkspaceId, $Query, $Timespan, $ErrorAction) }
}

Describe 'Invoke-PALogAnalyticsQuery' {

    BeforeEach {
        Mock Start-Sleep {}
    }

    Context 'Successful query' {

        It 'Returns result rows from a successful query' {
            $mockRows = @(
                [PSCustomObject]@{ UserPrincipalName = 'user1@contoso.com'; Count = 10 },
                [PSCustomObject]@{ UserPrincipalName = 'user2@contoso.com'; Count = 5 }
            )
            Mock Invoke-AzOperationalInsightsQuery {
                [PSCustomObject]@{ Results = $mockRows; Error = $null }
            }

            $queryParams = @{
                WorkspaceId = '<workspace-id>'
                Query       = 'SigninLogs | summarize count() by UserPrincipalName'
            }
            $result = Invoke-PALogAnalyticsQuery @queryParams

            $result | Should -HaveCount 2
            $result[0].UserPrincipalName | Should -Be 'user1@contoso.com'
        }
    }

    Context 'Empty results' {

        It 'Returns empty array when Results is null' {
            Mock Invoke-AzOperationalInsightsQuery {
                [PSCustomObject]@{ Results = $null; Error = $null }
            }

            $queryParams = @{
                WorkspaceId = '<workspace-id>'
                Query       = 'SigninLogs | where 1 == 0'
            }
            $result = Invoke-PALogAnalyticsQuery @queryParams

            $result | Should -HaveCount 0
        }
    }

    Context 'Error property' {

        It 'Throws when response has .Error' {
            Mock Invoke-AzOperationalInsightsQuery {
                [PSCustomObject]@{
                    Results = $null
                    Error   = [PSCustomObject]@{ Message = 'Syntax error in query at line 1' }
                }
            }

            $queryParams = @{
                WorkspaceId = '<workspace-id>'
                Query       = 'bad query syntax !!!'
            }

            { Invoke-PALogAnalyticsQuery @queryParams } | Should -Throw '*Syntax error*'
        }
    }

    Context 'Retry on transient failure' {

        It 'Retries on transient error and succeeds' {
            $script:callCount = 0
            Mock Invoke-AzOperationalInsightsQuery {
                $script:callCount++
                if ($script:callCount -eq 1) {
                    throw [System.Net.Http.HttpRequestException]::new('Connection timeout')
                }
                [PSCustomObject]@{
                    Results = @([PSCustomObject]@{ Col1 = 'val1' })
                    Error   = $null
                }
            }

            $queryParams = @{
                WorkspaceId       = '<workspace-id>'
                Query             = 'SigninLogs | take 1'
                RetryDelaySeconds = 1
            }
            $result = Invoke-PALogAnalyticsQuery @queryParams

            $result | Should -HaveCount 1
            Should -Invoke Invoke-AzOperationalInsightsQuery -Exactly -Times 2
        }
    }

    Context 'No retry on permanent failure' {

        It 'Throws immediately on 400 Bad Request' {
            Mock Invoke-AzOperationalInsightsQuery {
                $ex = [System.Exception]::new('Bad request: syntax error in query')
                throw $ex
            }

            $queryParams = @{
                WorkspaceId       = '<workspace-id>'
                Query             = 'bad query !!!'
                MaxRetries        = 2
                RetryDelaySeconds = 1
            }

            { Invoke-PALogAnalyticsQuery @queryParams } | Should -Throw
            Should -Invoke Invoke-AzOperationalInsightsQuery -Exactly -Times 1
        }
    }

    Context 'MaxRetries exhausted' {

        It 'Throws after all retry attempts fail' {
            Mock Invoke-AzOperationalInsightsQuery {
                throw [System.Net.Http.HttpRequestException]::new('Service unavailable')
            }

            $queryParams = @{
                WorkspaceId       = '<workspace-id>'
                Query             = 'SigninLogs | take 1'
                MaxRetries        = 2
                RetryDelaySeconds = 1
            }

            { Invoke-PALogAnalyticsQuery @queryParams } | Should -Throw '*Service unavailable*'
            Should -Invoke Invoke-AzOperationalInsightsQuery -Exactly -Times 3
        }
    }

    Context 'Timespan parameter' {

        It 'Passes Timespan to the underlying query' {
            Mock Invoke-AzOperationalInsightsQuery {
                [PSCustomObject]@{ Results = @(); Error = $null }
            }

            $queryParams = @{
                WorkspaceId = '<workspace-id>'
                Query       = 'SigninLogs | take 1'
                Timespan    = [timespan]::FromDays(30)
            }
            Invoke-PALogAnalyticsQuery @queryParams

            Should -Invoke Invoke-AzOperationalInsightsQuery -ParameterFilter {
                $Timespan -eq [timespan]::FromDays(30)
            }
        }
    }
}
