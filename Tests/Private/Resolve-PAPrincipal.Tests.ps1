#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
    . (Join-Path $PSScriptRoot '../../Private/Resolve-PAPrincipal.ps1')

    # Stub for Invoke-PAGraphRequest (tested separately)
    function Invoke-PAGraphRequest { param($Uri, $Select, $Filter, $ApiVersion, $MaxPages, $ConsistencyLevel, $HttpMethod) }
}

Describe 'Resolve-PAPrincipal' {

    Context 'User resolution' {

        It 'Resolves user IDs to display names' {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id              = 'aaaaaaaa-1111-2222-3333-444444444444'
                        displayName     = 'Alice Smith'
                        '@odata.type'   = '#microsoft.graph.user'
                    },
                    [PSCustomObject]@{
                        id              = 'bbbbbbbb-1111-2222-3333-444444444444'
                        displayName     = 'Bob Jones'
                        '@odata.type'   = '#microsoft.graph.user'
                    }
                )
            }

            $ids = @('aaaaaaaa-1111-2222-3333-444444444444', 'bbbbbbbb-1111-2222-3333-444444444444')
            $result = Resolve-PAPrincipal -PrincipalIds $ids

            $result['aaaaaaaa-1111-2222-3333-444444444444'] | Should -Be 'Alice Smith'
            $result['bbbbbbbb-1111-2222-3333-444444444444'] | Should -Be 'Bob Jones'
        }
    }

    Context 'Service principal resolution' {

        It 'Falls back to appDisplayName when displayName is empty' {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id              = 'cccccccc-1111-2222-3333-444444444444'
                        displayName     = $null
                        appDisplayName  = 'My Application'
                        '@odata.type'   = '#microsoft.graph.servicePrincipal'
                    }
                )
            }

            $result = Resolve-PAPrincipal -PrincipalIds @('cccccccc-1111-2222-3333-444444444444')

            $result['cccccccc-1111-2222-3333-444444444444'] | Should -Be 'My Application'
        }

        It 'Uses displayName when present on service principal' {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id              = 'cccccccc-1111-2222-3333-444444444444'
                        displayName     = 'SP Display Name'
                        appDisplayName  = 'App Name'
                        '@odata.type'   = '#microsoft.graph.servicePrincipal'
                    }
                )
            }

            $result = Resolve-PAPrincipal -PrincipalIds @('cccccccc-1111-2222-3333-444444444444')

            $result['cccccccc-1111-2222-3333-444444444444'] | Should -Be 'SP Display Name'
        }
    }

    Context 'Group resolution' {

        It 'Resolves group IDs to display names' {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id              = 'dddddddd-1111-2222-3333-444444444444'
                        displayName     = 'Security Group A'
                        '@odata.type'   = '#microsoft.graph.group'
                    }
                )
            }

            $result = Resolve-PAPrincipal -PrincipalIds @('dddddddd-1111-2222-3333-444444444444')

            $result['dddddddd-1111-2222-3333-444444444444'] | Should -Be 'Security Group A'
        }
    }

    Context 'Deduplication' {

        It 'Deduplicates input IDs before querying' {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id              = 'aaaaaaaa-1111-2222-3333-444444444444'
                        displayName     = 'Alice Smith'
                        '@odata.type'   = '#microsoft.graph.user'
                    }
                )
            }

            $ids = @(
                'aaaaaaaa-1111-2222-3333-444444444444',
                'aaaaaaaa-1111-2222-3333-444444444444',
                'aaaaaaaa-1111-2222-3333-444444444444'
            )
            $result = Resolve-PAPrincipal -PrincipalIds $ids

            Should -Invoke Invoke-PAGraphRequest -Exactly -Times 1
            Should -Invoke Invoke-PAGraphRequest -ParameterFilter {
                # Filter should contain only one ID, not three
                ($Filter -split "'").Count -eq 3  # 'id' produces 3 segments when split on '
            }
        }
    }

    Context 'Batching' {

        It 'Splits into multiple batches when more than 15 IDs' {
            Mock Invoke-PAGraphRequest { @() }

            # Generate 20 unique IDs
            $ids = 1..20 | ForEach-Object {
                "$($_.ToString('D8'))-1111-2222-3333-444444444444"
            }
            Resolve-PAPrincipal -PrincipalIds $ids

            Should -Invoke Invoke-PAGraphRequest -Exactly -Times 2
        }
    }

    Context 'Unresolved IDs' {

        It 'Maps unresolved IDs to placeholder text' {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id              = 'aaaaaaaa-1111-2222-3333-444444444444'
                        displayName     = 'Alice Smith'
                        '@odata.type'   = '#microsoft.graph.user'
                    }
                )
            }

            $ids = @(
                'aaaaaaaa-1111-2222-3333-444444444444',
                'eeeeeeee-1111-2222-3333-444444444444'
            )
            $result = Resolve-PAPrincipal -PrincipalIds $ids

            $result['aaaaaaaa-1111-2222-3333-444444444444'] | Should -Be 'Alice Smith'
            $result['eeeeeeee-1111-2222-3333-444444444444'] | Should -BeLike '`[Deleted or inaccessible: eeeeeeee*'
        }
    }

    Context 'Empty input' {

        It 'Returns empty hashtable for empty input' {
            Mock Invoke-PAGraphRequest { @() }

            $result = Resolve-PAPrincipal -PrincipalIds @()

            $result | Should -BeOfType [hashtable]
            $result.Count | Should -Be 0
            Should -Invoke Invoke-PAGraphRequest -Exactly -Times 0
        }
    }

    Context 'Return type' {

        It 'Returns a hashtable' {
            Mock Invoke-PAGraphRequest {
                @(
                    [PSCustomObject]@{
                        id              = 'aaaaaaaa-1111-2222-3333-444444444444'
                        displayName     = 'Test User'
                        '@odata.type'   = '#microsoft.graph.user'
                    }
                )
            }

            $result = Resolve-PAPrincipal -PrincipalIds @('aaaaaaaa-1111-2222-3333-444444444444')

            $result | Should -BeOfType [hashtable]
        }
    }
}
