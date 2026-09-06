$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Invoke-InspectorGraphRequest' {

    InModuleScope EntraObjectInspector {

        BeforeEach {

            Mock Get-MgContext {
                [PSCustomObject]@{
                    AuthType = 'AppOnly'
                }
            }

            Mock Start-Sleep {}
        }

        It 'returns a successful single object' {

            $response =
                [System.Net.Http.HttpResponseMessage]::new(
                    [System.Net.HttpStatusCode]::OK
                )

            $response.Content =
                [System.Net.Http.StringContent]::new(
                    '{"id":"123","displayName":"Test"}'
                )

            Mock Invoke-MgGraphRequest {
                $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications/123'

            $result.Status |
                Should -Be 'Success'

            $result.ObservedValue[0].id |
                Should -Be '123'
        }

        It 'handles an empty Graph collection' {

            $response =
                [System.Net.Http.HttpResponseMessage]::new(
                    [System.Net.HttpStatusCode]::OK
                )

            $response.Content =
                [System.Net.Http.StringContent]::new(
                    '{"value":[]}'
                )

            Mock Invoke-MgGraphRequest {
                $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications/123/owners'

            $result.Status |
                Should -Be 'Success'

            $result.ObservedValue.Count |
                Should -Be 0
        }

        It 'aggregates paginated results' {

            $script:page = 0

            Mock Invoke-MgGraphRequest {

                $script:page++

                if ($script:page -eq 1) {

                    $response =
                        [System.Net.Http.HttpResponseMessage]::new(
                            [System.Net.HttpStatusCode]::OK
                        )

                    $response.Content =
                        [System.Net.Http.StringContent]::new(
                            '{"value":[{"id":"1"}],"@odata.nextLink":"https://graph.microsoft.com/next"}'
                        )

                    return $response
                }

                $response =
                    [System.Net.Http.HttpResponseMessage]::new(
                        [System.Net.HttpStatusCode]::OK
                    )

                $response.Content =
                    [System.Net.Http.StringContent]::new(
                        '{"value":[{"id":"2"}]}'
                    )

                return $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/users'

            $result.Status |
                Should -Be 'Success'

            $result.ObservedValue.Count |
                Should -Be 2

            $result.ObservedValue[0].id |
                Should -Be '1'

            $result.ObservedValue[1].id |
                Should -Be '2'
        }

        It 'maps HTTP 403 to InsufficientPermission' {

            $response =
                [System.Net.Http.HttpResponseMessage]::new(
                    [System.Net.HttpStatusCode]::Forbidden
                )

            Mock Invoke-MgGraphRequest {
                $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications'

            $result.Status |
                Should -Be 'InsufficientPermission'

            $result.ObservedValue |
                Should -Match '403'
        }

        It 'maps HTTP 404 to NotFound' {

            $response =
                [System.Net.Http.HttpResponseMessage]::new(
                    [System.Net.HttpStatusCode]::NotFound
                )

            Mock Invoke-MgGraphRequest {
                $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications/not-found'

            $result.Status |
                Should -Be 'NotFound'
        }

        It 'retries HTTP 429 and honors Retry-After' {

            $script:callCount = 0

            Mock Invoke-MgGraphRequest {

                $script:callCount++

                if ($script:callCount -eq 1) {

                    $response =
                        [System.Net.Http.HttpResponseMessage]::new(
                            [System.Net.HttpStatusCode]::TooManyRequests
                        )

                    $response.Headers.Add(
                        'Retry-After',
                        '1'
                    )

                    return $response
                }

                $response =
                    [System.Net.Http.HttpResponseMessage]::new(
                        [System.Net.HttpStatusCode]::OK
                    )

                $response.Content =
                    [System.Net.Http.StringContent]::new(
                        '{"id":"recovered"}'
                    )

                return $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications'

            $result.Status |
                Should -Be 'Success'

            $script:callCount |
                Should -Be 2

            Should-Invoke `
                Start-Sleep `
                -Times 1 `
                -Exactly
        }

        It 'retries 429 when Graph throws an HTTP exception' {

            $script:callCount = 0

            Mock Invoke-MgGraphRequest {

                $script:callCount++

                if ($script:callCount -eq 1) {

                    $response =
                        [System.Net.Http.HttpResponseMessage]::new(
                            [System.Net.HttpStatusCode]::TooManyRequests
                        )

                    $response.Headers.Add(
                        'Retry-After',
                        '1'
                    )

                    $exception =
                        [System.Exception]::new(
                            'Too Many Requests'
                        )

                    $exception |
                        Add-Member `
                            -NotePropertyName Response `
                            -NotePropertyValue $response `
                            -Force

                    throw $exception
                }

                $response =
                    [System.Net.Http.HttpResponseMessage]::new(
                        [System.Net.HttpStatusCode]::OK
                    )

                $response.Content =
                    [System.Net.Http.StringContent]::new(
                        '{"id":"recovered"}'
                    )

                return $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications'

            $result.Status |
                Should -Be 'Success'

            $script:callCount |
                Should -Be 2
        }

        It 'reports throttling after retry exhaustion' {

            $response =
                [System.Net.Http.HttpResponseMessage]::new(
                    [System.Net.HttpStatusCode]::TooManyRequests
                )

            $response.Headers.Add(
                'Retry-After',
                '1'
            )

            Mock Invoke-MgGraphRequest {
                $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications' `
                    -MaxRetries 1

            $result.Status |
                Should -Be 'Throttled'

            $result.ObservedValue |
                Should -Match '429'
        }

        It 'returns Failed when Graph returns malformed JSON' {

            $response =
                [System.Net.Http.HttpResponseMessage]::new(
                    [System.Net.HttpStatusCode]::OK
                )

            $response.Content =
                [System.Net.Http.StringContent]::new(
                    '{invalid-json'
                )

            Mock Invoke-MgGraphRequest {
                $response
            }

            $result =
                Invoke-InspectorGraphRequest `
                    -Uri 'https://graph.microsoft.com/v1.0/applications'

            $result.Status |
                Should -Be 'Failed'

            $result.Limitations |
                Should -Contain 'Graph request raised an exception.'
        }
    }
}
