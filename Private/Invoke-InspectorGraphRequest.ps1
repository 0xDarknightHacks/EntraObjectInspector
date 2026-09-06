function Invoke-InspectorGraphRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$RequiredPermission = "Unknown",

        [ValidateRange(0, 10)]
        [int]$MaxRetries = 5,

        [AllowNull()]
        [object]$RuntimeTelemetry
    )

    $originalUri = $Uri
    $retryCount = 0
    $allResults = @()

    if ($null -eq $RuntimeTelemetry) {
        $RuntimeTelemetry =
            Get-Variable `
                -Name 'InspectorCurrentRuntimeTelemetry' `
                -Scope Script `
                -ValueOnly `
                -ErrorAction SilentlyContinue
    }

    $evidence = @{
        SourceEndpoint     = $originalUri
        RequiredPermission = $RequiredPermission
        CollectionTime     = (Get-Date).ToUniversalTime().ToString("o")
        Status             = "Pending"
        ObservedValue      = $null
        Limitations        = @()
    }

    if (-not (Get-MgContext)) {
        $evidence.Status = "Failed"
        $evidence.ObservedValue = "Not connected to Microsoft Graph."
        $result = [PSCustomObject]$evidence
        Add-InspectorGraphTelemetryRecord -Telemetry $RuntimeTelemetry -GraphResult $result
        return $result
    }

    do {
        try {
            Add-InspectorGraphTransportTelemetryRecord `
                -Telemetry $RuntimeTelemetry `
                -TransportKind 'Single' `
                -LogicalSubrequestCount 1

            $response = Invoke-MgGraphRequest `
                -Uri $Uri `
                -Method GET `
                -OutputType HttpResponseMessage

            $statusCode = [int]$response.StatusCode

            # 429 = Graph throttling; 503 = transient service unavailability.
            if ($statusCode -in @(429, 503)) {
                if ($retryCount -ge $MaxRetries) {
                    $evidence.Status = if ($statusCode -eq 429) {
                        "Throttled"
                    }
                    else {
                        "ServiceUnavailable"
                    }

                    $evidence.ObservedValue = "HTTP $statusCode after retry exhaustion."
                    $evidence.Limitations += "Maximum retry count reached."
                    break
                }

                $delay = $null

                if (
                    $statusCode -eq 429 -and
                    $response.Headers.Contains("Retry-After")
                ) {
                    $rawRetryAfter =
                        $response.Headers.GetValues("Retry-After") |
                        Select-Object -First 1

                    $parsedDelay = 0.0

                    if (
                        [double]::TryParse(
                            [string]$rawRetryAfter,
                            [ref]$parsedDelay
                        )
                    ) {
                        $delay = $parsedDelay
                    }
                }

                if ($null -eq $delay) {
                    $baseDelay = [math]::Pow(2, [math]::Min($retryCount, 6))
                    $jitter = (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
                    $delay = [math]::Min($baseDelay + $jitter, 60)
                }

                $retryCount++
                Start-Sleep -Seconds $delay
                continue
            }

            if (-not $response.IsSuccessStatusCode) {
                $evidence.Status = switch ($statusCode) {
                    403 { "InsufficientPermission" }
                    404 { "NotFound" }
                    default { "Failed" }
                }

                $evidence.ObservedValue = "Microsoft Graph returned HTTP $statusCode."
                $evidence.Limitations += "Request failed with HTTP $statusCode."
                break
            }

            $rawContent =
                $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

            if ([string]::IsNullOrWhiteSpace($rawContent)) {
                $content = $null
            }
            else {
                $content = $rawContent | ConvertFrom-Json
            }

            if ($null -eq $content) {
                $Uri = $null
            }
            else {
                # StrictMode-safe property access.
                $valueProperty = $content.PSObject.Properties['value']

                if ($null -ne $valueProperty) {
                    if ($null -ne $valueProperty.Value) {
                        $allResults += @($valueProperty.Value)
                    }

                    $nextLinkProperty =
                        $content.PSObject.Properties['@odata.nextLink']

                    if (
                        $null -ne $nextLinkProperty -and
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$nextLinkProperty.Value
                        )
                    ) {
                        $Uri = [string]$nextLinkProperty.Value
                    }
                    else {
                        $Uri = $null
                    }
                }
                else {
                    $allResults += $content
                    $Uri = $null
                }
            }

            $evidence.Status = "Success"
        }
        catch {
            $statusCode = 0
            $response = $null

            # IMPORTANT: StrictMode-safe. Never access $_.Exception.Response directly.
            $responseProperty =
                $_.Exception.PSObject.Properties['Response']

            if ($null -ne $responseProperty) {
                $response = $responseProperty.Value
            }

            if ($null -ne $response) {
                $statusCode = [int]$response.StatusCode
            }

            if ($statusCode -in @(429, 503) -and $retryCount -lt $MaxRetries) {
                $delay = $null

                if (
                    $statusCode -eq 429 -and
                    $null -ne $response -and
                    $response.Headers.Contains("Retry-After")
                ) {
                    $rawRetryAfter =
                        $response.Headers.GetValues("Retry-After") |
                        Select-Object -First 1

                    $parsedDelay = 0.0

                    if (
                        [double]::TryParse(
                            [string]$rawRetryAfter,
                            [ref]$parsedDelay
                        )
                    ) {
                        $delay = $parsedDelay
                    }
                }

                if ($null -eq $delay) {
                    $baseDelay = [math]::Pow(2, [math]::Min($retryCount, 6))
                    $jitter = (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
                    $delay = [math]::Min($baseDelay + $jitter, 60)
                }

                $retryCount++
                Start-Sleep -Seconds $delay
                continue
            }

            $evidence.Status = switch ($statusCode) {
                403 { "InsufficientPermission" }
                404 { "NotFound" }
                429 { "Throttled" }
                503 { "ServiceUnavailable" }
                default { "Failed" }
            }

            $evidence.ObservedValue =
                if ($statusCode) {
                    "HTTP $statusCode - $($_.Exception.Message)"
                }
                else {
                    $_.Exception.Message
                }

            $evidence.Limitations += "Graph request raised an exception."
            break
        }

    } while ($Uri)

    if ($evidence.Status -eq "Success") {
        $evidence.ObservedValue = $allResults
    }

    $result = [PSCustomObject]$evidence
    Add-InspectorGraphTelemetryRecord -Telemetry $RuntimeTelemetry -GraphResult $result
    return $result
}
