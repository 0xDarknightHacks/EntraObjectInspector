function Get-InspectorGraphBatchProperty {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in @($InputObject.Keys)) {
            if ([string]$key -ieq $Name) {
                return $InputObject[$key]
            }
        }
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-InspectorGraphBatchObservedObject {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $normalized = [ordered]@{}

        foreach ($key in @($InputObject.Keys)) {
            $normalized[[string]$key] =
                ConvertTo-InspectorGraphBatchObservedObject `
                    -InputObject $InputObject[$key]
        }

        return [PSCustomObject]$normalized
    }

    if (
        $InputObject -is [System.Collections.IEnumerable] -and
        $InputObject -isnot [string]
    ) {
        $normalizedItems = @(
            foreach ($item in $InputObject) {
                ConvertTo-InspectorGraphBatchObservedObject -InputObject $item
            }
        )

        # Prevent PowerShell from unrolling the normalized array so dictionary
        # property values retain the same collection shape as the Graph JSON.
        return ,$normalizedItems
    }

    return $InputObject
}

function ConvertTo-InspectorGraphBatchRelativeUri {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri
    )

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        throw 'A non-empty Microsoft Graph URI is required for a batch subrequest.'
    }

    if ($Uri -notmatch '^https?://') {
        if ($Uri.StartsWith('/v1.0/', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $Uri.Substring('/v1.0'.Length)
        }

        if ($Uri.StartsWith('/')) {
            return $Uri
        }

        return "/$Uri"
    }

    $parsed = [uri]$Uri
    if ($parsed.Host -ine 'graph.microsoft.com') {
        throw "Batch subrequests must target graph.microsoft.com. Received '$($parsed.Host)'."
    }

    if (-not $parsed.AbsolutePath.StartsWith('/v1.0/', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Only Microsoft Graph v1.0 requests are eligible for this batch transport. Received '$Uri'."
    }

    $relativePath = $parsed.AbsolutePath.Substring('/v1.0'.Length)
    return "$relativePath$($parsed.Query)"
}

function Get-InspectorGraphBatchHeaderValue {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Headers,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Headers) {
        return $null
    }

    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($key in @($Headers.Keys)) {
            if ([string]$key -ieq $Name) {
                $value = $Headers[$key]
                if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                    return @($value | Select-Object -First 1)[0]
                }
                return $value
            }
        }
        return $null
    }

    if (
        $null -ne $Headers.PSObject.Methods['Contains'] -and
        $null -ne $Headers.PSObject.Methods['GetValues']
    ) {
        try {
            if ($Headers.Contains($Name)) {
                return @($Headers.GetValues($Name) | Select-Object -First 1)[0]
            }
        }
        catch {
            # Fall through to ordinary property inspection.
        }
    }

    $property = $Headers.PSObject.Properties |
        Where-Object { $_.Name -ieq $Name } |
        Select-Object -First 1

    if ($null -eq $property) {
        return $null
    }

    $propertyValue = $property.Value
    if ($propertyValue -is [System.Collections.IEnumerable] -and $propertyValue -isnot [string]) {
        return @($propertyValue | Select-Object -First 1)[0]
    }

    return $propertyValue
}

function Get-InspectorGraphBatchRetryDelaySeconds {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Headers,

        [ValidateRange(0, 10)]
        [int]$RetryCount = 0
    )

    $rawRetryAfter = Get-InspectorGraphBatchHeaderValue -Headers $Headers -Name 'Retry-After'
    if ($null -ne $rawRetryAfter) {
        $parsedDelay = 0.0
        if ([double]::TryParse([string]$rawRetryAfter, [ref]$parsedDelay)) {
            return [math]::Max(0, $parsedDelay)
        }
    }

    $baseDelay = [math]::Pow(2, [math]::Min($RetryCount, 6))
    $jitter = (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
    return [math]::Min($baseDelay + $jitter, 60)
}

function New-InspectorGraphBatchLogicalResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$State
    )

    $observedValue =
        if ([string]$State.Status -eq 'Success') {
            @($State.Results.ToArray())
        }
        else {
            $State.ErrorObservedValue
        }

    return [PSCustomObject][ordered]@{
        SourceEndpoint     = [string]$State.OriginalUri
        RequiredPermission = [string]$State.RequiredPermission
        CollectionTime     = [string]$State.CollectionTime
        Status             = [string]$State.Status
        ObservedValue      = $observedValue
        Limitations        = @($State.Limitations)
    }
}

function Invoke-InspectorGraphBatchRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]$Requests,

        [ValidateRange(1, 20)]
        [int]$BatchSize = 10,

        [ValidateRange(0, 10)]
        [int]$MaxRetries = 5,

        [AllowNull()]
        [object]$RuntimeTelemetry
    )

    $requestList = @($Requests | Where-Object { $null -ne $_ })
    if ($requestList.Count -eq 0) {
        return @()
    }

    if ($null -eq $RuntimeTelemetry) {
        $RuntimeTelemetry =
            Get-Variable `
                -Name 'InspectorCurrentRuntimeTelemetry' `
                -Scope Script `
                -ValueOnly `
                -ErrorAction SilentlyContinue
    }

    $states = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $requestList.Count; $index++) {
        $request = $requestList[$index]
        $uri = [string](Get-InspectorGraphBatchProperty -InputObject $request -Name 'Uri')
        $requiredPermission = [string](Get-InspectorGraphBatchProperty -InputObject $request -Name 'RequiredPermission')

        $states.Add([PSCustomObject][ordered]@{
            Index              = $index
            OriginalUri        = $uri
            CurrentUri         = $uri
            RequiredPermission = $requiredPermission
            CollectionTime     = (Get-Date).ToUniversalTime().ToString('o')
            Status             = 'Pending'
            Results            = [System.Collections.Generic.List[object]]::new()
            Limitations        = [System.Collections.Generic.List[string]]::new()
            ErrorObservedValue = $null
            RetryCount         = 0
            Completed          = $false
        })
    }

    if (-not (Get-MgContext)) {
        foreach ($state in @($states)) {
            $state.Status = 'Failed'
            $state.ErrorObservedValue = 'Not connected to Microsoft Graph.'
            $state.Limitations.Add('Not connected to Microsoft Graph.')
            $state.Completed = $true
        }
    }
    else {
        while (@($states | Where-Object { -not $_.Completed }).Count -gt 0) {
            $pendingStates = @($states | Where-Object { -not $_.Completed })
            $chunk = @($pendingStates | Select-Object -First $BatchSize)
            $batchRequests = [System.Collections.Generic.List[object]]::new()
            $stateByResponseId = @{}

            foreach ($state in $chunk) {
                try {
                    $relativeUri = ConvertTo-InspectorGraphBatchRelativeUri -Uri ([string]$state.CurrentUri)
                    $responseId = [string]($state.Index + 1)
                    $batchRequests.Add([PSCustomObject][ordered]@{
                        id     = $responseId
                        method = 'GET'
                        url    = $relativeUri
                    })
                    $stateByResponseId[$responseId] = $state
                }
                catch {
                    $state.Status = 'Failed'
                    $state.ErrorObservedValue = $_.Exception.Message
                    $state.Limitations.Add('Request was not eligible for the read-only Microsoft Graph v1.0 batch transport.')
                    $state.Completed = $true
                }
            }

            if ($batchRequests.Count -eq 0) {
                continue
            }

            $batchResponse = $null
            $batchTransportRetryCount = 0
            $batchTransportCompleted = $false
            $batchTransportFailureStatus = $null
            $batchTransportFailureMessage = $null

            while (-not $batchTransportCompleted) {
                try {
                    Add-InspectorGraphTransportTelemetryRecord `
                        -Telemetry $RuntimeTelemetry `
                        -TransportKind 'Batch' `
                        -LogicalSubrequestCount $batchRequests.Count

                    $batchResponse = Invoke-MgGraphRequest `
                        -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                        -Method POST `
                        -Body (@{ requests = $batchRequests.ToArray() } | ConvertTo-Json -Depth 8 -Compress) `
                        -ContentType 'application/json'

                    $batchTransportCompleted = $true
                }
                catch {
                    $statusCode = 0
                    $response = $null
                    $responseProperty = $_.Exception.PSObject.Properties['Response']
                    if ($null -ne $responseProperty) {
                        $response = $responseProperty.Value
                    }
                    if ($null -ne $response) {
                        $statusCode = [int](Get-InspectorGraphBatchProperty -InputObject $response -Name 'StatusCode')
                    }

                    if ($statusCode -in @(429, 503) -and $batchTransportRetryCount -lt $MaxRetries) {
                        $headers = if ($null -ne $response) { Get-InspectorGraphBatchProperty -InputObject $response -Name 'Headers' } else { $null }
                        $delay = Get-InspectorGraphBatchRetryDelaySeconds -Headers $headers -RetryCount $batchTransportRetryCount
                        $batchTransportRetryCount++
                        Start-Sleep -Seconds $delay
                        continue
                    }

                    $batchTransportFailureStatus = switch ($statusCode) {
                        403 { 'InsufficientPermission' }
                        404 { 'NotFound' }
                        429 { 'Throttled' }
                        503 { 'ServiceUnavailable' }
                        default { 'Failed' }
                    }
                    $batchTransportFailureMessage =
                        if ($statusCode) {
                            "HTTP $statusCode - $($_.Exception.Message)"
                        }
                        else {
                            $_.Exception.Message
                        }
                    $batchTransportCompleted = $true
                }
            }

            if ($null -ne $batchTransportFailureStatus) {
                foreach ($state in @($stateByResponseId.Values)) {
                    $state.Status = $batchTransportFailureStatus
                    $state.ErrorObservedValue = $batchTransportFailureMessage
                    $state.Limitations.Add('Microsoft Graph batch transport failed before a subresponse could be processed.')
                    $state.Completed = $true
                }
                continue
            }

            $responseById = @{}
            foreach ($response in @((Get-InspectorGraphBatchProperty -InputObject $batchResponse -Name 'responses'))) {
                $responseId = [string](Get-InspectorGraphBatchProperty -InputObject $response -Name 'id')
                if (-not [string]::IsNullOrWhiteSpace($responseId)) {
                    $responseById[$responseId] = $response
                }
            }

            $retryDelaySeconds = 0.0

            foreach ($responseId in @($stateByResponseId.Keys)) {
                $state = $stateByResponseId[$responseId]
                if (-not $responseById.ContainsKey($responseId)) {
                    $state.Status = 'Failed'
                    $state.ErrorObservedValue = 'Microsoft Graph batch response did not contain the correlated subresponse.'
                    $state.Limitations.Add('Batch response did not contain a correlated subresponse.')
                    $state.Completed = $true
                    continue
                }

                $response = $responseById[$responseId]
                $statusCode = [int](Get-InspectorGraphBatchProperty -InputObject $response -Name 'status')
                $headers = Get-InspectorGraphBatchProperty -InputObject $response -Name 'headers'

                if ($statusCode -in @(429, 503)) {
                    if ($state.RetryCount -ge $MaxRetries) {
                        $state.Status = if ($statusCode -eq 429) { 'Throttled' } else { 'ServiceUnavailable' }
                        $state.ErrorObservedValue = "HTTP $statusCode after retry exhaustion."
                        $state.Limitations.Add('Maximum retry count reached.')
                        $state.Completed = $true
                        continue
                    }

                    $delay = Get-InspectorGraphBatchRetryDelaySeconds -Headers $headers -RetryCount $state.RetryCount
                    $state.RetryCount++
                    if ($delay -gt $retryDelaySeconds) {
                        $retryDelaySeconds = $delay
                    }
                    continue
                }

                if ($statusCode -lt 200 -or $statusCode -ge 300) {
                    $state.Status = switch ($statusCode) {
                        403 { 'InsufficientPermission' }
                        404 { 'NotFound' }
                        default { 'Failed' }
                    }
                    $state.ErrorObservedValue = "Microsoft Graph returned HTTP $statusCode."
                    $state.Limitations.Add("Request failed with HTTP $statusCode.")
                    $state.Completed = $true
                    continue
                }

                $body = Get-InspectorGraphBatchProperty -InputObject $response -Name 'body'
                if ($null -ne $body) {
                    $value = Get-InspectorGraphBatchProperty -InputObject $body -Name 'value'
                    $valuePropertyExists = $false

                    if ($body -is [System.Collections.IDictionary]) {
                        foreach ($key in @($body.Keys)) {
                            if ([string]$key -ieq 'value') {
                                $valuePropertyExists = $true
                                break
                            }
                        }
                    }
                    elseif ($null -ne $body.PSObject.Properties['value']) {
                        $valuePropertyExists = $true
                    }

                    if ($valuePropertyExists) {
                        foreach ($item in @($value)) {
                            if ($null -ne $item) {
                                $state.Results.Add(
                                    (ConvertTo-InspectorGraphBatchObservedObject -InputObject $item)
                                )
                            }
                        }
                    }
                    else {
                        $state.Results.Add(
                            (ConvertTo-InspectorGraphBatchObservedObject -InputObject $body)
                        )
                    }

                    $nextLink = [string](Get-InspectorGraphBatchProperty -InputObject $body -Name '@odata.nextLink')
                    if (-not [string]::IsNullOrWhiteSpace($nextLink)) {
                        $state.CurrentUri = $nextLink
                        continue
                    }
                }

                $state.Status = 'Success'
                $state.Completed = $true
            }

            if ($retryDelaySeconds -gt 0) {
                Start-Sleep -Seconds $retryDelaySeconds
            }
        }
    }

    $results = @(
        foreach ($state in @($states | Sort-Object Index)) {
            $result = New-InspectorGraphBatchLogicalResult -State $state
            Add-InspectorGraphTelemetryRecord -Telemetry $RuntimeTelemetry -GraphResult $result
            $result
        }
    )

    return @($results)
}
