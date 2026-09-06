function Add-InspectorGraphTelemetryRecord {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Telemetry,

        [Parameter(Mandatory)]
        [object]$GraphResult
    )

    $currentRuntimeTelemetry =
        Get-Variable `
            -Name 'InspectorCurrentRuntimeTelemetry' `
            -Scope Script `
            -ValueOnly `
            -ErrorAction SilentlyContinue

    if ($null -ne $currentRuntimeTelemetry) {
        # A tenant inspection's scoped telemetry context is authoritative so a
        # Graph call cannot evade post-snapshot accounting by supplying another
        # telemetry object. Standalone collectors can still pass one explicitly.
        $Telemetry = $currentRuntimeTelemetry
    }

    if ($null -eq $Telemetry) {
        return
    }

    $timestamp = Get-InspectorTelemetryTimestamp
    $status = [string]$GraphResult.Status
    $endpoint = Get-InspectorTelemetryEndpointPattern -Uri ([string]$GraphResult.SourceEndpoint)
    $host = Get-InspectorTelemetryHost -Uri ([string]$GraphResult.SourceEndpoint)

    $Telemetry.GraphRequestSummary.TotalRequests++

    if ($status -eq 'Success') {
        $Telemetry.GraphRequestSummary.SuccessfulRequests++
    }
    else {
        $Telemetry.GraphRequestSummary.FailedRequests++
    }

    if ($status -eq 'Throttled') {
        $Telemetry.GraphRequestSummary.ThrottledRequests++
        $Telemetry.ThrottlingSummary.ThrottledRequests++
    }

    if (-not $Telemetry.GraphRequestSummary.FirstGraphRequestAt) {
        $Telemetry.GraphRequestSummary.FirstGraphRequestAt = $timestamp
    }

    $Telemetry.GraphRequestSummary.LastGraphRequestAt = $timestamp

    if (-not $Telemetry.GraphRequestsByEndpoint.Contains($endpoint)) {
        $Telemetry.GraphRequestsByEndpoint[$endpoint] = 0
    }
    $Telemetry.GraphRequestsByEndpoint[$endpoint]++

    if (-not $Telemetry.GraphStatusCodeSummary.Contains($status)) {
        $Telemetry.GraphStatusCodeSummary[$status] = 0
    }
    $Telemetry.GraphStatusCodeSummary[$status]++

    if (-not [string]::IsNullOrWhiteSpace($host)) {
        $observed = @($Telemetry.ExternalEndpointSummary.ObservedExternalHosts)
        if ($host -notin $observed) {
            $Telemetry.ExternalEndpointSummary.ObservedExternalHosts = @($observed + $host | Sort-Object -Unique)
        }

        if ($host -notin @($Telemetry.ExternalEndpointSummary.ExpectedExternalHosts)) {
            $unexpected = @($Telemetry.ExternalEndpointSummary.UnexpectedExternalHosts)
            $Telemetry.ExternalEndpointSummary.UnexpectedExternalHosts = @($unexpected + $host | Sort-Object -Unique)
        }
    }
}
