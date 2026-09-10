function Get-InspectorReportProperty {
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

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-InspectorReportArray {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return @()
    }

    return @($Value)
}

function ConvertTo-InspectorReportString {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [array]) {
        return (@($Value) | ForEach-Object { [string]$_ }) -join '; '
    }

    if (
        $Value -is [System.Management.Automation.PSCustomObject] -or
        $Value -is [hashtable]
    ) {
        return (
            $Value |
            ConvertTo-Json -Depth 30 -Compress
        )
    }

    return [string]$Value
}


function Get-InspectorTenantPortalBaseUrl {
    [CmdletBinding()]
    param (
        [string]$TenantId = ''
    )

    $baseUrl = 'https://entra.microsoft.com'
    if ([string]::IsNullOrWhiteSpace($TenantId)) { return $baseUrl }

    return "$baseUrl/$([System.Uri]::EscapeDataString($TenantId))"
}

function ConvertTo-InspectorHtmlEncodedText {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value
    )

    return [System.Net.WebUtility]::HtmlEncode(
        (ConvertTo-InspectorReportString $Value)
    )
}

function ConvertTo-InspectorReportSafeHtmlId {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Value,

        [string]$Prefix = 'item'
    )

    $text = ConvertTo-InspectorReportString $Value

    if ([string]::IsNullOrWhiteSpace($text)) {
        $text = [guid]::NewGuid().ToString()
    }

    $safe =
        ($text -replace '[^A-Za-z0-9\-_:.]', '-').Trim('-')

    if ([string]::IsNullOrWhiteSpace($safe)) {
        $safe = [guid]::NewGuid().ToString()
    }

    return "$Prefix-$safe"
}

function New-InspectorReportLinkList {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$Value,

        [Parameter(Mandatory)]
        [string]$Prefix,

        [int]$MaxInline = 6,

        [switch]$AsLinks
    )

    $items = @(
        @($Value) |
            Where-Object {
                $null -ne $_ -and
                -not [string]::IsNullOrWhiteSpace([string]$_)
            } |
            Select-Object -Unique
    )

    if (@($items).Count -eq 0) {
        return ''
    }

    $links = @(
        foreach ($item in @($items)) {
            $encodedText = ConvertTo-InspectorHtmlEncodedText $item
            if ($AsLinks) {
                $targetId = "$Prefix-$([System.Uri]::EscapeDataString([string]$item))"
                "<a class=""xref"" href=""#$(ConvertTo-InspectorHtmlEncodedText $targetId)"">$encodedText</a>"
            }
            else {
                "<span class=""xref"">$encodedText</span>"
            }
        }
    )

    if (@($links).Count -le $MaxInline) {
        return (@($links) -join ', ')
    }

    $visible =
        @(@($links) | Select-Object -First $MaxInline) -join ', '

    $hidden =
        @(@($links) | Select-Object -Skip $MaxInline) -join ', '

    return "<details class=""inline-details""><summary>$(@($items).Count) references</summary>$visible<span class=""xref-more"">, $hidden</span></details>"
}

function ConvertTo-InspectorReportSafeFileName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $safe = $Name

    foreach ($char in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safe = $safe.Replace([string]$char, '-')
    }

    $safe = $safe.Trim()

    if ([string]::IsNullOrWhiteSpace($safe)) {
        return 'entra-assessment-report'
    }

    return $safe
}

function Read-InspectorReportJsonFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $content =
        Get-Content `
            -LiteralPath $Path `
            -Raw `
            -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($content)) {
        return $null
    }

    return $content | ConvertFrom-Json
}

function Get-InspectorReportSeverityOrder {
    [CmdletBinding()]
    param (
        [string]$Severity
    )

    switch ($Severity) {
        'High' { return 1 }
        'Medium' { return 2 }
        'Low' { return 3 }
        'Informational' { return 4 }
        default { return 99 }
    }
}

function Get-InspectorReportStatusClass {
    [CmdletBinding()]
    param (
        [string]$Value
    )

    switch ($Value) {
        'High' { return 'severity-high' }
        'Medium' { return 'severity-medium' }
        'Low' { return 'severity-low' }
        'Informational' { return 'severity-info' }
        'Success' { return 'status-success' }
        'Complete' { return 'status-success' }
        'Resolved' { return 'status-success' }
        'Partial' { return 'status-warning' }
        'Failed' { return 'status-danger' }
        'AttentionRequired' { return 'status-danger' }
        'ReviewRecommended' { return 'status-warning' }
        'InformationalReview' { return 'status-info' }
        'NoObservations' { return 'status-success' }
        default { return 'status-default' }
    }
}

function Get-InspectorReportNormalizedCategory {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Category
    )

    $value =
        ConvertTo-InspectorReportString `
            -Value $Category

    if ([string]::IsNullOrWhiteSpace($value)) {
        return ''
    }

    switch ($value) {
        'AssessmentOverview' { return 'AssessmentOverview' }
        'ConsentGovernance' { return 'Consent' }
        'CredentialHygiene' { return 'Credentials' }
        'PermissionExposure' { return 'Permissions' }
        'ServicePrincipalGovernance' { return 'ServicePrincipal' }
        'UserGovernance' { return 'Users' }
        'GroupGovernance' { return 'Groups' }
        default { return $value }
    }
}

function Get-InspectorReportRowAnchorId {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Row
    )

    $observationId =
        ConvertTo-InspectorReportString `
            (Get-InspectorReportProperty -InputObject $Row -Name 'ObservationId')

    if (-not [string]::IsNullOrWhiteSpace($observationId)) {
        return ConvertTo-InspectorReportSafeHtmlId `
            -Value $observationId `
            -Prefix 'observation'
    }

    $evidenceId =
        ConvertTo-InspectorReportString `
            (Get-InspectorReportProperty -InputObject $Row -Name 'EvidenceId')

    if (-not [string]::IsNullOrWhiteSpace($evidenceId)) {
        return ConvertTo-InspectorReportSafeHtmlId `
            -Value $evidenceId `
            -Prefix 'evidence'
    }

    return ''
}

function New-InspectorReportMetric {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Label,

        [AllowNull()]
        [object]$Value,

        [string]$Hint = '',

        [string]$Status = 'Default'
    )

    return [PSCustomObject][ordered]@{
        Label  = $Label
        Value  = $Value
        Hint   = $Hint
        Status = $Status
    }
}

function ConvertTo-InspectorReportDuration {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Milliseconds
    )

    $value = 0.0

    if ($null -eq $Milliseconds -or -not [double]::TryParse([string]$Milliseconds, [ref]$value)) {
        return 'Not instrumented separately'
    }

    if ($value -lt 1000) {
        return "$([math]::Round($value, 0)) ms"
    }

    $seconds = $value / 1000.0

    if ($seconds -lt 60) {
        return "$([math]::Round($seconds, 1)) sec"
    }

    $wholeSeconds = [int][math]::Round($seconds, 0)
    $minutes = [math]::Floor($wholeSeconds / 60)
    $remainingSeconds = $wholeSeconds % 60

    return "$minutes" + "m $remainingSeconds" + "s"
}

function Get-InspectorReportObservationDisplayName {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Observation
    )

    $affected =
        Get-InspectorReportProperty `
            -InputObject $Observation `
            -Name 'AffectedObject'

    $displayName =
        ConvertTo-InspectorReportString `
            (Get-InspectorReportProperty -InputObject $affected -Name 'DisplayName')

    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        return $displayName
    }

    $objectId =
        ConvertTo-InspectorReportString `
            (Get-InspectorReportProperty -InputObject $affected -Name 'ObjectId')

    if (-not [string]::IsNullOrWhiteSpace($objectId)) {
        return $objectId
    }

    return ''
}

function Get-InspectorReportObservationObjectType {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Observation
    )

    $affected =
        Get-InspectorReportProperty `
            -InputObject $Observation `
            -Name 'AffectedObject'

    return ConvertTo-InspectorReportString `
        (Get-InspectorReportProperty -InputObject $affected -Name 'ObjectType')
}

function Get-InspectorReportObjectDisplayNameFromInsight {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$ObjectInsight
    )

    $sourceObjects =
        @(
            Get-InspectorReportProperty `
                -InputObject $ObjectInsight `
                -Name 'SourceObjects'
        ) |
        Where-Object { $null -ne $_ }

    foreach ($sourceObject in $sourceObjects) {
        $properties =
            Get-InspectorReportProperty `
                -InputObject $sourceObject `
                -Name 'Properties'

        $displayName =
            ConvertTo-InspectorReportString `
                (Get-InspectorReportProperty -InputObject $properties -Name 'DisplayName')

        if (-not [string]::IsNullOrWhiteSpace($displayName)) {
            return $displayName
        }
    }

    return ConvertTo-InspectorReportString `
        (Get-InspectorReportProperty -InputObject $ObjectInsight -Name 'Input')
}

function New-InspectorReportSection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Content,

        [switch]$Collapsed,

        [string]$Summary = ''
    )

    $openAttribute =
        if ($Collapsed) {
            ''
        }
        else {
            ' open'
        }

    if ([string]::IsNullOrWhiteSpace($Summary)) {
        $Summary = $Title
    }

    return @"
<section id="$Id" class="section report-section">
  <details$openAttribute>
    <summary class="section-summary">
      <span>$([System.Net.WebUtility]::HtmlEncode($Title))</span>
      <span class="summary-hint">$([System.Net.WebUtility]::HtmlEncode($Summary))</span>
    </summary>
    <div class="section-body">
      $Content
    </div>
  </details>
</section>
"@
}
