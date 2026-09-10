function New-InspectorHtmlTable {
    [CmdletBinding()]
    param (
        [object[]]$Rows,

        [string[]]$Columns,

        [string]$EmptyMessage = 'No records.',

        [switch]$Searchable,

        [switch]$SuppressRowAnchors,

        [switch]$EnableReferenceLinks,

        [string]$CssClass = '',

        [string]$DefaultCategory = ''
    )

    $safeRows = @(
        @($Rows) |
            Where-Object { $null -ne $_ }
    )

    if (@($safeRows).Count -eq 0) {
        return "<p class=""empty-state"">$([System.Net.WebUtility]::HtmlEncode($EmptyMessage))</p>"
    }

    $tableClass =
        if ($Searchable) {
            "data-table searchable sortable $CssClass"
        }
        else {
            "data-table $CssClass"
        }

    $html = [System.Collections.Generic.List[string]]::new()
    $html.Add('<div class="table-wrap">')
    $html.Add("<table class=""$tableClass"">")
    $html.Add('<thead><tr>')

    foreach ($column in $Columns) {
        if ($Searchable) {
            $html.Add("<th role=""button"" tabindex=""0"" data-sort=""$($column)"">$(ConvertTo-InspectorHtmlEncodedText $column)</th>")
        }
        else {
            $html.Add("<th>$(ConvertTo-InspectorHtmlEncodedText $column)</th>")
        }
    }

    $html.Add('</tr></thead>')
    $html.Add('<tbody>')

    foreach ($row in $safeRows) {
        $searchParts =
            @(
                $Columns |
                    ForEach-Object {
                        ConvertTo-InspectorReportString `
                            (Get-InspectorReportProperty -InputObject $row -Name $_)
                    }
            )

        $category =
            ConvertTo-InspectorReportString `
                (Get-InspectorReportProperty -InputObject $row -Name 'Category')

        if ([string]::IsNullOrWhiteSpace($category)) {
            $category = $DefaultCategory
        }

        $normalizedCategory =
            Get-InspectorReportNormalizedCategory `
                -Category $category

        if (-not [string]::IsNullOrWhiteSpace($normalizedCategory)) {
            $searchParts += $normalizedCategory
        }

        $searchText =
            ConvertTo-InspectorHtmlEncodedText `
                (@($searchParts) -join ' ')

        $severity =
            ConvertTo-InspectorReportString `
                (Get-InspectorReportProperty -InputObject $row -Name 'Severity')

        $rowAnchorId =
            if ($SuppressRowAnchors) {
                ''
            }
            else {
                Get-InspectorReportRowAnchorId `
                    -Row $row
            }

        $rowIdAttribute =
            if ([string]::IsNullOrWhiteSpace($rowAnchorId)) {
                ''
            }
            else {
                " id=""$rowAnchorId"""
            }

        $html.Add("<tr$rowIdAttribute data-search=""$searchText"" data-severity=""$(ConvertTo-InspectorHtmlEncodedText $severity)"" data-category=""$(ConvertTo-InspectorHtmlEncodedText $normalizedCategory)"">")

        foreach ($column in $Columns) {
            $value =
                Get-InspectorReportProperty `
                    -InputObject $row `
                    -Name $column

            if ($column -in @('Severity', 'Status', 'Label', 'HighestSeverity')) {
                $class = "pill $(Get-InspectorReportStatusClass -Value ([string]$value))"
                $html.Add("<td><span class=""$class"">$(ConvertTo-InspectorHtmlEncodedText $value)</span></td>")
            }
            elseif ($column -in @('ObservationIds', 'ObservationId')) {
                $links =
                    New-InspectorReportLinkList `
                        -Value @($value) `
                        -Prefix 'observation' `
                        -AsLinks:$EnableReferenceLinks

                $html.Add("<td>$links</td>")
            }
            elseif ($column -in @('EvidenceIds', 'EvidenceId')) {
                $links =
                    New-InspectorReportLinkList `
                        -Value @($value) `
                        -Prefix 'evidence' `
                        -AsLinks:$EnableReferenceLinks

                $html.Add("<td>$links</td>")
            }
            elseif ($column -eq 'PortalLink') {
                $portalUrl = [string]$value
                if (
                    $portalUrl.Equals('https://entra.microsoft.com', [System.StringComparison]::OrdinalIgnoreCase) -or
                    $portalUrl.StartsWith('https://entra.microsoft.com/', [System.StringComparison]::OrdinalIgnoreCase)
                ) {
                    $html.Add("<td><a href=""$(ConvertTo-InspectorHtmlEncodedText $portalUrl)"" target=""_blank"" rel=""noopener noreferrer"">Open in Entra</a></td>")
                }
                else {
                    $html.Add('<td></td>')
                }
            }
            else {
                $html.Add("<td>$(ConvertTo-InspectorHtmlEncodedText $value)</td>")
            }
        }

        $html.Add('</tr>')
    }

    $html.Add('</tbody></table>')
    $html.Add('</div>')

    return ($html -join [Environment]::NewLine)
}

function New-InspectorMetricCardsHtml {
    [CmdletBinding()]
    param (
        [object[]]$Metrics
    )

    $html = [System.Collections.Generic.List[string]]::new()
    $html.Add('<div class="metric-grid">')

    foreach ($metric in @($Metrics)) {
        $metricClass = "metric-card $(Get-InspectorReportStatusClass -Value ([string](Get-InspectorReportProperty -InputObject $metric -Name 'Status')))"
        $html.Add("<div class=""$metricClass"">")
        $html.Add("<div class=""metric-label"">$(ConvertTo-InspectorHtmlEncodedText $metric.Label)</div>")
        $html.Add("<div class=""metric-value"">$(ConvertTo-InspectorHtmlEncodedText $metric.Value)</div>")

        if (-not [string]::IsNullOrWhiteSpace([string]$metric.Hint)) {
            $html.Add("<div class=""metric-hint"">$(ConvertTo-InspectorHtmlEncodedText $metric.Hint)</div>")
        }

        $html.Add('</div>')
    }

    $html.Add('</div>')

    return ($html -join [Environment]::NewLine)
}

function New-InspectorReportMetadataPillHtml {
    [CmdletBinding()]
    param (
        [string]$Label,

        [AllowNull()]
        [object]$Value
    )

    $text = ConvertTo-InspectorReportString $Value

    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq 'Not available') {
        return ''
    }

    return "<span class=""pill"" data-highlight-target>$(ConvertTo-InspectorHtmlEncodedText $Label): $(ConvertTo-InspectorHtmlEncodedText $text)</span>"
}

function Get-InspectorReportMetricValue {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$InputObject,

        [string[]]$Names
    )

    foreach ($name in @($Names)) {
        $value = Get-InspectorReportProperty -InputObject $InputObject -Name $name

        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            return $value
        }
    }

    return $null
}

function Get-InspectorReportNormalizedObjectType {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$ObjectType
    )

    $value = ConvertTo-InspectorReportString $ObjectType

    switch -Regex ($value) {
        '^user$' { return 'User' }
        '^riskyuser$' { return 'RiskyUser' }
        '^group$' { return 'Group' }
        '^application$' { return 'Application' }
        '^service\s*principal$' { return 'ServicePrincipal' }
        '^serviceprincipal$' { return 'ServicePrincipal' }
        '^applicationidentity$' { return 'ApplicationIdentity' }
        '^oauth2permissiongrant$' { return 'OAuth2PermissionGrant' }
        '^administrative\s*unit$' { return 'AdministrativeUnit' }
        '^administrativeunit$' { return 'AdministrativeUnit' }
        '^directory\s*role.*$' { return 'DirectoryRole' }
        '^pim.*$' { return 'PimRole' }
        default { return $value }
    }
}

function New-InspectorClientTenantDetailsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
    $manifest = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Manifest'
    $inventoryDetails = Get-InspectorReportProperty -InputObject $ReportModel -Name 'InventoryDetails'
    $activeSkuNames = @(
        @(Get-InspectorReportProperty -InputObject $inventoryDetails -Name 'ActiveSkus') |
        ForEach-Object { Get-InspectorReportMetricValue -InputObject $_ -Names @('Product','SkuPartNumber','SkuId') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Sort-Object -Unique
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $rows.Add([PSCustomObject]@{ Field='Tenant'; Value=$(if (Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantDisplayName','TenantName','DisplayName')) { Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantDisplayName','TenantName','DisplayName') } else { 'Not provided' }) })
    $rows.Add([PSCustomObject]@{ Field='Tenant ID'; Value=$(if (Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantId','TenantID')) { Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantId','TenantID') } else { 'Not provided' }) })
    $rows.Add([PSCustomObject]@{ Field='Active SKUs'; Value=$(if ($activeSkuNames.Count -gt 0) { $activeSkuNames -join ', ' } else { 'Not available' }) })
    if (-not [string]::IsNullOrWhiteSpace([string]$ReportModel.ClientName)) { $rows.Add([PSCustomObject]@{ Field='Client'; Value=$ReportModel.ClientName }) }
    if (-not [string]::IsNullOrWhiteSpace([string]$ReportModel.ConsultantName)) { $rows.Add([PSCustomObject]@{ Field='Prepared by'; Value=$ReportModel.ConsultantName }) }
    $rows.Add([PSCustomObject]@{ Field='Generated'; Value=(Get-InspectorReportProperty -InputObject $ReportModel -Name 'GeneratedAt') })
    $rows.Add([PSCustomObject]@{ Field='Module version'; Value=$(if (Get-InspectorReportMetricValue -InputObject $manifest -Names @('ModuleVersion')) { Get-InspectorReportMetricValue -InputObject $manifest -Names @('ModuleVersion') } else { 'Not provided' }) })

    return @"
<section id="client-tenant-details" class="section">
  <div class="section-header"><h2>Tenant details</h2><span class="muted">Assessment context</span></div>
  $(New-InspectorHtmlTable -Rows $rows -Columns @('Field','Value'))
  <p class="muted">Tenant-level discovered licensing only; Active SKUs are not a per-user licensing compliance result.</p>
</section>
"@
}

function New-InspectorInventoryDetailHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][object]$ReportModel,
        [Parameter(Mandatory)][string]$PropertyName,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Columns,
        [int]$MaximumRows = 0
    )

    $inventoryDetails = Get-InspectorReportProperty -InputObject $ReportModel -Name 'InventoryDetails'
    $allRows = @(Get-InspectorReportProperty -InputObject $inventoryDetails -Name $PropertyName | Where-Object { $null -ne $_ })
    if ($allRows.Count -eq 0) { return '' }

    $visibleRows = if ($MaximumRows -gt 0) { @($allRows | Select-Object -First $MaximumRows) } else { @($allRows) }
    $displayRows = @(
        foreach ($row in $visibleRows) {
            $copy = [ordered]@{}
            foreach ($column in $Columns) { $copy[$column] = Get-InspectorReportProperty -InputObject $row -Name $column }

            $objectType = [string](Get-InspectorReportProperty -InputObject $row -Name 'ObjectType')
            $objectId = [string](Get-InspectorReportProperty -InputObject $row -Name 'ObjectId')
            $appId = [string](Get-InspectorReportProperty -InputObject $row -Name 'AppId')

            $principalType = [string](Get-InspectorReportProperty -InputObject $row -Name 'PrincipalType')
            $principalId = [string](Get-InspectorReportProperty -InputObject $row -Name 'PrincipalId')
            if ([string]::IsNullOrWhiteSpace($objectType) -and -not [string]::IsNullOrWhiteSpace($principalType)) {
                $objectType = $principalType
                $objectId = $principalId
            }

            if ($PropertyName -eq 'AdministrativeUnits') {
                $objectType = 'AdministrativeUnit'
            }

            $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
            $tenantId = ConvertTo-InspectorReportString (Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantId','TenantID'))
            $copy.PortalLink = Get-InspectorPortalLink -ObjectType $objectType -ObjectId $objectId -AppId $appId -TenantId $tenantId
            [PSCustomObject]$copy
        }
    )
    $shownText = if ($visibleRows.Count -lt $allRows.Count) { "Showing $($visibleRows.Count) of $($allRows.Count)" } else { "$($allRows.Count) discovered" }
    $tableColumns = @($Columns)
    if (@($displayRows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.PortalLink) }).Count -gt 0) { $tableColumns += 'PortalLink' }

    return @"
<details class="inventory-detail">
  <summary><span>$Title</span><span class="muted">$shownText</span></summary>
  <div class="context-list">$(New-InspectorHtmlTable -Rows $displayRows -Columns $tableColumns -SuppressRowAnchors)</div>
</details>
"@
}

function New-InspectorSummaryMetricsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
    $highCount = @($ReportModel.AssessmentFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'High' }).Count
    $mediumCount = @($ReportModel.AssessmentFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'Medium' }).Count
    $lowCount = @($ReportModel.AssessmentFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'Low' }).Count
    $findingCount = @($ReportModel.AssessmentFindings | Where-Object { (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')) -ne 'Tenant assessment observation summary' }).Count
    $objectCount = Get-InspectorReportMetricValue -InputObject $summary -Names @('ObjectInsightCount','ObjectsProcessed','TotalObjects')
    $failedCount = Get-InspectorReportMetricValue -InputObject $summary -Names @('FailedCount','FailedObjectCount')

    $metrics = @(
        New-InspectorReportMetric -Label 'High findings' -Value $highCount -Hint 'Review first' -Status $(if ($highCount -gt 0) { 'High' } else { 'Success' })
        New-InspectorReportMetric -Label 'Medium findings' -Value $mediumCount -Hint 'Review after High' -Status $(if ($mediumCount -gt 0) { 'Medium' } else { 'Success' })
        New-InspectorReportMetric -Label 'Low findings' -Value $lowCount -Hint 'Lower priority review' -Status $(if ($lowCount -gt 0) { 'Low' } else { 'Success' })
        New-InspectorReportMetric -Label 'Grouped findings' -Value $findingCount -Hint 'Security issues after grouping' -Status 'Info'
        New-InspectorReportMetric -Label 'Objects inspected' -Value $(if ($null -ne $objectCount) { $objectCount } else { @($ReportModel.ObjectIndex).Count }) -Hint 'Objects in assessment scope' -Status 'Info'
        New-InspectorReportMetric -Label 'Failed objects' -Value $(if ($null -ne $failedCount) { $failedCount } else { 0 }) -Hint 'Incomplete processing' -Status $(if ($null -ne $failedCount -and [int]$failedCount -gt 0) { 'High' } else { 'Success' })
    )

    return @"
<section id="summary-metrics" class="section">
  <div class="section-header">
    <h2>At a glance</h2>
    <span class="muted">Security assessment summary</span>
  </div>
  $(New-InspectorMetricCardsHtml -Metrics $metrics)
</section>
"@
}

function New-InspectorScopeInventoryHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
    $inventory = Get-InspectorReportProperty -InputObject $ReportModel -Name 'ScopeInventory'
    if ($null -eq $inventory) { $inventory = Get-InspectorReportProperty -InputObject $summary -Name 'ScopeInventory' }

    $microsoftPublishedCount = Get-InspectorReportMetricValue -InputObject $inventory -Names @('MicrosoftPublishedServicePrincipals')
    $classificationConfidence = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $inventory -Name 'FirstPartyClassificationConfidence')
    $microsoftPublishedValue = if ($null -ne $microsoftPublishedCount -and $classificationConfidence -ne 'NotClassified') { $microsoftPublishedCount } else { 'Not classified' }

    $rows = @(
        [PSCustomObject]@{ Metric = 'Users discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('UsersDiscovered') }
        [PSCustomObject]@{ Metric = 'App registrations discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('AppRegistrationsDiscovered') }
        [PSCustomObject]@{ Metric = 'Enterprise applications / service principals discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('ServicePrincipalsDiscovered') }
        [PSCustomObject]@{ Metric = 'Microsoft-published service principals'; Count = $microsoftPublishedValue }
        [PSCustomObject]@{ Metric = 'Groups discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('GroupsDiscovered') }
        [PSCustomObject]@{ Metric = 'OAuth2 permission grants discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('OAuth2PermissionGrantsDiscovered') }
        [PSCustomObject]@{ Metric = 'Directory role assignments discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('DirectoryRoleAssignmentsDiscovered') }
        [PSCustomObject]@{ Metric = 'Active role schedule instances collected'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('RoleAssignmentScheduleInstancesDiscovered') }
        [PSCustomObject]@{ Metric = 'Eligible role schedule instances collected'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('RoleEligibilityScheduleInstancesDiscovered') }
        [PSCustomObject]@{ Metric = 'Administrative units discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('AdministrativeUnitsDiscovered') }
        [PSCustomObject]@{ Metric = 'Risky users discovered'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('RiskyUsersDiscovered') }
        [PSCustomObject]@{ Metric = 'Evidence records collected'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('EvidenceRecordsCollected') }
        [PSCustomObject]@{ Metric = 'Failed objects'; Count = Get-InspectorReportMetricValue -InputObject $inventory -Names @('FailedObjects') }
    )

    $evidenceFileName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'EvidenceReportFileName')
    $diagnosticsFileName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'DiagnosticsReportFileName')
    $links = @()
    if (-not [string]::IsNullOrWhiteSpace($evidenceFileName)) { $links += '<a class="nav-button" href="' + (ConvertTo-InspectorHtmlEncodedText $evidenceFileName) + '">Open evidence report</a>' }
    if (-not [string]::IsNullOrWhiteSpace($diagnosticsFileName)) { $links += '<a class="nav-button" href="' + (ConvertTo-InspectorHtmlEncodedText $diagnosticsFileName) + '">Open diagnostics report</a>' }

    $content = @"
<p class="muted">Collection counts and package detail are kept here so the main assessment stays focused on findings.</p>
<div class="technical-links">$($links -join [Environment]::NewLine)</div>
<h3>Assessment scope inventory</h3>
$(New-InspectorHtmlTable -Rows $rows -Columns @('Metric','Count'))
"@

    return New-InspectorReportSection `
        -Id 'technical-appendix' `
        -Title 'Technical appendix' `
        -Summary 'Collection counts and supporting reports' `
        -Content $content `
        -Collapsed
}

function New-InspectorFindingEvidenceHtml {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$ObservationIds,

        [AllowNull()]
        [object[]]$EvidenceIds,

        [string]$EvidenceReportFileName = '',

        [string]$FindingId = ''
    )

    $items = [System.Collections.Generic.List[string]]::new()

    if (-not [string]::IsNullOrWhiteSpace($EvidenceReportFileName) -and -not [string]::IsNullOrWhiteSpace($FindingId)) {
        $findingHref = ConvertTo-InspectorHtmlEncodedText ("$EvidenceReportFileName#finding-$([System.Uri]::EscapeDataString([string]$FindingId))")
        $items.Add("<li><strong><a href=""$findingHref"">Open this grouped finding in the Evidence report</a></strong> — shows the condition, contributing observations, and supporting collection records together.</li>")
    }

    $observationSampleIds =
        @($ObservationIds) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Select-Object -First 10

    foreach ($observationId in $observationSampleIds) {
        if (-not [string]::IsNullOrWhiteSpace([string]$observationId)) {
            $encodedObservationId = ConvertTo-InspectorHtmlEncodedText $observationId
            if (-not [string]::IsNullOrWhiteSpace($EvidenceReportFileName)) {
                $href = ConvertTo-InspectorHtmlEncodedText ("$EvidenceReportFileName#observation-$([System.Uri]::EscapeDataString([string]$observationId))")
                $items.Add("<li>Observation: <a class=""pill"" href=""$href"">$encodedObservationId</a></li>")
            }
            else {
                $items.Add("<li>Observation: <span class=""pill"">$encodedObservationId</span></li>")
            }
        }
    }

    if (@($ObservationIds).Count -gt @($observationSampleIds).Count) {
        $items.Add("<li>Observation IDs truncated: showing $(@($observationSampleIds).Count) of $(@($ObservationIds).Count).</li>")
    }

    $evidenceSampleIds =
        @($EvidenceIds) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Select-Object -First 10

    foreach ($evidenceId in $evidenceSampleIds) {
        if (-not [string]::IsNullOrWhiteSpace([string]$evidenceId)) {
            $encodedEvidenceId = ConvertTo-InspectorHtmlEncodedText $evidenceId
            if (-not [string]::IsNullOrWhiteSpace($EvidenceReportFileName)) {
                $href = ConvertTo-InspectorHtmlEncodedText ("$EvidenceReportFileName#evidence-$([System.Uri]::EscapeDataString([string]$evidenceId))")
                $items.Add("<li>Evidence: <a class=""pill"" href=""$href"">$encodedEvidenceId</a></li>")
            }
            else {
                $items.Add("<li>Evidence: <span class=""pill"">$encodedEvidenceId</span></li>")
            }
        }
    }

    if (@($EvidenceIds).Count -gt @($evidenceSampleIds).Count) {
        $items.Add("<li>Evidence IDs truncated: showing $(@($evidenceSampleIds).Count) of $(@($EvidenceIds).Count).</li>")
    }

    if (
        @(
            @($EvidenceIds) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        ).Count -eq 0
    ) {
        $items.Add('<li>No direct evidence record associated with this observation.</li>')
    }

    return "<details class=""evidence""><summary>Evidence details</summary><ul class=""evidence-list"">$($items -join [Environment]::NewLine)</ul></details>"
}

function Get-InspectorReferenceSourceLabel {
    [CmdletBinding()]
    param ([string]$SourceType)

    switch ($SourceType) {
        'MicrosoftLearn' { return 'Microsoft Learn' }
        'MicrosoftGraph' { return 'Microsoft Graph' }
        'MicrosoftZeroTrust' { return 'Microsoft Zero Trust' }
        'NIST' { return 'NIST' }
        'CIS' { return 'CIS' }
        default { return $SourceType }
    }
}

function New-InspectorOfficialReferencesHtml {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$References
    )

    $items =
        @(
            @($References) |
                Where-Object { $null -ne $_ } |
                Sort-Object ReferenceId -Unique |
                ForEach-Object {
                    $url = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Url')
                    $title = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
                    $sourceType = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'SourceType')
                    $sourceLabel = Get-InspectorReferenceSourceLabel -SourceType $sourceType

                    if ([string]::IsNullOrWhiteSpace($url) -or [string]::IsNullOrWhiteSpace($title)) {
                        return
                    }

                    $summary = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Summary')
                    $summaryHtml = if ([string]::IsNullOrWhiteSpace($summary)) { '' } else { "<br><span class=""muted"">$(ConvertTo-InspectorHtmlEncodedText $summary)</span>" }
                    "<li><a href=""$(ConvertTo-InspectorHtmlEncodedText $url)"" target=""_blank"" rel=""noopener noreferrer"">$(ConvertTo-InspectorHtmlEncodedText $title)</a> <span class=""muted"">$(ConvertTo-InspectorHtmlEncodedText $sourceLabel)</span>$summaryHtml</li>"
                }
        )

    if (@($items).Count -eq 0) {
        return ''
    }

    return "<div class=""official-references""><strong>Official references</strong><ul>$($items -join [Environment]::NewLine)</ul></div>"
}

function Get-InspectorReportFindingObservation {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$SecurityObservations,

        [AllowNull()]
        [object[]]$ObservationIds,

        [AllowNull()]
        [hashtable]$ObservationIndex
    )

    $firstObservationId =
        @(
            @($ObservationIds) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Select-Object -First 1
        )[0]

    if ([string]::IsNullOrWhiteSpace([string]$firstObservationId)) {
        return $null
    }

    if ($null -ne $ObservationIndex -and $ObservationIndex.ContainsKey([string]$firstObservationId)) {
        return $ObservationIndex[[string]$firstObservationId]
    }

    return @($SecurityObservations) |
        Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'ObservationId') -eq $firstObservationId } |
        Select-Object -First 1
}

function Get-InspectorReportAffectedObjectValue {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Observation,

        [string[]]$Names
    )

    $affected =
        Get-InspectorReportProperty `
            -InputObject $Observation `
            -Name 'AffectedObject'

    foreach ($name in @($Names)) {
        $value = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $affected -Name $name)

        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return ''
}

function ConvertTo-InspectorReportSearchAttribute {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$Values
    )

    $text =
        @(
            @($Values) |
                ForEach-Object { ConvertTo-InspectorReportString $_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        ) -join ' '

    return ConvertTo-InspectorHtmlEncodedText ($text.ToLowerInvariant())
}

function Get-InspectorReportFindingRecommendationText {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Finding,

        [AllowNull()]
        [object[]]$AssessmentRecommendations,

        [AllowNull()]
        [hashtable]$RecommendationTextByObservationId
    )

    $findingObservationIds = @(
        Get-InspectorReportProperty -InputObject $Finding -Name 'ObservationIds'
    )

    if ($null -ne $RecommendationTextByObservationId) {
        $recommendationText =
            @(
                Get-InspectorReportProperty -InputObject $Finding -Name 'Recommendation'
                foreach ($observationId in @($findingObservationIds)) {
                    $key = ConvertTo-InspectorReportString $observationId

                    if (-not [string]::IsNullOrWhiteSpace($key) -and $RecommendationTextByObservationId.ContainsKey($key)) {
                        $RecommendationTextByObservationId[$key]
                    }
                }
            ) |
            ForEach-Object { ConvertTo-InspectorReportString $_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        return (@($recommendationText) -join ' ')
    }

    $recommendationText =
        @(
            Get-InspectorReportProperty -InputObject $Finding -Name 'Recommendation'
            @($AssessmentRecommendations) |
                Where-Object {
                    $recommendationObservationIds = @(
                        Get-InspectorReportProperty -InputObject $_ -Name 'ObservationIds'
                    )

                    @(
                        $recommendationObservationIds |
                            Where-Object { $_ -in $findingObservationIds }
                    ).Count -gt 0
                } |
                ForEach-Object {
                    @(
                        Get-InspectorReportProperty -InputObject $_ -Name 'Title'
                        Get-InspectorReportProperty -InputObject $_ -Name 'Action'
                        Get-InspectorReportProperty -InputObject $_ -Name 'Rationale'
                    )
                }
        ) |
        ForEach-Object { ConvertTo-InspectorReportString $_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return (@($recommendationText) -join ' ')
}

function New-InspectorReportObservationIndex {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$SecurityObservations
    )

    $index = [hashtable]::Synchronized(@{})

    foreach ($observation in @($SecurityObservations)) {
        $observationId =
            ConvertTo-InspectorReportString `
                (Get-InspectorReportProperty -InputObject $observation -Name 'ObservationId')

        if (-not [string]::IsNullOrWhiteSpace($observationId) -and -not $index.ContainsKey($observationId)) {
            $index[$observationId] = $observation
        }
    }

    return $index
}

function New-InspectorReportEvidenceIndex {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$EvidenceRows
    )

    $index = [hashtable]::Synchronized(@{})

    foreach ($row in @($EvidenceRows)) {
        $evidenceId =
            ConvertTo-InspectorReportString `
                (Get-InspectorReportProperty -InputObject $row -Name 'EvidenceId')

        if ([string]::IsNullOrWhiteSpace($evidenceId)) {
            continue
        }

        if (-not $index.ContainsKey($evidenceId)) {
            $index[$evidenceId] = [System.Collections.Generic.List[object]]::new()
        }

        $index[$evidenceId].Add($row)
    }

    return $index
}

function New-InspectorReportRecommendationTextIndex {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object[]]$AssessmentRecommendations
    )

    $index = [hashtable]::Synchronized(@{})

    foreach ($recommendation in @($AssessmentRecommendations)) {
        $text =
            @(
                Get-InspectorReportProperty -InputObject $recommendation -Name 'Title'
                Get-InspectorReportProperty -InputObject $recommendation -Name 'Action'
                Get-InspectorReportProperty -InputObject $recommendation -Name 'Rationale'
            ) |
            ForEach-Object { ConvertTo-InspectorReportString $_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        if (@($text).Count -eq 0) {
            continue
        }

        foreach ($observationId in @(Get-InspectorReportProperty -InputObject $recommendation -Name 'ObservationIds')) {
            $key = ConvertTo-InspectorReportString $observationId

            if ([string]::IsNullOrWhiteSpace($key)) {
                continue
            }

            if (-not $index.ContainsKey($key)) {
                $index[$key] = [System.Collections.Generic.List[string]]::new()
            }

            $index[$key].Add(($text -join ' '))
        }
    }

    return $index
}

function Get-InspectorReportEvidenceRowsById {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [hashtable]$EvidenceIndex,

        [AllowNull()]
        [object[]]$EvidenceIds
    )

    return @(
        foreach ($evidenceId in @($EvidenceIds)) {
            $key = ConvertTo-InspectorReportString $evidenceId

            if (-not [string]::IsNullOrWhiteSpace($key) -and $null -ne $EvidenceIndex -and $EvidenceIndex.ContainsKey($key)) {
                $EvidenceIndex[$key]
            }
        }
    )
}

function Get-InspectorPortalLink {
    [CmdletBinding()]
    param (
        [string]$ObjectType,
        [string]$ObjectId,
        [string]$AppId = '',
        [string]$TenantId = ''
    )

    $encodedId = if (-not [string]::IsNullOrWhiteSpace($ObjectId)) { [System.Uri]::EscapeDataString($ObjectId) } else { '' }
    $tenantBase = Get-InspectorTenantPortalBaseUrl -TenantId $TenantId
    $url = ''

    switch (Get-InspectorReportNormalizedObjectType $ObjectType) {
        'User' {
            if ([string]::IsNullOrWhiteSpace($ObjectId)) { return $null }
            $url = "$tenantBase/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/$encodedId"
        }
        'RiskyUser' {
            if (-not [string]::IsNullOrWhiteSpace($ObjectId)) {
                $url = "$tenantBase/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/$encodedId"
            }
            else {
                $url = "$tenantBase/#view/Microsoft_AAD_IdentityProtection/RiskyUsers.ReactView"
            }
        }
        'Group' {
            if ([string]::IsNullOrWhiteSpace($ObjectId)) { return $null }
            $url = "$tenantBase/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/$encodedId"
        }
        'Application' {
            if ([string]::IsNullOrWhiteSpace($AppId)) { return $null }
            $encodedAppId = [System.Uri]::EscapeDataString($AppId)
            $url = "$tenantBase/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$encodedAppId"
        }
        'ServicePrincipal' {
            if ([string]::IsNullOrWhiteSpace($ObjectId) -or [string]::IsNullOrWhiteSpace($AppId)) { return $null }
            $encodedAppId = [System.Uri]::EscapeDataString($AppId)
            $url = "$tenantBase/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$encodedId/appId/$encodedAppId"
        }
        'DirectoryRole' {
            $url = "$tenantBase/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles"
        }
        'PimRole' {
            $url = "$tenantBase/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles?"
        }
        'AdministrativeUnit' {
            if ([string]::IsNullOrWhiteSpace($ObjectId)) { return $null }
            # Microsoft documents Administrative Units under Entra ID > Roles & admins >
            # Admin units but does not publish a stable object-specific deep-link contract.
            # Use the tenant-scoped Entra landing page instead of guessing an internal blade.
            $url = $tenantBase
        }
        default { return $null }
    }

    return $url
}

function New-InspectorOpenEntraLinkHtml {
    [CmdletBinding()]
    param (
        [string]$ObjectType,
        [string]$ObjectId,
        [string]$AppId = '',
        [string]$TenantId = '',
        [string]$Label = 'Open in Entra'
    )

    $url = Get-InspectorPortalLink -ObjectType $ObjectType -ObjectId $ObjectId -AppId $AppId -TenantId $TenantId
    if ([string]::IsNullOrWhiteSpace($url)) { return '' }

    return "<a class=""open-btn"" href=""$(ConvertTo-InspectorHtmlEncodedText $url)"" target=""_blank"" rel=""noopener noreferrer"">$(ConvertTo-InspectorHtmlEncodedText $Label)</a>"
}

function New-InspectorAffectedObjectsHtml {
    [CmdletBinding()]
    param (
        [object[]]$AffectedObjects = @(),
        [string]$TenantId = ''
    )

    $allObjects = @(
        foreach ($item in @($AffectedObjects)) {
            if ($item -is [array]) { foreach ($nested in @($item)) { $nested } }
            else { $item }
        }
    ) | Where-Object { $null -ne $_ }

    $objects = @($allObjects | Select-Object -First 8)
    $total = @($allObjects).Count
    if ($total -eq 0) { return '<div class="affected-objects"><span class="muted">No affected object was attached to this finding.</span></div>' }

    $rows = @(
        foreach ($object in $objects) {
            $objectType = Get-InspectorReportNormalizedObjectType (Get-InspectorReportProperty -InputObject $object -Name 'ObjectType')
            $objectId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $object -Name 'ObjectId')
            $displayName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $object -Name 'DisplayName')
            $appId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $object -Name 'AppId')
            $upn = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $object -Name 'UserPrincipalName')
            $identifier = @($upn, $appId, $objectId) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
            if ([string]::IsNullOrWhiteSpace($displayName) -or $displayName -eq $objectId) { $displayName = $identifier }
            if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = 'Not available' }
            $portalLink = New-InspectorOpenEntraLinkHtml -ObjectType $objectType -ObjectId $objectId -AppId $appId -TenantId $TenantId -Label 'Open object'
            "<tr><td>$(ConvertTo-InspectorHtmlEncodedText $displayName)</td><td>$(ConvertTo-InspectorHtmlEncodedText $objectType)</td><td>$(ConvertTo-InspectorHtmlEncodedText $identifier)</td><td>$portalLink</td></tr>"
        }
    ) -join [Environment]::NewLine

    $more = if ($total -gt @($objects).Count) { "<p class=""muted"">Showing $(@($objects).Count) of $total affected objects. Use the evidence report for the full grouped-finding detail.</p>" } else { '' }

    return @"
<div class="affected-objects">
  <span class="muted">Affected objects ($total)</span>
  <div class="table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>Type</th><th>Identifier</th><th>Entra</th></tr></thead><tbody>$rows</tbody></table></div>
  $more
</div>
"@
}

function New-InspectorIssueGroupsHtml {
    [CmdletBinding()]
    param ([AllowNull()][object[]]$IssueGroups = @())

    $groups = @($IssueGroups) | Where-Object { $null -ne $_ } | Select-Object -First 12
    if (@($groups).Count -eq 0) { return '' }

    $rows = @(
        foreach ($group in $groups) {
            $samples = @(
                Get-InspectorReportProperty -InputObject $group -Name 'SampleAffectedObjects'
            ) | Where-Object { $null -ne $_ } | Select-Object -First 3 | ForEach-Object {
                ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'DisplayName')
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

            [PSCustomObject][ordered]@{
                Condition = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'Condition')
                Severity = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'Severity')
                AffectedObjects = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'ObjectCount')
                Observations = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'ObservationCount')
                Example = @($samples) -join '; '
            }
        }
    )

    return @"
<details class="finding-technical">
  <summary>Grouped conditions</summary>
  <p class="muted">Repeated instances of the same security issue are grouped here instead of repeated as separate findings.</p>
  $(New-InspectorHtmlTable -Rows $rows -Columns @('Condition','Severity','AffectedObjects','Observations','Example') -SuppressRowAnchors)
</details>
"@
}

function New-InspectorPriorityFindingsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $findings = @($ReportModel.AssessmentFindings) |
        Where-Object { (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')) -ne 'Tenant assessment observation summary' } |
        Sort-Object { Get-InspectorReportSeverityOrder -Severity ([string](Get-InspectorReportProperty -InputObject $_ -Name 'Severity')) }, Category, Title

    $observationIndex = New-InspectorReportObservationIndex -SecurityObservations $ReportModel.SecurityObservations
    $evidenceIndex = New-InspectorReportEvidenceIndex -EvidenceRows $ReportModel.EvidenceRows
    $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
    $tenantId = ConvertTo-InspectorReportString (Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantId','TenantID'))

    $filters = @('All','High','Medium','Low','Informational')
    $filterHtml = @($filters | ForEach-Object {
        $active = if ($_ -eq 'All') { ' is-active' } else { '' }
        "<button type=""button"" class=""filter-button$active"" data-filter-severity=""$_"">$(ConvertTo-InspectorHtmlEncodedText $_)</button>"
    }) -join [Environment]::NewLine

    $objectTypes = @(
        $findings | ForEach-Object {
            @(Get-InspectorReportProperty -InputObject $_ -Name 'AffectedObjects') | ForEach-Object {
                Get-InspectorReportNormalizedObjectType (Get-InspectorReportProperty -InputObject $_ -Name 'ObjectType')
            }
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
    )
    $objectTypeOptions = @(
        '<option value="">All object types</option>'
        @($objectTypes | ForEach-Object { "<option value=""$(ConvertTo-InspectorHtmlEncodedText $_)"">$(ConvertTo-InspectorHtmlEncodedText $_)</option>" })
    ) -join [Environment]::NewLine

    if (@($findings).Count -eq 0) {
        $cards = '<p class="empty-state">No actionable grouped findings were supplied.</p>'
    }
    else {
        $cards = @(
            foreach ($finding in $findings) {
                $severity = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Severity')
                $category = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Category')
                $title = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Title')
                $description = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Conclusion')
                $recommendation = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Recommendation')
                $observationIds = @(Get-InspectorReportProperty -InputObject $finding -Name 'ObservationIds')
                $evidenceIds = @(Get-InspectorReportProperty -InputObject $finding -Name 'EvidenceIds')
                $references = @(Get-InspectorReportProperty -InputObject $finding -Name 'References')
                $affectedObjects = @(Get-InspectorReportProperty -InputObject $finding -Name 'AffectedObjects')
                $resultState = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'ResultState')
                $evidenceSupportStatus = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'EvidenceSupportStatus')
                $criterionSummary = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'CriterionSummary')
                $severityReason = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'SeverityReason')
                $issueGroups = @(Get-InspectorReportProperty -InputObject $finding -Name 'IssueGroups')

                if (@($references).Count -eq 0) { $references = @(Resolve-InspectorRecommendationReferences -InputObject $finding) }
                if ([string]::IsNullOrWhiteSpace($description)) { $description = 'The assessment detected this security condition in the collected tenant data.' }
                if ([string]::IsNullOrWhiteSpace($criterionSummary)) { $criterionSummary = 'See the contributing observations and evidence for the exact trigger.' }
                if ([string]::IsNullOrWhiteSpace($recommendation)) { $recommendation = 'Review the affected objects and supporting evidence.' }

                $observation = Get-InspectorReportFindingObservation -ObservationIds $observationIds -ObservationIndex $observationIndex
                $objectText = if ($null -ne $observation) { Get-InspectorReportObservationDisplayName -Observation $observation } else { 'Not available' }
                $objectType = if ($null -ne $observation) { Get-InspectorReportNormalizedObjectType (Get-InspectorReportObservationObjectType -Observation $observation) } else { 'Not available' }
                $affectedObjectId = Get-InspectorReportAffectedObjectValue -Observation $observation -Names @('ObjectId','Id')
                $appId = Get-InspectorReportAffectedObjectValue -Observation $observation -Names @('AppId','ApplicationId','ClientId')
                $upn = Get-InspectorReportAffectedObjectValue -Observation $observation -Names @('UserPrincipalName','UPN')
                $primaryPortalLink = New-InspectorOpenEntraLinkHtml -ObjectType $objectType -ObjectId $affectedObjectId -AppId $appId -TenantId $tenantId -Label 'Open primary object'

                $permission = (@(
                    Get-InspectorReportProperty -InputObject $finding -Name 'Permission'
                    Get-InspectorReportProperty -InputObject $finding -Name 'PermissionName'
                ) | ForEach-Object { ConvertTo-InspectorReportString $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique) -join ' '

                $matchingEvidenceRows = Get-InspectorReportEvidenceRowsById -EvidenceIndex $evidenceIndex -EvidenceIds $evidenceIds
                $evidenceSummary = @(
                    @($matchingEvidenceRows) | ForEach-Object {
                        @(Get-InspectorReportProperty -InputObject $_ -Name 'QueryName'; Get-InspectorReportProperty -InputObject $_ -Name 'RequiredPermission'; Get-InspectorReportProperty -InputObject $_ -Name 'Status')
                    } | Select-Object -Unique | Select-Object -First 12
                ) -join ' '

                $metadataPills = @(
                    New-InspectorReportMetadataPillHtml -Label 'Primary object' -Value $objectText
                    New-InspectorReportMetadataPillHtml -Label 'Object ID' -Value $affectedObjectId
                    New-InspectorReportMetadataPillHtml -Label 'Type' -Value $objectType
                    New-InspectorReportMetadataPillHtml -Label 'AppId' -Value $appId
                    New-InspectorReportMetadataPillHtml -Label 'UPN' -Value $upn
                    New-InspectorReportMetadataPillHtml -Label 'Permission' -Value $permission
                    New-InspectorReportMetadataPillHtml -Label 'Result state' -Value $resultState
                    New-InspectorReportMetadataPillHtml -Label 'Evidence support' -Value $evidenceSupportStatus
                    "<span class=""pill"">Observations: $(@($observationIds).Count)</span>"
                    "<span class=""pill"">Evidence: $(@($evidenceIds).Count)</span>"
                ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }

                $technicalDetails = @"
<details class="finding-technical">
  <summary>Technical details</summary>
  <div class="finding-meta">$($metadataPills -join [Environment]::NewLine)</div>
  <p class="muted" data-highlight-target><strong>Severity basis:</strong> $(ConvertTo-InspectorHtmlEncodedText $severityReason)</p>
  $(New-InspectorIssueGroupsHtml -IssueGroups $issueGroups)
  $(New-InspectorFindingEvidenceHtml -ObservationIds $observationIds -EvidenceIds $evidenceIds -EvidenceReportFileName (Get-InspectorReportProperty -InputObject $ReportModel -Name 'EvidenceReportFileName') -FindingId (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'FindingId')))
</details>
"@

                $searchText = ConvertTo-InspectorReportSearchAttribute -Values @(
                    $title,$description,$severity,$category,(Get-InspectorReportNormalizedCategory $category),$objectText,$affectedObjectId,$appId,$upn,$objectType,$permission,$evidenceSummary,$resultState,$evidenceSupportStatus,$criterionSummary,$severityReason
                )
                if ($searchText.Length -gt 8192) { $searchText = $searchText.Substring(0,8192) }

@"
<article class="finding-card" data-severity="$(ConvertTo-InspectorHtmlEncodedText $severity)" data-category="$(ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportNormalizedCategory $category))" data-object-type="$(ConvertTo-InspectorHtmlEncodedText $objectType)" data-object-types="$(ConvertTo-InspectorHtmlEncodedText ((@($affectedObjects) | ForEach-Object { Get-InspectorReportNormalizedObjectType (Get-InspectorReportProperty -InputObject $_ -Name 'ObjectType') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ' '))" data-object-id="$(ConvertTo-InspectorHtmlEncodedText $affectedObjectId)" data-app-id="$(ConvertTo-InspectorHtmlEncodedText $appId)" data-upn="$(ConvertTo-InspectorHtmlEncodedText $upn)" data-display-name="$(ConvertTo-InspectorHtmlEncodedText $objectText)" data-search="$searchText">
  <div class="finding-top">
    <span class="pill $(Get-InspectorReportStatusClass -Value $severity)">$(ConvertTo-InspectorHtmlEncodedText $severity)</span>
    <span class="finding-category">$(ConvertTo-InspectorHtmlEncodedText $category)</span>
    $primaryPortalLink
  </div>
  <h3 class="finding-title" data-highlight-target>$(ConvertTo-InspectorHtmlEncodedText $title)</h3>
  <div class="finding-summary-grid">
    <div class="finding-summary-item" data-highlight-target><span class="field-label">Why it matters</span><span class="field-value">$(ConvertTo-InspectorHtmlEncodedText $description)</span></div>
    <div class="finding-summary-item" data-highlight-target><span class="field-label">What triggered it</span><span class="field-value">$(ConvertTo-InspectorHtmlEncodedText $criterionSummary)</span></div>
  </div>
  $(New-InspectorAffectedObjectsHtml -AffectedObjects $affectedObjects -TenantId $tenantId)
  <div class="finding-action" data-highlight-target><strong>Recommended action:</strong> $(ConvertTo-InspectorHtmlEncodedText $recommendation)$(New-InspectorOfficialReferencesHtml -References $references)</div>
  $technicalDetails
</article>
"@
            }
        ) -join [Environment]::NewLine
    }

    return @"
<section id="priority-findings" class="section">
  <div class="section-header">
    <h2>Findings</h2>
    <span id="findingResultCount" class="muted">$(@($findings).Count) of $(@($findings).Count) grouped findings</span>
  </div>
  <p class="section-intro">Findings are grouped by security issue. Review High first, then open the affected Entra objects directly from each finding.</p>
  <div class="investigation-bar" aria-label="Finding filters">
    <input id="findingSearch" type="search" placeholder="Search finding, object, UPN, app ID, permission, or category" aria-label="Search findings">
    <select id="objectTypeFilter" aria-label="Filter findings by object type">$objectTypeOptions</select>
    <button id="clearFindingFilters" type="button">Clear</button>
  </div>
  <div class="filter-row" aria-label="Finding severity filters">$filterHtml</div>
  <p id="noFindingResults" class="empty-state" hidden>No findings match the current filters.</p>
  <div class="finding-list">$cards</div>
</section>
"@
}

function New-InspectorRecommendedActionsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $recommendations = @($ReportModel.AssessmentRecommendations) | Select-Object -First 8

    if (@($recommendations).Count -eq 0) {
        $content = '<p class="empty-state">No assessment recommendations were supplied.</p>'
    }
    else {
        $items =
            @(
                foreach ($recommendation in $recommendations) {
                    $title = ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportProperty -InputObject $recommendation -Name 'Title')
                    $action = ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportProperty -InputObject $recommendation -Name 'Action')
                    $category = ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportProperty -InputObject $recommendation -Name 'Category')
                    $references =
                        @(
                            Get-InspectorReportProperty `
                                -InputObject $recommendation `
                                -Name 'References'
                        )

                    if (@($references).Count -eq 0) {
                        $references = @(Resolve-InspectorRecommendationReferences -InputObject $recommendation)
                    }

                    $referenceHtml = New-InspectorOfficialReferencesHtml -References $references

                    "<li><strong>$title</strong><br><span class=""muted"">$category</span><br>$action$referenceHtml</li>"
                }
            ) -join [Environment]::NewLine

        $content = "<ol class=""action-list"">$items</ol>"
    }

    return @"
<section id="recommended-next-actions" class="section">
  <div class="section-header">
    <h2>Top Actions / Recommended Next Actions</h2>
    <span class="muted">$(@($recommendations).Count) shown</span>
  </div>
  <p class="muted">These actions are rendered from existing assessment recommendations only. No new recommendations are generated by the report layer.</p>
  $content
</section>
"@
}

function New-InspectorFindingsByCategoryHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $categories = @(
        [PSCustomObject]@{ Label='Permissions'; Key='Permissions' }
        [PSCustomObject]@{ Label='Ownership / Identity Governance'; Key='IdentityGovernance' }
        [PSCustomObject]@{ Label='Consent'; Key='Consent' }
        [PSCustomObject]@{ Label='Service principals'; Key='ServicePrincipal' }
        [PSCustomObject]@{ Label='Users'; Key='Users' }
        [PSCustomObject]@{ Label='Groups'; Key='Groups' }
        [PSCustomObject]@{ Label='Credential Hygiene'; Key='Credentials' }
    )

    $cards =
        @(
            foreach ($category in $categories) {
                $count =
                    @($ReportModel.SecurityObservations |
                        Where-Object {
                            (Get-InspectorReportNormalizedCategory (Get-InspectorReportProperty -InputObject $_ -Name 'Category')) -eq $category.Key
                        }).Count

                $emptyText =
                    if ($count -eq 0) {
                        "<div class=""muted"">No $(ConvertTo-InspectorHtmlEncodedText $category.Label) observations were supplied.</div>"
                    }
                    else {
                        $groupedCount = @($ReportModel.AssessmentFindings | Where-Object {
                            (Get-InspectorReportNormalizedCategory (Get-InspectorReportProperty -InputObject $_ -Name 'Category')) -eq $category.Key
                        }).Count
                        "<div class=""muted"">deduplicated observations</div><div class=""muted"">$groupedCount grouped finding</div>"
                    }

                "<div class=""category-card""><h3>$(ConvertTo-InspectorHtmlEncodedText $category.Label)</h3><div class=""category-count"">$count</div>$emptyText</div>"
            }
        ) -join [Environment]::NewLine

    return @"
<section id="assessment-signals-by-category" class="section">
  <div class="section-header">
    <h2>Assessment Signals by Category</h2>
    <span class="muted">Deduplicated observations and grouped findings</span>
  </div>
  <div class="category-grid">
    $cards
  </div>
</section>
"@
}

function New-InspectorPrivilegedIdentityContextHtml {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][object]$ReportModel)

    $details = Get-InspectorReportProperty -InputObject $ReportModel -Name 'InventoryDetails'
    if ($null -eq $details) { return '' }

    $riskyCount = @(Get-InspectorReportProperty -InputObject $details -Name 'RiskyUsers').Count
    $privilegedGroupCount = @(Get-InspectorReportProperty -InputObject $details -Name 'PrivilegedGroups').Count
    $directRoleCount = @(Get-InspectorReportProperty -InputObject $details -Name 'DirectoryRoleAssignments').Count
    $pimActiveDisplayCount = @(Get-InspectorReportProperty -InputObject $details -Name 'PimActive').Count
    $pimEligibleCount = @(Get-InspectorReportProperty -InputObject $details -Name 'PimEligible').Count
    $auCount = @(Get-InspectorReportProperty -InputObject $details -Name 'AdministrativeUnits').Count
    $scopeInventory = Get-InspectorReportProperty -InputObject $ReportModel -Name 'ScopeInventory'
    if ($null -eq $scopeInventory) { $scopeInventory = Get-InspectorReportProperty -InputObject (Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary') -Name 'ScopeInventory' }
    $pimActiveCollected = Get-InspectorReportMetricValue -InputObject $scopeInventory -Names @('RoleAssignmentScheduleInstancesDiscovered')
    if ($null -eq $pimActiveCollected) { $pimActiveCollected = $pimActiveDisplayCount }

    $cards = @(
        [PSCustomObject]@{ Label='Risky users'; Value=$riskyCount; Hint='Identity Protection state collected'; Status=$(if ($riskyCount -gt 0) { 'Medium' } else { 'Success' }) }
        [PSCustomObject]@{ Label='Privileged groups'; Value=$privilegedGroupCount; Hint='Role-assignable groups'; Status='Info' }
        [PSCustomObject]@{ Label='Direct role assignments'; Value=$directRoleCount; Hint='Collected current assignments'; Status='Info' }
        [PSCustomObject]@{ Label='Active role schedule instances collected'; Value=$pimActiveCollected; Hint='Raw current active-assignment schedule instances'; Status='Info' }
        [PSCustomObject]@{ Label='Eligible role schedule instances'; Value=$pimEligibleCount; Hint='Eligible role state, not active privilege'; Status='Info' }
        [PSCustomObject]@{ Label='Administrative units'; Value=$auCount; Hint='Delegated directory scope'; Status='Info' }
    ) | ForEach-Object { New-InspectorReportMetric -Label $_.Label -Value $_.Value -Hint $_.Hint -Status $_.Status }

    $detailHtml = @(
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'RiskyUsers' -Title 'Risky users' -Columns @('DisplayName','UserPrincipalName','RiskLevel','RiskState','RiskDetail')
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'PrivilegedGroups' -Title 'Privileged groups' -Columns @('DisplayName','ObjectId') -MaximumRows 100
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'DirectoryRoleAssignments' -Title 'Directory role assignments' -Columns @('Principal','PrincipalType','Role','Scope','AssignmentId') -MaximumRows 150
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'PimActive' -Title 'Active role schedule instances (deduplicated view)' -Columns @('Principal','PrincipalType','Role','Scope','State','Start','End') -MaximumRows 150
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'PimEligible' -Title 'Eligible role schedule instances' -Columns @('Principal','PrincipalType','Role','Scope','Start','End') -MaximumRows 150
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'AdministrativeUnits' -Title 'Administrative units' -Columns @('DisplayName','Description','Visibility','RestrictedManagement') -MaximumRows 100
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return @"
<section id="privileged-identity-context" class="section">
  <div class="section-header"><h2>Privileged identity context</h2><span class="muted">Roles, PIM, risky users, groups, and Administrative Units</span></div>
  <p class="section-intro">This is supporting tenant context. Security conclusions remain in the Findings section above.</p>
  $(New-InspectorMetricCardsHtml -Metrics $cards)
  <div class="context-panel context-list">$($detailHtml -join [Environment]::NewLine)</div>
</section>
"@
}

function New-InspectorApplicationIdentityContextHtml {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][object]$ReportModel)

    $details = Get-InspectorReportProperty -InputObject $ReportModel -Name 'InventoryDetails'
    if ($null -eq $details) { return '' }
    $applications = @(Get-InspectorReportProperty -InputObject $details -Name 'Applications')
    $servicePrincipals = @(Get-InspectorReportProperty -InputObject $details -Name 'ServicePrincipals')
    $applicationFindingCategories = @('Consent','Credentials','Permissions','ServicePrincipal')
    $applicationFindings = @($ReportModel.AssessmentFindings | Where-Object {
        $applicationFindingCategories -contains (Get-InspectorReportNormalizedCategory (Get-InspectorReportProperty -InputObject $_ -Name 'Category'))
    })

    if ($applications.Count -eq 0 -and $servicePrincipals.Count -eq 0 -and $applicationFindings.Count -eq 0) { return '' }

    $cards = @(
        New-InspectorReportMetric -Label 'App registrations' -Value $applications.Count -Hint 'Application objects collected' -Status 'Info'
        New-InspectorReportMetric -Label 'Enterprise applications' -Value $servicePrincipals.Count -Hint 'Service principals collected' -Status 'Info'
        New-InspectorReportMetric -Label 'Application / permission findings' -Value $applicationFindings.Count -Hint 'Grouped security issues in this area' -Status $(if (@($applicationFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'High' }).Count -gt 0) { 'High' } elseif ($applicationFindings.Count -gt 0) { 'Medium' } else { 'Success' })
    )
    $detailHtml = @(
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'Applications' -Title 'App registrations' -Columns @('DisplayName','AppId','ObjectId') -MaximumRows 150
        New-InspectorInventoryDetailHtml -ReportModel $ReportModel -PropertyName 'ServicePrincipals' -Title 'Enterprise applications / service principals' -Columns @('DisplayName','AppId','ObjectId') -MaximumRows 150
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return @"
<section id="application-identity-context" class="section">
  <div class="section-header"><h2>Application and permission context</h2><span class="muted">Applications, enterprise applications, and related findings</span></div>
  <p class="section-intro">Use this supporting inventory to identify the application identities referenced by permission, credential, consent, and ownership findings. Security conclusions remain in Findings.</p>
  $(New-InspectorMetricCardsHtml -Metrics $cards)
  <div class="context-panel context-list">$($detailHtml -join [Environment]::NewLine)</div>
</section>
"@
}

function New-InspectorAssessmentNotesHtml {
    [CmdletBinding()]
    param ([Parameter(Mandatory)][object]$ReportModel)

    $items = @(
        'This is a read-only assessment; the report does not modify Microsoft Entra ID.'
        @($ReportModel.AssessmentLimitations)
    ) | ForEach-Object {
        if ($_ -is [array]) { $_ } else { ,$_ }
    } | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    $list = @($items | ForEach-Object { "<li>$(ConvertTo-InspectorHtmlEncodedText $_)</li>" }) -join [Environment]::NewLine
    $content = if (@($items).Count -gt 0) { "<ul class=""limitations"">$list</ul>" } else { '<p class="empty-state">No assessment limitations were supplied.</p>' }

    return New-InspectorReportSection `
        -Id 'assessment-notes' `
        -Title 'Assessment notes and limitations' `
        -Summary "$(@($items).Count) notes" `
        -Content $content `
        -Collapsed
}

function New-InspectorRuntimeTelemetryHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $telemetry = Get-InspectorReportProperty -InputObject $ReportModel -Name 'RuntimeTelemetry'

    if ($null -eq $telemetry) {
        return @"
<section id="runtime-telemetry" class="section">
  <div class="section-header"><h2>Runtime Telemetry</h2></div>
  <p class="empty-state">Runtime telemetry was not available for this assessment.</p>
</section>
"@
    }

    $stageSummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'StageSummary'
    $graphSummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'GraphRequestSummary'
    $transportSummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'GraphTransportSummary'
    $throughputSummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'ThroughputSummary'
    $executionProfile = Get-InspectorReportProperty -InputObject $telemetry -Name 'ExecutionProfile'
    $scopeSummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'ScopeSummary'
    $throttlingSummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'ThrottlingSummary'
    $retrySummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'RetrySummary'
    $memorySummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'MemorySummary'
    $externalSummary = Get-InspectorReportProperty -InputObject $telemetry -Name 'ExternalEndpointSummary'
    $orchestration = Get-InspectorReportProperty -InputObject $ReportModel -Name 'OrchestrationTelemetry'
    $batchExecutionShare = Get-InspectorReportMetricValue -InputObject $transportSummary -Names @('BatchExecutionSharePercent')
    $batchExecutionShareText = if ($null -eq $batchExecutionShare) { 'n/a' } else { "$batchExecutionShare%" }
    $runPeakWorkingSet = Get-InspectorReportMetricValue -InputObject $memorySummary -Names @('RunPeakWorkingSetMB')
    $runPeakWorkingSetText = if ($null -eq $runPeakWorkingSet) { 'n/a' } else { "$runPeakWorkingSet MB" }

    $rows = @(
        [PSCustomObject]@{ Field='Command runtime at report generation'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'TotalCommandDurationMs')) }
        [PSCustomObject]@{ Field='Tenant inspection duration'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportMetricValue -InputObject $orchestration -Names @('TenantInspectionDurationMs'))) }
        [PSCustomObject]@{ Field='Snapshot collection duration'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportMetricValue -InputObject $orchestration -Names @('SnapshotCollectionDurationMs'))) }
        [PSCustomObject]@{ Field='Offline processing duration'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportMetricValue -InputObject $orchestration -Names @('OfflineProcessingDurationMs'))) }
        [PSCustomObject]@{ Field='Assessment intelligence duration'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'AssessmentIntelligenceDurationMs')) }
        [PSCustomObject]@{ Field='Export duration'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'ExportDurationMs')) }
        [PSCustomObject]@{ Field='Report generation duration'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'ReportGenerationDurationMs')) }
        [PSCustomObject]@{ Field='Tenant runtime telemetry'; Value=(ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $telemetry -Name 'TotalDurationMs')) }
        [PSCustomObject]@{ Field='Execution mode'; Value=Get-InspectorReportMetricValue -InputObject $executionProfile -Names @('Mode') }
        [PSCustomObject]@{ Field='Collection scope'; Value=Get-InspectorReportMetricValue -InputObject $scopeSummary -Names @('Mode') }
        [PSCustomObject]@{ Field='Target count'; Value=Get-InspectorReportMetricValue -InputObject $scopeSummary -Names @('TargetCount') }
        [PSCustomObject]@{ Field='Offline objects/sec'; Value=Get-InspectorReportMetricValue -InputObject $throughputSummary -Names @('ObjectsPerSecond') }
        [PSCustomObject]@{ Field='Graph logical requests'; Value=Get-InspectorReportMetricValue -InputObject $graphSummary -Names @('TotalRequests','GraphRequestCount') }
        [PSCustomObject]@{ Field='Graph physical HTTP requests'; Value=Get-InspectorReportMetricValue -InputObject $transportSummary -Names @('TotalHttpRequests') }
        [PSCustomObject]@{ Field='Logical requests / HTTP request'; Value=Get-InspectorReportMetricValue -InputObject $transportSummary -Names @('LogicalRequestsPerHttpRequest') }
        [PSCustomObject]@{ Field='Transport executions / HTTP request'; Value=Get-InspectorReportMetricValue -InputObject $transportSummary -Names @('TransportExecutionsPerHttpRequest') }
        [PSCustomObject]@{ Field='Average batch subrequests'; Value=Get-InspectorReportMetricValue -InputObject $transportSummary -Names @('AverageBatchSubrequestsPerRequest') }
        [PSCustomObject]@{ Field='Batch execution share'; Value=$batchExecutionShareText }
        [PSCustomObject]@{ Field='Throttled requests'; Value=Get-InspectorReportMetricValue -InputObject $throttlingSummary -Names @('ThrottledRequests') }
        [PSCustomObject]@{ Field='Retried requests'; Value=Get-InspectorReportMetricValue -InputObject $retrySummary -Names @('RetriedRequests') }
        [PSCustomObject]@{ Field='Process peak working set'; Value="$(Get-InspectorReportMetricValue -InputObject $memorySummary -Names @('PeakMemoryMB')) MB" }
        [PSCustomObject]@{ Field='Run-observed working-set peak'; Value="$(Get-InspectorReportMetricValue -InputObject $memorySummary -Names @('RunObservedWorkingSetPeakMB')) MB" }
        [PSCustomObject]@{ Field='Exact run peak working set'; Value=$runPeakWorkingSetText }
        [PSCustomObject]@{ Field='Run peak status'; Value=Get-InspectorReportMetricValue -InputObject $memorySummary -Names @('RunPeakMemoryStatus') }
        [PSCustomObject]@{ Field='Peak-memory scope'; Value=Get-InspectorReportMetricValue -InputObject $memorySummary -Names @('PeakMemoryScope') }
        [PSCustomObject]@{ Field='Raw snapshot persisted'; Value=Get-InspectorReportMetricValue -InputObject $telemetry -Names @('RawSnapshotPersisted') }
        [PSCustomObject]@{ Field='Unexpected external hosts'; Value=$(if ($null -ne (Get-InspectorReportMetricValue -InputObject $externalSummary -Names @('UnexpectedExternalHosts'))) { @((Get-InspectorReportMetricValue -InputObject $externalSummary -Names @('UnexpectedExternalHosts'))).Count } else { 0 }) }
    )

    return @"
<section id="runtime-telemetry" class="section">
  <div class="section-header"><h2>Runtime Telemetry</h2><span class="muted">Local telemetry only</span></div>
  $(New-InspectorHtmlTable -Rows $rows -Columns @('Field','Value'))
</section>
"@
}

function New-InspectorBoundariesTrustHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $telemetry = Get-InspectorReportProperty -InputObject $ReportModel -Name 'RuntimeTelemetry'
    $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
    $snapshotMode = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $summary -Name 'SnapshotMode')

    $items = @(
        'Read-only assessment'
        'Microsoft Graph GET-only collection'
        $(if (-not [string]::IsNullOrWhiteSpace($snapshotMode)) { 'Snapshot-first pipeline' })
        $(if ($null -ne $telemetry) { 'Local telemetry only' })
        'No risk score'
        'No attack paths'
        'No remediation actions'
        'Raw snapshot not persisted by default'
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }

    $cards = @($items | ForEach-Object { "<div class=""trust-box"">$(ConvertTo-InspectorHtmlEncodedText $_)</div>" }) -join [Environment]::NewLine

    return @"
<section id="boundaries-trust" class="section">
  <div class="section-header"><h2>Boundaries &amp; Trust</h2><span class="muted">Report invariants</span></div>
  <div class="trust-grid">$cards</div>
</section>
"@
}

function New-InspectorEvidenceReferenceHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @($ReportModel.EvidenceRows) |
        Select-Object -First 25 |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                EvidenceId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId')
                QueryName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'QueryName')
                Status = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status')
            }
        }

    return @"
<section id="evidence-references" class="section">
  <div class="section-header"><h2>Evidence References</h2><span class="muted">$(@($ReportModel.EvidenceRows).Count) total</span></div>
  <p class="muted">Evidence is summarized here and attached to findings on demand. Source artifacts remain unchanged.</p>
  $(New-InspectorHtmlTable -Rows $rows -Columns @('EvidenceId','QueryName','Status') -EmptyMessage 'No evidence references were supplied.')
</section>
"@
}

function New-InspectorExecutiveSummaryHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $posture = Get-InspectorReportProperty -InputObject $ReportModel -Name 'TenantPosture'
    $postureLabel = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $posture -Name 'Label')
    $highestSeverity = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $posture -Name 'HighestSeverity')
    if ([string]::IsNullOrWhiteSpace($postureLabel)) { $postureLabel = 'Not available' }
    if ([string]::IsNullOrWhiteSpace($highestSeverity)) { $highestSeverity = 'Not available' }

    $postureClass = switch ($highestSeverity) { 'High' { 'high' } 'Medium' { 'medium' } 'Low' { 'low' } default { '' } }
    $highCount = @($ReportModel.AssessmentFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'High' }).Count
    $mediumCount = @($ReportModel.AssessmentFindings | Where-Object { (Get-InspectorReportProperty -InputObject $_ -Name 'Severity') -eq 'Medium' }).Count
    $findingCount = @($ReportModel.AssessmentFindings | Where-Object { (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')) -ne 'Tenant assessment observation summary' }).Count

    $failedCount = Get-InspectorReportMetricValue -InputObject (Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary') -Names @('FailedCount','FailedObjectCount')
    $failureText = ''
    if ($null -ne $failedCount -and [int]$failedCount -gt 0) {
        $diagnosticsFileName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'DiagnosticsReportFileName')
        $failureText = if ([string]::IsNullOrWhiteSpace($diagnosticsFileName)) {
            "<p><strong>Collection warning:</strong> $failedCount object(s) did not complete processing. Review the failed-object exports.</p>"
        } else {
            "<p><strong>Collection warning:</strong> $failedCount object(s) did not complete processing. <a href=""$(ConvertTo-InspectorHtmlEncodedText $diagnosticsFileName)"">Review diagnostics report</a>.</p>"
        }
    }

    $packageValidationStatus = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'PackageValidationStatus')
    $validationText = ''
    if (-not [string]::IsNullOrWhiteSpace($packageValidationStatus) -and $packageValidationStatus -ne 'Success') {
        $diagnosticsFileName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'DiagnosticsReportFileName')
        $diagnosticsLink = if ([string]::IsNullOrWhiteSpace($diagnosticsFileName)) { 'Review diagnostics before relying on the package.' } else { "<a href=""$(ConvertTo-InspectorHtmlEncodedText $diagnosticsFileName)"">Review diagnostics report</a> before relying on the package." }
        $validationText = @"
<div class="posture-banner high">
  <div><div class="posture-label">Assessment package validation failed</div><div class="posture-text">Internal package consistency checks did not pass. $diagnosticsLink</div></div>
  <span class="pill severity-high">$(ConvertTo-InspectorHtmlEncodedText $packageValidationStatus)</span>
</div>
"@
    }

    $prioritySentence = if ($highCount -gt 0) {
        "Start with the $highCount High finding(s), then review the $mediumCount Medium finding(s)."
    } elseif ($mediumCount -gt 0) {
        "No High findings were produced. Start with the $mediumCount Medium finding(s)."
    } else {
        'No High or Medium grouped findings were produced by the implemented rules.'
    }

    return @"
<section id="executive-summary" class="section always-open">
  <h2>Assessment summary</h2>
  $validationText
  <div class="posture-banner $postureClass">
    <div><div class="posture-label">Tenant posture: $(ConvertTo-InspectorHtmlEncodedText $postureLabel)</div><div class="posture-text">Highest finding severity: $(ConvertTo-InspectorHtmlEncodedText $highestSeverity)</div></div>
    <span class="pill $(Get-InspectorReportStatusClass -Value $highestSeverity)">$findingCount grouped findings</span>
  </div>
  <div class="narrative"><p>$prioritySentence Each finding below explains the issue, the trigger, affected objects, recommended action, and supporting evidence.</p>$failureText</div>
</section>
"@
}

function New-InspectorTopActionsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @($ReportModel.AssessmentRecommendations) |
        Select-Object -First 5 |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                Category       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Category')
                Confidence     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Confidence')
                Title          = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
                Action         = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Action')
                ObservationIds = @(
                    Get-InspectorReportProperty `
                        -InputObject $_ `
                        -Name 'ObservationIds'
                )
            }
        }

    $content = @"
<p class="muted">These actions are rendered from existing assessment recommendations only. No new recommendations are generated by the report layer.</p>
$(New-InspectorHtmlTable -Rows $rows -Columns @('Category','Confidence','Title','Action','ObservationIds') -EmptyMessage 'No recommended actions were supplied.' -Searchable)
"@

    return New-InspectorReportSection `
        -Id 'top-actions' `
        -Title 'Top Actions' `
        -Summary "$(@($rows).Count) recommended actions" `
        -Content $content
}

function New-InspectorTenantPostureHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $posture =
        Get-InspectorReportProperty `
            -InputObject $ReportModel `
            -Name 'TenantPosture'

    if ($null -eq $posture) {
        return '<section id="tenant-posture" class="section"><h2>Tenant Posture</h2><p class="empty-state">No tenant posture artifact was supplied.</p></section>'
    }

    $rows = @(
        [PSCustomObject]@{ Field = 'Label'; Value = Get-InspectorReportProperty -InputObject $posture -Name 'Label' }
        [PSCustomObject]@{ Field = 'HighestSeverity'; Value = Get-InspectorReportProperty -InputObject $posture -Name 'HighestSeverity' }
        [PSCustomObject]@{ Field = 'Confidence'; Value = Get-InspectorReportProperty -InputObject $posture -Name 'Confidence' }
        [PSCustomObject]@{ Field = 'ObservationCount'; Value = Get-InspectorReportProperty -InputObject $posture -Name 'ObservationCount' }
        [PSCustomObject]@{ Field = 'FindingCount'; Value = Get-InspectorReportProperty -InputObject $posture -Name 'FindingCount' }
        [PSCustomObject]@{ Field = 'RecommendationCount'; Value = Get-InspectorReportProperty -InputObject $posture -Name 'RecommendationCount' }
        [PSCustomObject]@{ Field = 'CorrelationCount'; Value = Get-InspectorReportProperty -InputObject $posture -Name 'CorrelationCount' }
    )

    return New-InspectorReportSection `
        -Id 'tenant-posture' `
        -Title 'Tenant Posture' `
        -Summary "$(@($rows).Count) posture fields" `
        -Content (New-InspectorHtmlTable -Rows $rows -Columns @('Field','Value'))
}

function New-InspectorFindingsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @($ReportModel.AssessmentFindings) |
        Sort-Object {
            Get-InspectorReportSeverityOrder -Severity ([string](Get-InspectorReportProperty -InputObject $_ -Name 'Severity'))
        }, Category, Title |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                Category       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Category')
                Severity       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Severity')
                Confidence     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Confidence')
                Title          = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
                Conclusion     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Conclusion')
                ObservationIds = @(
                    Get-InspectorReportProperty `
                        -InputObject $_ `
                        -Name 'ObservationIds'
                )
            }
        }

    return New-InspectorReportSection `
        -Id 'assessment-findings' `
        -Title 'Assessment Findings' `
        -Summary "$(@($rows).Count) findings" `
        -Content (New-InspectorHtmlTable -Rows $rows -Columns @('Category','Severity','Confidence','Title','Conclusion','ObservationIds') -EmptyMessage 'No assessment findings were supplied.' -Searchable) `
        -Collapsed
}

function New-InspectorRecommendationsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @($ReportModel.AssessmentRecommendations) |
        Sort-Object Category, Title |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                Category       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Category')
                Confidence     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Confidence')
                Title          = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
                Action         = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Action')
                Rationale      = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Rationale')
                ObservationIds = @(
                    Get-InspectorReportProperty `
                        -InputObject $_ `
                        -Name 'ObservationIds'
                )
            }
        }

    return New-InspectorReportSection `
        -Id 'assessment-recommendations' `
        -Title 'Recommendations' `
        -Summary "$(@($rows).Count) recommendations" `
        -Content (New-InspectorHtmlTable -Rows $rows -Columns @('Category','Confidence','Title','Action','Rationale','ObservationIds') -EmptyMessage 'No assessment recommendations were supplied.' -Searchable) `
        -Collapsed
}

function New-InspectorObservationGroupsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $groups =
        @($ReportModel.ObservationGroups)

    if ($groups.Count -eq 0) {
        return New-InspectorReportSection `
            -Id 'observation-groups' `
            -Title 'Observation Groups' `
            -Summary '0 groups' `
            -Content '<p class="empty-state">No observation groups were supplied.</p>' `
            -Collapsed
    }

    $html = [System.Collections.Generic.List[string]]::new()
    $html.Add('<div class="group-list">')

    foreach ($group in $groups) {
        $affected =
            @(
                Get-InspectorReportProperty `
                    -InputObject $group `
                    -Name 'AffectedObjects'
            )

        $observationIds =
            @(
                Get-InspectorReportProperty `
                    -InputObject $group `
                    -Name 'ObservationIds'
            )

        $affectedText =
            if ($affected.Count -gt 0) {
                ConvertTo-InspectorHtmlEncodedText ($affected -join '; ')
            }
            else {
                'Not available'
            }

        $html.Add('<details class="observation-group-card">')
        $html.Add("<summary><span class=""pill $(Get-InspectorReportStatusClass -Value ([string]$group.Severity))"">$([System.Net.WebUtility]::HtmlEncode([string]$group.Severity))</span> <strong>$(ConvertTo-InspectorHtmlEncodedText $group.Title)</strong> <span class=""group-count"">$($group.Count)x</span></summary>")
        $html.Add("<div class=""group-meta""><strong>Category:</strong> $(ConvertTo-InspectorHtmlEncodedText $group.Category) · <strong>Confidence:</strong> $(ConvertTo-InspectorHtmlEncodedText $group.Confidence)</div>")
        $html.Add("<p><strong>Why it matters:</strong> $(ConvertTo-InspectorHtmlEncodedText $group.WhyItMatters)</p>")
        $html.Add("<p><strong>Affected objects:</strong> $affectedText</p>")
        $html.Add("<p><strong>Observations:</strong> $(New-InspectorReportLinkList -Value $observationIds -Prefix 'observation' -MaxInline 8)</p>")
        $html.Add('</details>')
    }

    $html.Add('</div>')

    return New-InspectorReportSection `
        -Id 'observation-groups' `
        -Title 'Grouped Observation Summary' `
        -Summary "$($groups.Count) grouped observation types" `
        -Content ($html -join [Environment]::NewLine) `
        -Collapsed
}

function New-InspectorObservationsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @($ReportModel.SecurityObservations) |
        Sort-Object Category, {
            Get-InspectorReportSeverityOrder -Severity ([string](Get-InspectorReportProperty -InputObject $_ -Name 'Severity'))
        }, Title |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                ObservationId  = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ObservationId')
                Category       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Category')
                Severity       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Severity')
                Confidence     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Confidence')
                Title          = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
                AffectedObject = Get-InspectorReportObservationDisplayName -Observation $_
                ObjectType     = Get-InspectorReportObservationObjectType -Observation $_
                EvidenceIds    = @(
                    Get-InspectorReportProperty `
                        -InputObject $_ `
                        -Name 'EvidenceIds'
                )
            }
        }

    $table = New-InspectorHtmlTable -Rows $rows -Columns @('ObservationId','Category','Severity','Confidence','Title','ObjectType','AffectedObject','EvidenceIds') -EmptyMessage 'No security observations were supplied.' -Searchable

    return New-InspectorReportSection `
        -Id 'security-observations' `
        -Title 'Security Observations' `
        -Summary "$(@($rows).Count) observations" `
        -Content $table `
        -Collapsed
}

function New-InspectorInventoryHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @($ReportModel.ObjectIndex) |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                DisplayName              = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'DisplayName')
                ObjectType               = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ObjectType')
                ObjectId                 = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ObjectId')
                Status                   = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status')
                RelationshipStatus       = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'RelationshipStatus')
                RelationshipCompleteness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'RelationshipCompleteness')
                SecurityObservationCount = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'SecurityObservationCount')
            }
        }

    return New-InspectorReportSection `
        -Id 'object-inventory' `
        -Title 'Object Inventory' `
        -Summary "$(@($rows).Count) objects" `
        -Content (New-InspectorHtmlTable -Rows $rows -Columns @('DisplayName','ObjectType','ObjectId','Status','RelationshipStatus','RelationshipCompleteness','SecurityObservationCount') -EmptyMessage 'No object inventory was supplied.' -Searchable) `
        -Collapsed
}

function New-InspectorCategoryReviewHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $sections = [System.Collections.Generic.List[string]]::new()

    $map = @(
        [PSCustomObject]@{ Id='permission-exposure'; Title='Permission Exposure'; Category='Permissions' }
        [PSCustomObject]@{ Id='identity-governance'; Title='Identity Governance'; Category='IdentityGovernance' }
        [PSCustomObject]@{ Id='service-principal-governance'; Title='Service Principal Governance'; Category='ServicePrincipal' }
        [PSCustomObject]@{ Id='credential-hygiene'; Title='Credential Hygiene'; Category='Credentials' }
        [PSCustomObject]@{ Id='consent-review'; Title='Consent Review'; Category='Consent' }
    )

    foreach ($item in $map) {
        $rows =
            @($ReportModel.SecurityObservations) |
            Where-Object {
                (Get-InspectorReportProperty -InputObject $_ -Name 'Category') -eq $item.Category
            } |
            Sort-Object {
                Get-InspectorReportSeverityOrder -Severity ([string](Get-InspectorReportProperty -InputObject $_ -Name 'Severity'))
            }, Title |
            ForEach-Object {
                [PSCustomObject][ordered]@{
                    Category     = $item.Category
                    Severity     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Severity')
                    Confidence   = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Confidence')
                    Title        = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
                    ObjectType   = Get-InspectorReportObservationObjectType -Observation $_
                    AffectedObject = Get-InspectorReportObservationDisplayName -Observation $_
                    WhyItMatters = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'WhyItMatters')
                }
            }

        $section =
            New-InspectorReportSection `
                -Id $item.Id `
                -Title $item.Title `
                -Summary "$(@($rows).Count) observations" `
                -Content (
                    New-InspectorHtmlTable `
                        -Rows $rows `
                        -Columns @(
                            'Severity',
                            'Confidence',
                            'Title',
                            'ObjectType',
                            'AffectedObject',
                            'WhyItMatters'
                        ) `
                        -EmptyMessage "No $($item.Title) observations were supplied." `
                        -Searchable `
                        -DefaultCategory $item.Category
                ) `
                -Collapsed

        $null = $sections.Add($section)
    }

    return ($sections -join [Environment]::NewLine)
}

function New-InspectorCorrelationsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @($ReportModel.AssessmentCorrelations) |
        Sort-Object CorrelationType, Title |
        ForEach-Object {
            [PSCustomObject][ordered]@{
                CorrelationType = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'CorrelationType')
                Confidence      = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Confidence')
                Title           = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Title')
                Description     = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Description')
                ObservationIds  = @(
                    Get-InspectorReportProperty `
                        -InputObject $_ `
                        -Name 'ObservationIds'
                )
            }
        }

    $content = @"
<p class="muted">Correlation records are co-occurrence review signals only. They are not attack paths, privilege paths, or exploitability claims.</p>
$(New-InspectorHtmlTable -Rows $rows -Columns @('CorrelationType','Confidence','Title','Description','ObservationIds') -EmptyMessage 'No assessment correlations were supplied.' -Searchable)
"@

    return New-InspectorReportSection `
        -Id 'correlations' `
        -Title 'Correlation Summaries' `
        -Summary "$(@($rows).Count) correlations" `
        -Content $content `
        -Collapsed
}

function New-InspectorEvidenceHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $rows =
        @(
            @($ReportModel.EvidenceRows) |
            Where-Object { $null -ne $_ } |
            Group-Object {
                $evidenceId =
                    ConvertTo-InspectorReportString `
                        (Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId')

                if (-not [string]::IsNullOrWhiteSpace($evidenceId)) {
                    return "EvidenceId|$evidenceId"
                }

                $parentInput =
                    ConvertTo-InspectorReportString `
                        (Get-InspectorReportProperty -InputObject $_ -Name 'ParentInput')

                $parentResolutionType =
                    ConvertTo-InspectorReportString `
                        (Get-InspectorReportProperty -InputObject $_ -Name 'ParentResolutionType')

                $queryName =
                    ConvertTo-InspectorReportString `
                        (Get-InspectorReportProperty -InputObject $_ -Name 'QueryName')

                $requiredPermission =
                    ConvertTo-InspectorReportString `
                        (Get-InspectorReportProperty -InputObject $_ -Name 'RequiredPermission')

                $status =
                    ConvertTo-InspectorReportString `
                        (Get-InspectorReportProperty -InputObject $_ -Name 'Status')

                return "Shape|$parentInput|$parentResolutionType|$queryName|$requiredPermission|$status"
            } |
            ForEach-Object {
                $first = @($_.Group)[0]

                [PSCustomObject][ordered]@{
                    EvidenceId           = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'EvidenceId')
                    Count                = @($_.Group).Count
                    ParentInput          = (@(
                        @($_.Group) |
                            ForEach-Object {
                                ConvertTo-InspectorReportString `
                                    (Get-InspectorReportProperty -InputObject $_ -Name 'ParentInput')
                            } |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            Select-Object -Unique
                    ) -join '; ')
                    ParentResolutionType = (@(
                        @($_.Group) |
                            ForEach-Object {
                                ConvertTo-InspectorReportString `
                                    (Get-InspectorReportProperty -InputObject $_ -Name 'ParentResolutionType')
                            } |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            Select-Object -Unique
                    ) -join '; ')
                    QueryName            = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'QueryName')
                    RequiredPermission   = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'RequiredPermission')
                    Status               = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $first -Name 'Status')
                }
            } |
            Sort-Object ParentResolutionType, ParentInput, QueryName, EvidenceId
        )

    $content = @"
<p class="muted">Duplicate evidence records are grouped for the HTML view only. The source artifacts remain unchanged.</p>
$(New-InspectorHtmlTable -Rows $rows -Columns @('EvidenceId','Count','ParentInput','ParentResolutionType','QueryName','RequiredPermission','Status') -EmptyMessage 'No evidence references were supplied.' -Searchable)
"@

    return New-InspectorReportSection `
        -Id 'evidence' `
        -Title 'Evidence References' `
        -Summary "$(@($rows).Count) grouped evidence records" `
        -Content $content `
        -Collapsed
}

function New-InspectorExportMetadataHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $manifest =
        Get-InspectorReportProperty `
            -InputObject $ReportModel `
            -Name 'Manifest'

    $rows = @(
        [PSCustomObject]@{ Field='ReportSchemaVersion'; Value=$ReportModel.SchemaVersion }
        [PSCustomObject]@{ Field='ReportGeneratedAt'; Value=$ReportModel.GeneratedAt }
        [PSCustomObject]@{ Field='SourceKind'; Value=$ReportModel.SourceKind }
        [PSCustomObject]@{ Field='SourcePath'; Value=$ReportModel.SourcePath }
        [PSCustomObject]@{ Field='ManifestSchemaVersion'; Value=(Get-InspectorReportProperty -InputObject $manifest -Name 'SchemaVersion') }
        [PSCustomObject]@{ Field='Graph calls issued by report'; Value=$ReportModel.GraphCallsIssued }
        [PSCustomObject]@{ Field='Intelligence added by report'; Value=$ReportModel.IntelligenceAdded }
        [PSCustomObject]@{ Field='Observations added by report'; Value=$ReportModel.NewObservationsAdded }
        [PSCustomObject]@{ Field='RiskScoreProduced'; Value=$ReportModel.RiskScoreProduced }
        [PSCustomObject]@{ Field='AttackPathsProduced'; Value=$ReportModel.AttackPathsProduced }
        [PSCustomObject]@{ Field='ClientSideInteractivity'; Value=$ReportModel.ClientSideInteractivity }
        [PSCustomObject]@{ Field='Printable'; Value=$ReportModel.Printable }
    )

    return New-InspectorReportSection `
        -Id 'export-metadata' `
        -Title 'Export Metadata' `
        -Summary "$(@($rows).Count) metadata fields" `
        -Content (New-InspectorHtmlTable -Rows $rows -Columns @('Field','Value')) `
        -Collapsed
}

function New-InspectorLimitationsHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $items = @(
        @($ReportModel.ReportLimitations) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Sort-Object -Unique
    )

    if (@($items).Count -eq 0) {
        return New-InspectorReportSection `
            -Id 'limitations' `
            -Title 'Assessment Limitations' `
            -Summary '0 limitations' `
            -Content '<p class="empty-state">No limitations were supplied.</p>' `
            -Collapsed
    }

    $list =
        @(
            $items |
            ForEach-Object {
                "<li>$(ConvertTo-InspectorHtmlEncodedText $_)</li>"
            }
        ) -join [Environment]::NewLine

    return New-InspectorReportSection `
        -Id 'limitations' `
        -Title 'Assessment Limitations' `
        -Summary "$(@($items).Count) limitations" `
        -Content "<ul class=""limitations"">$list</ul>" `
        -Collapsed
}
