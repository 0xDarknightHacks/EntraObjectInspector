function New-InspectorAssessmentMarkdown {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ExportModel
    )

    $manifest =
        Get-InspectorExportProperty `
            -InputObject $ExportModel `
            -Name 'Manifest'

    $summary =
        Get-InspectorExportProperty `
            -InputObject $ExportModel `
            -Name 'Summary'

    $severitySummary =
        @(
            Get-InspectorExportProperty `
                -InputObject $summary `
                -Name 'SeveritySummary'
        )

    $categorySummary =
        @(
            Get-InspectorExportProperty `
                -InputObject $summary `
                -Name 'CategorySummary'
        )

    $tenantPosture =
        Get-InspectorExportProperty `
            -InputObject $ExportModel `
            -Name 'TenantPosture'

    $findingRows =
        @(
            Get-InspectorExportProperty `
                -InputObject $ExportModel `
                -Name 'AssessmentFindingRows'
        )

    $recommendationRows =
        @(
            Get-InspectorExportProperty `
                -InputObject $ExportModel `
                -Name 'AssessmentRecommendationRows'
        )

    $correlationRows =
        @(
            Get-InspectorExportProperty `
                -InputObject $ExportModel `
                -Name 'AssessmentCorrelationRows'
        )

    $scopeInventory =
        Get-InspectorExportProperty `
            -InputObject $summary `
            -Name 'ScopeInventory'

    $artifactRows =
        @(
            Get-InspectorExportProperty `
                -InputObject $manifest `
                -Name 'Artifacts'
        )

    $assessmentLimitations =
        @(
            Get-InspectorExportProperty `
                -InputObject $ExportModel `
                -Name 'AssessmentLimitations'
        )

    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add("# $(Get-InspectorExportProperty -InputObject $manifest -Name 'AssessmentName')")
    $lines.Add('')
    $lines.Add('## Assessment Manifest')
    $lines.Add('')
    $lines.Add('| Field | Value |')
    $lines.Add('|---|---|')
    $lines.Add("| Export ID | $(Get-InspectorExportProperty -InputObject $manifest -Name 'ExportId') |")
    $lines.Add("| Generated At | $(Get-InspectorExportProperty -InputObject $manifest -Name 'GeneratedAt') |")
    $lines.Add("| Source Status | $(Get-InspectorExportProperty -InputObject $manifest -Name 'SourceStatus') |")
    $lines.Add("| Tenant ID | $(Get-InspectorExportProperty -InputObject $manifest -Name 'TenantId') |")
    $lines.Add("| Tenant Name | $(Get-InspectorExportProperty -InputObject $manifest -Name 'TenantDisplayName') |")
    $lines.Add("| Module Version | $(Get-InspectorExportProperty -InputObject $manifest -Name 'ModuleVersion') |")
    $lines.Add("| Source Started At | $(Get-InspectorExportProperty -InputObject $manifest -Name 'SourceStartedAt') |")
    $lines.Add("| Source Completed At | $(Get-InspectorExportProperty -InputObject $manifest -Name 'SourceCompletedAt') |")
    $lines.Add("| Assessment Intelligence Included | $(Get-InspectorExportProperty -InputObject $manifest -Name 'AssessmentIntelligenceIncluded') |")
    $lines.Add("| Graph Calls Issued By Export | $(Get-InspectorExportProperty -InputObject $manifest -Name 'GraphCallsIssued') |")
    $lines.Add("| Intelligence Added By Export | $(Get-InspectorExportProperty -InputObject $manifest -Name 'IntelligenceAdded') |")
    $lines.Add("| Package Validation Status | $(Get-InspectorExportProperty -InputObject $manifest -Name 'PackageValidationStatus') |")
    $lines.Add("| Release Eligible | $(Get-InspectorExportProperty -InputObject $manifest -Name 'ReleaseEligible') |")
    $lines.Add('')

    $lines.Add('## Summary')
    $lines.Add('')
    $lines.Add('| Metric | Count |')
    $lines.Add('|---|---:|')
    $lines.Add("| Discovered objects | $(Get-InspectorExportProperty -InputObject $summary -Name 'DiscoveredCount') |")
    $lines.Add("| Processed objects | $(Get-InspectorExportProperty -InputObject $summary -Name 'ProcessedCount') |")
    $lines.Add("| Failed objects | $(Get-InspectorExportProperty -InputObject $summary -Name 'FailedCount') |")
    $lines.Add("| Skipped objects | $(Get-InspectorExportProperty -InputObject $summary -Name 'SkippedCount') |")
    $lines.Add("| Object insights | $(Get-InspectorExportProperty -InputObject $summary -Name 'ObjectInsightCount') |")
    $lines.Add("| Security observations | $(Get-InspectorExportProperty -InputObject $summary -Name 'SecurityObservationCount') |")
    $lines.Add("| Raw observations | $(Get-InspectorExportProperty -InputObject $summary -Name 'RawObservationCount') |")
    $lines.Add("| Deduplicated observations | $(Get-InspectorExportProperty -InputObject $summary -Name 'DeduplicatedObservationCount') |")
    $lines.Add("| Duplicate observations | $(Get-InspectorExportProperty -InputObject $summary -Name 'DuplicateObservationCount') |")
    $lines.Add("| Grouped findings | $(Get-InspectorExportProperty -InputObject $summary -Name 'GroupedFindingCount') |")
    $lines.Add("| Evidence records | $(Get-InspectorExportProperty -InputObject $summary -Name 'EvidenceRecordCount') |")
    $lines.Add("| Assessment findings | $(Get-InspectorExportProperty -InputObject $summary -Name 'AssessmentFindingCount') |")
    $lines.Add("| Assessment recommendations | $(Get-InspectorExportProperty -InputObject $summary -Name 'AssessmentRecommendationCount') |")
    $lines.Add("| Assessment correlations | $(Get-InspectorExportProperty -InputObject $summary -Name 'AssessmentCorrelationCount') |")
    $lines.Add('')

    $lines.Add('## Scope Inventory')
    $lines.Add('')
    $lines.Add('| Metric | Count |')
    $lines.Add('|---|---:|')
    $lines.Add("| Users discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'UsersDiscovered') |")
    $lines.Add("| App registrations discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'AppRegistrationsDiscovered') |")
    $lines.Add("| Enterprise applications / service principals discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'ServicePrincipalsDiscovered') |")
    $lines.Add("| Groups discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'GroupsDiscovered') |")
    $lines.Add("| OAuth2 permission grants discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'OAuth2PermissionGrantsDiscovered') |")
    $lines.Add("| Subscribed SKUs discovered (license inventory) | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'SubscribedSkusDiscovered') |")
    $lines.Add("| License inventory status | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'LicenseInventoryStatus') |")
    $lines.Add("| PIM license capability | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'PimLicenseCapability') |")
    $lines.Add("| Identity Protection license capability | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'IdentityProtectionLicenseCapability') |")
    $lines.Add("| Directory role definitions discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'DirectoryRoleDefinitionsDiscovered') |")
    $lines.Add("| Directory role assignments discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'DirectoryRoleAssignmentsDiscovered') |")
    $lines.Add("| PIM active role states discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'RoleAssignmentScheduleInstancesDiscovered') |")
    $lines.Add("| PIM eligible role states discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'RoleEligibilityScheduleInstancesDiscovered') |")
    $lines.Add("| Administrative units discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'AdministrativeUnitsDiscovered') |")
    $lines.Add("| Administrative unit members discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'AdministrativeUnitMembersDiscovered') |")
    $lines.Add("| Risky users discovered | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'RiskyUsersDiscovered') |")
    $lines.Add("| Evidence records collected | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'EvidenceRecordsCollected') |")
    $lines.Add("| Failed objects | $(Get-InspectorExportProperty -InputObject $scopeInventory -Name 'FailedObjects') |")
    $lines.Add('')

    if ($null -ne $tenantPosture) {
        $lines.Add('## Tenant Posture')
        $lines.Add('')
        $lines.Add('| Field | Value |')
        $lines.Add('|---|---|')
        $lines.Add("| Label | $(Get-InspectorExportProperty -InputObject $tenantPosture -Name 'Label') |")
        $lines.Add("| Highest Severity | $(Get-InspectorExportProperty -InputObject $tenantPosture -Name 'HighestSeverity') |")
        $lines.Add("| Confidence | $(Get-InspectorExportProperty -InputObject $tenantPosture -Name 'Confidence') |")
        $lines.Add("| Observation Count | $(Get-InspectorExportProperty -InputObject $tenantPosture -Name 'ObservationCount') |")
        $lines.Add("| Finding Count | $(Get-InspectorExportProperty -InputObject $tenantPosture -Name 'FindingCount') |")
        $lines.Add("| Recommendation Count | $(Get-InspectorExportProperty -InputObject $tenantPosture -Name 'RecommendationCount') |")
        $lines.Add("| Correlation Count | $(Get-InspectorExportProperty -InputObject $tenantPosture -Name 'CorrelationCount') |")
        $lines.Add('')
    }

    $lines.Add('## Observations by Severity')
    $lines.Add('')
    $lines.Add('| Severity | Count |')
    $lines.Add('|---|---:|')

    foreach ($item in @($severitySummary)) {
        $lines.Add("| $(Get-InspectorExportProperty -InputObject $item -Name 'Severity') | $(Get-InspectorExportProperty -InputObject $item -Name 'Count') |")
    }

    if (@($severitySummary).Count -eq 0) {
        $lines.Add('| None | 0 |')
    }

    $lines.Add('')
    $lines.Add('## Observations by Category')
    $lines.Add('')
    $lines.Add('| Category | Count |')
    $lines.Add('|---|---:|')

    foreach ($item in @($categorySummary)) {
        $lines.Add("| $(Get-InspectorExportProperty -InputObject $item -Name 'Category') | $(Get-InspectorExportProperty -InputObject $item -Name 'Count') |")
    }

    if (@($categorySummary).Count -eq 0) {
        $lines.Add('| None | 0 |')
    }

    $lines.Add('')
    $lines.Add('## Assessment Findings')
    $lines.Add('')
    $lines.Add('| Category | Severity | Confidence | Title |')
    $lines.Add('|---|---|---|---|')

    foreach ($finding in $findingRows) {
        $title = ([string](Get-InspectorExportProperty -InputObject $finding -Name 'Title')).Replace('|', '\|')
        $lines.Add("| $(Get-InspectorExportProperty -InputObject $finding -Name 'Category') | $(Get-InspectorExportProperty -InputObject $finding -Name 'Severity') | $(Get-InspectorExportProperty -InputObject $finding -Name 'Confidence') | $title |")
    }

    if ($findingRows.Count -eq 0) {
        $lines.Add('| None | None | None | No assessment intelligence findings exported |')
    }

    $lines.Add('')
    $lines.Add('## Assessment Recommendations')
    $lines.Add('')
    $lines.Add('| Category | Confidence | Title | Action |')
    $lines.Add('|---|---|---|---|')

    foreach ($recommendation in $recommendationRows) {
        $title = ([string](Get-InspectorExportProperty -InputObject $recommendation -Name 'Title')).Replace('|', '\|')
        $action = ([string](Get-InspectorExportProperty -InputObject $recommendation -Name 'Action')).Replace('|', '\|')
        $lines.Add("| $(Get-InspectorExportProperty -InputObject $recommendation -Name 'Category') | $(Get-InspectorExportProperty -InputObject $recommendation -Name 'Confidence') | $title | $action |")
    }

    if ($recommendationRows.Count -eq 0) {
        $lines.Add('| None | None | No recommendations exported | None |')
    }

    $lines.Add('')
    $lines.Add('## Assessment Correlations')
    $lines.Add('')
    $lines.Add('| Category | Confidence | Title |')
    $lines.Add('|---|---|---|')

    foreach ($correlation in $correlationRows) {
        $category = Get-InspectorExportProperty -InputObject $correlation -Name 'Category'
        $confidence = Get-InspectorExportProperty -InputObject $correlation -Name 'Confidence'
        $title = [string](Get-InspectorExportProperty -InputObject $correlation -Name 'Title')

        if ([string]::IsNullOrWhiteSpace($category)) {
            $category = Get-InspectorExportProperty -InputObject $correlation -Name 'CorrelationType'
        }

        if ([string]::IsNullOrWhiteSpace($confidence)) {
            $confidence = Get-InspectorExportProperty -InputObject $correlation -Name 'CorrelationStrength'
        }

        if ([string]::IsNullOrWhiteSpace($title)) {
            $title = Get-InspectorExportProperty -InputObject $correlation -Name 'Summary'
        }

        $title = ([string]$title).Replace('|', '\|')
        $lines.Add("| $category | $confidence | $title |")
    }

    if ($correlationRows.Count -eq 0) {
        $lines.Add('| None | None | No correlations exported |')
    }

    $lines.Add('')
    $lines.Add('## Detailed Artifacts')
    $lines.Add('')
    $lines.Add('| Artifact | Kind | Records | Path |')
    $lines.Add('|---|---|---:|---|')

    foreach ($artifact in @($artifactRows)) {
        $artifactPath = ([string](Get-InspectorExportProperty -InputObject $artifact -Name 'Path')).Replace('|', '\|')
        $lines.Add("| $(Get-InspectorExportProperty -InputObject $artifact -Name 'Name') | $(Get-InspectorExportProperty -InputObject $artifact -Name 'Kind') | $(Get-InspectorExportProperty -InputObject $artifact -Name 'RecordCount') | $artifactPath |")
    }

    if (@($artifactRows).Count -eq 0) {
        $lines.Add('| None | None | 0 | No artifact records supplied |')
    }

    $lines.Add('')
    $lines.Add('## Assessment Intelligence Limitations')
    $lines.Add('')

    foreach ($limitation in $assessmentLimitations) {
        $lines.Add("- $limitation")
    }

    if ($assessmentLimitations.Count -eq 0) {
        $lines.Add('- No assessment intelligence limitations were exported.')
    }

    $lines.Add('')
    $lines.Add('## Export Limitations')
    $lines.Add('')

    foreach ($limitation in @(Get-InspectorExportProperty -InputObject $summary -Name 'ExportLimitations')) {
        $lines.Add("- $limitation")
    }

    $lines.Add('')

    return ($lines -join [Environment]::NewLine)
}
