Set-StrictMode -Version Latest

$privateFunctions = @(
    'Private/Telemetry/Telemetry.Common.ps1',
    'Private/Telemetry/New-InspectorRuntimeTelemetry.ps1',
    'Private/Telemetry/Start-InspectorTelemetryStage.ps1',
    'Private/Telemetry/Stop-InspectorTelemetryStage.ps1',
    'Private/Telemetry/Add-InspectorGraphTelemetryRecord.ps1',
    'Private/Diagnostics/Diagnostics.Common.ps1',
    'Private/Diagnostics/New-InspectorRunLog.ps1',
    'Private/Diagnostics/Write-InspectorDiagnosticEvent.ps1',
    'Private/Diagnostics/Complete-InspectorRunLog.ps1',
    'Private/Invoke-InspectorGraphRequest.ps1',
    'Private/Invoke-InspectorGraphBatchRequest.ps1',
    'Private/Resolve-EntraObject.ps1',
    'Private/Collectors/Collector.Common.ps1',
    'Private/Collectors/Get-InspectorApplicationRelationships.ps1',
    'Private/Collectors/Get-InspectorServicePrincipalRelationships.ps1',
    'Private/Collectors/Get-InspectorUserRelationships.ps1',
    'Private/Collectors/Get-InspectorGroupRelationships.ps1',
    'Private/Collectors/Invoke-InspectorRelationshipCollection.ps1',
    'Private/Classification/PublisherClassification.Common.ps1',
    'Private/Normalize/ConvertTo-InspectorObjectInsight.ps1',
    'Private/Permissions/Permission.Common.ps1',
    'Private/Permissions/Get-InspectorPermissionCatalog.ps1',
    'Private/Permissions/Resolve-InspectorPermissionMetadata.ps1',
    'Private/Permissions/ConvertTo-InspectorPermissionInsight.ps1',
    'Private/Permissions/Add-InspectorPermissionIntelligence.ps1',
    'Private/Rules/Rule.Common.ps1',
    'Private/Rules/Invoke-InspectorRules.ps1',
    'Private/Observations/Observation.Common.ps1',
    'Private/Observations/Invoke-InspectorObservationEngine.ps1',
    'Private/Discovery/Discovery.Common.ps1',
    'Private/Discovery/Invoke-InspectorDiscovery.ps1',
    'Private/Snapshot/Snapshot.Common.ps1',
    'Private/Snapshot/Snapshot.Persistence.ps1',
    'Private/Targeting/Targeting.Common.ps1',
    'Private/Targeting/Resolve-InspectorAssessmentTargets.ps1',
    'Private/Comparison/Comparison.Common.ps1',
    'Private/Comparison/Compare-InspectorTenantSnapshots.ps1',
    'Private/Policy/AssessmentPolicy.Common.ps1',
    'Private/Policy/Invoke-InspectorAssessmentPolicy.ps1',
    'Private/Snapshot/ConvertFrom-InspectorTenantSnapshot.ps1',
    'Private/Snapshot/New-InspectorTenantSnapshot.ps1',
    'Private/Snapshot/Resolve-EntraObjectFromSnapshot.ps1',
    'Private/Snapshot/Get-InspectorSnapshotRelationships.ps1',
    'Private/Pipeline/Invoke-InspectorPipeline.ps1',
    'Private/Export/Export.Common.ps1',
    'Private/Export/ConvertTo-InspectorAssessmentExport.ps1',
    'Private/Export/New-InspectorAssessmentMarkdown.ps1',
    'Private/Intelligence/Intelligence.Common.ps1',
    'Private/References/Get-InspectorRecommendationReferenceCatalog.ps1',
    'Private/References/Resolve-InspectorRecommendationReferences.ps1',
    'Private/Intelligence/Invoke-InspectorAssessmentIntelligence.ps1',
    'Private/Reporting/Report.Common.ps1',
    'Private/Reporting/ConvertTo-InspectorReportModel.ps1',
    'Private/Reporting/Render-InspectorHtmlSections.ps1',
    'Private/Reporting/New-InspectorHtmlReport.ps1'
)

$publicFunctions = @(
    'Public/Connect-InspectorGraph.ps1',
    'Public/Get-EntraObjectInsight.ps1',
    'Public/Invoke-EntraTenantInspection.ps1',
    'Public/Export-EntraTenantInspection.ps1',
    'Public/Invoke-EntraAssessmentIntelligence.ps1',
    'Public/Export-EntraAssessmentReport.ps1',
    'Public/Invoke-EntraSecurityAssessment.ps1'
)

foreach ($relativePath in ($privateFunctions + $publicFunctions)) {

    $path = Join-Path $PSScriptRoot $relativePath

    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required module file was not found: $path"
    }

    . $path
}

Export-ModuleMember -Function @(
    'Connect-InspectorGraph',
    'Get-EntraObjectInsight',
    'Invoke-EntraTenantInspection',
    'Export-EntraTenantInspection',
    'Invoke-EntraAssessmentIntelligence',
    'Export-EntraAssessmentReport',
    'Invoke-EntraSecurityAssessment'
)
