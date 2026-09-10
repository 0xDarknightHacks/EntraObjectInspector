$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'assessment export layer' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestObservation {
                param (
                    [string]$ObservationId = 'OBS-1',
                    [string]$Category = 'Permissions',
                    [string]$Severity = 'High',
                    [string]$Title = 'High-impact permission: Directory.ReadWrite.All'
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.SecurityObservation'
                    SchemaVersion = '0.7.0'
                    ObservationId = $ObservationId
                    Category = $Category
                    Title = $Title
                    Description = 'Description'
                    Severity = $Severity
                    Confidence = 'High'
                    AffectedObject = [PSCustomObject]@{
                        ObjectType = 'ServicePrincipal'
                        ObjectId = 'sp-1'
                        DisplayName = 'SP One'
                    }
                    EvidenceIds = @('ev-1')
                    MicrosoftReference = 'Microsoft reference'
                    WhyItMatters = 'Why it matters'
                    Limitations = @()
                    Recommendation = 'Review'
                    SourceRuleIds = @('RULE-1')
                    Metadata = [PSCustomObject]@{
                        PermissionName = 'Directory.ReadWrite.All'
                    }
                }
            }

            function New-TestTenantResult {
                param (
                    [object[]]$Observations = @((New-TestObservation)),
                    [object[]]$FailedObjects = @()
                )

                $objectInsight = [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    Input = 'sp-1'
                    Status = 'Resolved'
                    ResolutionType = 'ApplicationIdentity'
                    SourceObjects = @()
                    Relationships = @()
                    Artifacts = @()
                    Evidence = @(
                        [PSCustomObject]@{
                            EvidenceId = 'ev-1'
                            QueryName = 'SyntheticQuery'
                            Endpoint = 'https://graph.microsoft.com/v1.0/synthetic'
                            RequiredPermission = 'Application.Read.All'
                            CollectionTime = '2026-08-30T10:00:00Z'
                            Status = 'Success'
                            Limitations = @()
                        }
                    )
                    RelationshipCollection = [PSCustomObject]@{
                        Status = 'Success'
                        Completeness = 'Complete'
                        Evidence = @()
                    }
                    RuleResults = @()
                    PermissionInsights = @()
                    SecurityObservations = @($Observations)
                }

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                    SchemaVersion = '0.7.0'
                    StartedAt = '2026-08-30T10:00:00Z'
                    CompletedAt = '2026-08-30T10:01:00Z'
                    Status = 'Success'
                    Discovery = [PSCustomObject]@{
                        TenantMetadata = [PSCustomObject]@{
                            TenantId = 'tenant-1'
                            TenantDisplayName = 'Tenant One'
                        }
                        Evidence = @(
                            [PSCustomObject]@{
                                EvidenceId = 'ev-discovery'
                                QueryName = 'DiscoverApplications'
                                Endpoint = 'https://graph.microsoft.com/v1.0/applications'
                                RequiredPermission = 'Application.Read.All'
                                RequiredForCoverage = $false
                                CollectionTime = '2026-08-30T10:00:00Z'
                                Status = 'Success'
                                ResultCount = 1
                                Limitations = @()
                            }
                        )
                    }
                    Pipeline = [PSCustomObject]@{}
                    ObjectInsights = @($objectInsight)
                    SecurityObservations = @($Observations)
                    FailedObjects = @($FailedObjects)
                    Logs = @(
                        [PSCustomObject]@{
                            Timestamp = '2026-08-30T10:00:00Z'
                            Stage = 'Pipeline'
                            Level = 'Information'
                            Message = 'Processed'
                            Data = [PSCustomObject]@{
                                ObjectKey = 'ServicePrincipal:sp-1'
                            }
                        }
                    )
                    Summary = [PSCustomObject]@{
                        TenantId = 'tenant-1'
                        TenantDisplayName = 'Tenant One'
                        DiscoveredCount = 1
                        ProcessedCount = 1
                        FailedCount = @($FailedObjects).Count
                        SkippedCount = 0
                        ObjectInsightCount = 1
                        SecurityObservationCount = @($Observations).Count
                    }
                }
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                throw 'Export must not call Graph.'
            }
        }

        It 'converts a tenant result into an export model without Graph calls' {
            $tenant = New-TestTenantResult

            $model =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant `
                    -AssessmentName 'Unit Test Assessment'

            $model.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.AssessmentExportModel'
            $model.Manifest.SchemaVersion | Should -Be '0.10.0'
            $model.Manifest.AssessmentName | Should -Be 'Unit Test Assessment'
            $model.Manifest.GraphCallsIssued | Should -Be 0
            $model.Manifest.GraphCallsAfterSnapshot | Should -BeNullOrEmpty
            $model.Summary.GraphCallsAfterSnapshot | Should -BeNullOrEmpty
            $model.Manifest.IntelligenceAdded | Should -BeFalse
            $model.Manifest.TenantId | Should -Be 'tenant-1'
            $model.Manifest.TenantDisplayName | Should -Be 'Tenant One'
            $model.Manifest.ModuleVersion | Should -Not -BeNullOrEmpty
            $model.Manifest.RunId | Should -Not -BeNullOrEmpty
            $model.Manifest.ReportId | Should -Not -BeNullOrEmpty
            $model.Manifest.PSObject.Properties.Name | Should -Contain 'AssessmentCoverage'
            $model.Summary.PSObject.Properties.Name | Should -Contain 'AssessmentCoverage'
            $model.Summary.RunId | Should -Be $model.Manifest.RunId
            $model.Summary.ReportId | Should -Be $model.Manifest.ReportId
            $model.Summary.FailedObjectCount | Should -Be $model.Manifest.FailedObjectCount
            $model.Summary.SecurityObservationCount | Should -Be 1
            $model.Summary.TenantId | Should -Be 'tenant-1'
            $model.Summary.TenantDisplayName | Should -Be 'Tenant One'
            $model.Summary.ModuleVersion | Should -Not -BeNullOrEmpty
            $model.SecurityObservationRows.Count | Should -Be 1
            $model.ObjectIndexRows.Count | Should -Be 1
            $model.EvidenceRows.Count | Should -Be 2
            (@($model.EvidenceRows | Where-Object QueryName -eq 'DiscoverApplications')[0].RequiredForCoverage) | Should -BeFalse

            $tenant | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue 0 -Force
            $measuredModel =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant `
                    -AssessmentName 'Measured Graph Provenance Assessment'

            $measuredModel.Manifest.GraphCallsAfterSnapshot | Should -Be 0
            $measuredModel.Summary.GraphCallsAfterSnapshot | Should -Be 0

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'persists report-safe inventory details in the assessment summary' {
            $tenant = New-TestTenantResult
            $tenant | Add-Member -NotePropertyName TenantSnapshot -NotePropertyValue ([PSCustomObject]@{
                Collections = [PSCustomObject]@{
                    Applications=@(); ServicePrincipals=@(); Groups=@(); DirectoryRoleDefinitions=@(); DirectoryRoleAssignments=@()
                    RoleAssignmentScheduleInstances=@(); RoleEligibilityScheduleInstances=@(); AdministrativeUnits=@()
                    Users=@([PSCustomObject]@{ id='user-1'; displayName='Alice Example'; userPrincipalName='alice@example.com' })
                    RiskyUsers=@([PSCustomObject]@{ id='user-1'; userPrincipalName='alice@example.com'; riskLevel='high'; riskState='atRisk' })
                    SubscribedSkus=@([PSCustomObject]@{ skuId='sku-1'; skuPartNumber='SPE_E5'; capabilityStatus='Enabled' })
                }
            })

            $model = ConvertTo-InspectorAssessmentExport -InputObject $tenant -AssessmentName 'Inventory projection test'

            $model.Summary.InventoryDetails.ActiveSkus[0].Product | Should -Be 'SPE_E5'
            $model.Summary.InventoryDetails.RiskyUsers[0].DisplayName | Should -Be 'Alice Example'
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'builds severity and category summaries deterministically' {
            $tenant =
                New-TestTenantResult `
                    -Observations @(
                        (New-TestObservation -ObservationId 'OBS-1' -Category 'Permissions' -Severity 'High')
                        (New-TestObservation -ObservationId 'OBS-2' -Category 'Credentials' -Severity 'Medium' -Title 'Credential expires soon')
                        (New-TestObservation -ObservationId 'OBS-3' -Category 'Credentials' -Severity 'Medium' -Title 'Expired credential')
                    )

            $model = ConvertTo-InspectorAssessmentExport -InputObject $tenant

            ($model.Summary.SeveritySummary | Where-Object Severity -eq 'High').Count | Should -Be 1
            ($model.Summary.SeveritySummary | Where-Object Severity -eq 'Medium').Count | Should -Be 2
            ($model.Summary.CategorySummary | Where-Object Category -eq 'Credentials').Count | Should -Be 2
            ($model.Summary.CategorySummary | Where-Object Category -eq 'Permissions').Count | Should -Be 1
        }

        It 'creates Markdown summary content' {
            $tenant = New-TestTenantResult
            $model = ConvertTo-InspectorAssessmentExport -InputObject $tenant -AssessmentName 'Markdown Test'

            $markdown =
                New-InspectorAssessmentMarkdown `
                    -ExportModel $model

            $markdown | Should -Match '# Markdown Test'
            $markdown | Should -Match '## Summary'
            $markdown | Should -Match '## Scope Inventory'
            $markdown | Should -Match 'Active role schedule instances collected'
            $markdown | Should -Match 'Eligible role schedule instances collected'
            $markdown | Should -Match '## Detailed Artifacts'
            $markdown | Should -Not -Match '## Security Observations'
        }

        It 'exports JSON, CSV, and Markdown artifacts' {
            $tenant = New-TestTenantResult

            $result =
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Export Test' `
                    -ExportDirectoryName 'export-test' `
                    -Force

            $result.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.AssessmentExportResult'
            $result.Status | Should -Be 'Success'
            $result.GraphCallsIssued | Should -Be 0
            $result.IntelligenceAdded | Should -BeFalse
            $result.PerformanceProfile | Should -Not -BeNullOrEmpty
            ($result.PerformanceProfile.TotalDurationMs -ge 0) | Should -BeTrue
            ($result.PerformanceProfile.ModelBuildDurationMs -ge 0) | Should -BeTrue
            @($result.PerformanceProfile.LargestArtifacts).Count | Should -BeGreaterThan 0

            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-manifest.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-summary.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'security-observations.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'failed-objects.json') | Should -BeTrue
            (Get-Content -LiteralPath (Join-Path $result.ExportDirectory 'failed-objects.json') -Raw).Trim() | Should -Be '[]'
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'object-insights.json') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'object-index.csv') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'security-observations.csv') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-summary.md') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'object-insights-full.json') | Should -BeFalse

            $finalManifest = Get-Content -LiteralPath $result.ManifestPath -Raw | ConvertFrom-Json
            foreach ($artifact in @($finalManifest.Artifacts)) {
                $artifactPath = Join-Path $result.ExportDirectory $artifact.Name
                Test-Path -LiteralPath $artifactPath -PathType Leaf | Should -BeTrue
                $artifact.SizeBytes | Should -Be (Get-Item -LiteralPath $artifactPath).Length
            }

            $evidenceIndex = @(Get-Content -LiteralPath (Join-Path $result.ExportDirectory 'evidence-index.json') -Raw | ConvertFrom-Json)
            $advisoryEvidence = @($evidenceIndex | Where-Object QueryName -eq 'DiscoverApplications')[0]
            $advisoryEvidence.PSObject.Properties.Name | Should -Contain 'RequiredForCoverage'
            $advisoryEvidence.RequiredForCoverage | Should -BeFalse
        }

        It 'hydrates Markdown artifact inventory from the finalized manifest' {
            $tenant = New-TestTenantResult

            $result =
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Markdown Hydration' `
                    -ExportDirectoryName 'markdown-hydration' `
                    -Force

            $markdown = Get-Content -LiteralPath (Join-Path $result.ExportDirectory 'assessment-summary.md') -Raw
            $markdown | Should -Match 'assessment-manifest\.json'
            $markdown | Should -Match 'assessment-summary\.md'
            $markdown | Should -Not -Match 'None \\| None \\| 0 \\| No artifact records supplied'
        }

        It 'exports compact object insights and de-duplicates repeated evidence by identifier' {
            $tenant = New-TestTenantResult
            $firstInsight = @($tenant.ObjectInsights)[0]
            $secondInsight = $firstInsight.PSObject.Copy()
            $secondInsight.Input = 'sp-2'
            $tenant.ObjectInsights = @($firstInsight, $secondInsight)
            $tenant.Summary.ObjectInsightCount = 2

            $model =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant

            $model.ObjectInsights.Count | Should -Be 2
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Contain 'EvidenceCount'
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Contain 'DirectEvidenceCount'
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Contain 'FindingEligibleObservationCount'
            $model.ObjectInsights[0].EvidenceCount | Should -Be $model.ObjectInsights[0].DirectEvidenceCount
            $model.ObjectInsights[0].FindingCount | Should -Be $model.ObjectInsights[0].FindingEligibleObservationCount
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Contain 'EvidenceSampleIds'
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Contain 'EvidenceTruncated'
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Contain 'Limitations'
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Not -Contain 'EvidenceIds'
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Not -Contain 'Evidence'
            $model.ObjectInsights[0].PSObject.Properties.Name | Should -Not -Contain 'RelationshipCollection'
            @($model.EvidenceRows | Where-Object EvidenceId -eq 'ev-1').Count | Should -Be 1
            $model.Summary.EvidenceRecordCount | Should -Be @($model.EvidenceRows).Count

            # Exercise the optimized current-snapshot path without adding a
            # separate test-case count. Snapshot resolutions carry the complete
            # tenant evidence corpus on each ObjectInsight; export must map only
            # the subject evidence to each object while flattening the global
            # evidence corpus exactly once.
            $tenant | Add-Member -NotePropertyName SnapshotMode -NotePropertyValue 'InMemory' -Force

            $tenantEvidence = @(
                [PSCustomObject]@{
                    EvidenceId = 'ev-1'
                    QueryName = 'SpOneRelationship'
                    Endpoint = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-1/memberOf'
                    RequiredPermission = 'Application.Read.All'
                    CollectionTime = '2026-08-30T10:00:00Z'
                    Status = 'Success'
                    Completeness = 'Complete'
                    EvidenceScope = 'ObjectRelationship'
                    SubjectObjectType = 'ServicePrincipal'
                    SubjectObjectId = 'sp-1'
                    Limitations = @()
                },
                [PSCustomObject]@{
                    EvidenceId = 'ev-2'
                    QueryName = 'SpTwoRelationship'
                    Endpoint = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-2/memberOf'
                    RequiredPermission = 'Application.Read.All'
                    CollectionTime = '2026-08-30T10:00:01Z'
                    Status = 'Success'
                    Completeness = 'Complete'
                    EvidenceScope = 'ObjectRelationship'
                    SubjectObjectType = 'ServicePrincipal'
                    SubjectObjectId = 'sp-2'
                    Limitations = @()
                },
                [PSCustomObject]@{
                    EvidenceId = 'ev-discovery'
                    QueryName = 'DiscoverApplications'
                    Endpoint = 'https://graph.microsoft.com/v1.0/applications'
                    RequiredPermission = 'Application.Read.All'
                    CollectionTime = '2026-08-30T10:00:00Z'
                    Status = 'Success'
                    Completeness = 'Complete'
                    EvidenceScope = 'TenantCollection'
                    Limitations = @()
                }
            )

            $firstInsight | Add-Member -NotePropertyName DiscoveryObject -NotePropertyValue ([PSCustomObject]@{
                ObjectType = 'ServicePrincipal'
                ObjectId = 'sp-1'
                DisplayName = 'SP One'
            }) -Force
            $firstInsight.Evidence = @($tenantEvidence)
            $firstInsight.RelationshipCollection = [PSCustomObject]@{
                Status = 'Success'
                Completeness = 'Complete'
                Evidence = @($tenantEvidence[0])
            }

            $secondInsight | Add-Member -NotePropertyName DiscoveryObject -NotePropertyValue ([PSCustomObject]@{
                ObjectType = 'ServicePrincipal'
                ObjectId = 'sp-2'
                DisplayName = 'SP Two'
            }) -Force
            $secondInsight.Evidence = @($tenantEvidence)
            $secondInsight.RelationshipCollection = [PSCustomObject]@{
                Status = 'Success'
                Completeness = 'Complete'
                Evidence = @($tenantEvidence[1])
            }
            $secondInsight.SecurityObservations = @()

            $tenant.Discovery.Evidence = @($tenantEvidence)
            $tenant.ObjectInsights = @($firstInsight, $secondInsight)

            $snapshotModel = ConvertTo-InspectorAssessmentExport -InputObject $tenant
            $sp1Row = @($snapshotModel.ObjectInsights | Where-Object Input -eq 'sp-1')[0]
            $sp2Row = @($snapshotModel.ObjectInsights | Where-Object Input -eq 'sp-2')[0]

            @($snapshotModel.EvidenceRows).Count | Should -Be 3
            (@($snapshotModel.EvidenceRows | Select-Object -ExpandProperty EvidenceId) -join ',') | Should -Be 'ev-1,ev-2,ev-discovery'
            @($snapshotModel.EvidenceRows | Where-Object ParentInput -ne 'sp-1').Count | Should -Be 0
            $sp1Row.EvidenceCount | Should -Be 1
            $sp1Row.EvidenceSampleIds | Should -Be 'ev-1'
            $sp2Row.EvidenceCount | Should -Be 1
            $sp2Row.EvidenceSampleIds | Should -Be 'ev-2'

            # Force the compatibility traversal over the same in-memory data and
            # require the optimized path to remain serialization-equivalent for
            # the two export surfaces it replaces.
            $tenant.SnapshotMode = 'Compatibility'
            $compatibilityModel = ConvertTo-InspectorAssessmentExport -InputObject $tenant

            (@($snapshotModel.ObjectInsights) | ConvertTo-Json -Depth 20 -Compress) |
                Should -Be (@($compatibilityModel.ObjectInsights) | ConvertTo-Json -Depth 20 -Compress)
            (@($snapshotModel.EvidenceRows) | ConvertTo-Json -Depth 20 -Compress) |
                Should -Be (@($compatibilityModel.EvidenceRows) | ConvertTo-Json -Depth 20 -Compress)
        }

        It 'caps object-index evidence identifiers to a compact sample' {
            $tenant = New-TestTenantResult
            $tenant.ObjectInsights[0].Evidence =
                1..12 |
                ForEach-Object {
                    [PSCustomObject]@{
                        EvidenceId = "ev-$_"
                        QueryName = 'SyntheticQuery'
                        Status = 'Success'
                    }
                }

            $model = ConvertTo-InspectorAssessmentExport -InputObject $tenant
            $row = $model.ObjectInsights[0]

            $row.DirectEvidenceCount | Should -Be 1
            $row.EvidenceTruncated | Should -BeFalse
            @($row.EvidenceSampleIds -split '; ').Count | Should -Be 1
            $row.EvidenceSampleIds | Should -Not -Match 'ev-11'
        }

        It 'exports full object insights only when explicitly requested' {
            $tenant = New-TestTenantResult

            $defaultModel =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant

            $fullModel =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant `
                    -IncludeFullObjectInsights

            @($defaultModel.FullObjectInsights).Count | Should -Be 0
            @($fullModel.FullObjectInsights).Count | Should -Be 1
            $fullModel.FullObjectInsights[0].PSObject.Properties.Name | Should -Contain 'RelationshipCollection'

            $result =
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Full Object Insight Export' `
                    -ExportDirectoryName 'full-object-insight-export' `
                    -IncludeFullObjectInsights `
                    -Force

            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'object-insights-full.json') | Should -BeTrue
        }

        It 'does not use depth 80 for default compact high-volume export artifacts' {
            $exportCommand = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Public\Export-EntraTenantInspection.ps1') -Raw
            $exportCommon = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Private\Export\Export.Common.ps1') -Raw

            $exportCommon | Should -Not -Match '\[int\]\$Depth = 80'
            $exportCommand | Should -Not -Match 'Write-InspectorJsonFile -Path \$objectInsightsPath -Value \$exportModel\.ObjectInsights -Depth 80'
            $exportCommand | Should -Not -Match 'Write-InspectorJsonFile -Path \$evidencePath -Value \$exportModel\.EvidenceRows -Depth 80'
            $exportCommand | Should -Match 'Write-InspectorJsonFile -Path \$fullObjectInsightsPath -Value \$exportModel\.FullObjectInsights -Depth 80'
        }

        It 'supports pipeline input' {
            $tenant = New-TestTenantResult

            $result =
                $tenant |
                Export-EntraTenantInspection `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Pipeline Export' `
                    -ExportDirectoryName 'pipeline-export' `
                    -Force

            $result.Status | Should -Be 'Success'
            Test-Path -LiteralPath $result.ManifestPath | Should -BeTrue
        }

        It 'supports JSON-only export when CSV and Markdown are disabled' {
            $tenant = New-TestTenantResult

            $result =
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Json Only' `
                    -ExportDirectoryName 'json-only' `
                    -NoCsv `
                    -NoMarkdown `
                    -Force

            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-manifest.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'security-observations.csv') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-summary.md') | Should -BeFalse
        }

        It 'prevents accidental overwrite unless Force is used' {
            $tenant = New-TestTenantResult

            Export-EntraTenantInspection `
                -InputObject $tenant `
                -OutputDirectory $TestDrive `
                -AssessmentName 'Overwrite Test' `
                -ExportDirectoryName 'same-folder' |
                Out-Null

            {
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Overwrite Test' `
                    -ExportDirectoryName 'same-folder'
            } | Should -Throw
        }

        It 'exports failed object rows when present' {
            $tenant =
                New-TestTenantResult `
                    -FailedObjects @(
                        [PSCustomObject]@{
                            ObjectKey = 'Application:app-1'
                            ObjectType = 'Application'
                            ObjectId = 'app-1'
                            InspectionIdentity = 'app-1'
                            Attempts = 3
                            Error = 'Synthetic failure'
                        }
                    )

            $model =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant

            $model.FailedObjectRows.Count | Should -Be 1
            $model.FailedObjectRows[0].Error | Should -Be 'Synthetic failure'
        }
    }
}
