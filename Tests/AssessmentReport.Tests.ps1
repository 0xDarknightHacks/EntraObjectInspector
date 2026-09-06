$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'HTML assessment report generator' {

    InModuleScope EntraObjectInspector {

        BeforeAll {
            function New-TestObservation {
                param (
                    [string]$ObservationId = 'OBS-1',
                    [string]$Category = 'Permissions',
                    [string]$Title = 'High-impact permission: Directory.ReadWrite.All',
                    [string]$Severity = 'High'
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.SecurityObservation'
                    SchemaVersion = '0.7.0'
                    ObservationId = $ObservationId
                    Category = $Category
                    Title = $Title
                    Description = 'Observation description'
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
                    SourceRuleIds = @()
                    Metadata = [PSCustomObject]@{}
                }
            }

            function New-TestIntelligence {
                param (
                    [object[]]$Observations = @((New-TestObservation))
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.AssessmentIntelligence'
                    SchemaVersion = '0.9.0'
                    AssessmentName = 'Unit Test Intelligence'
                    Status = 'Success'
                    GraphCallsIssued = 0
                    RiskScoreProduced = $false
                    ExposureScoreProduced = $false
                    AttackPathsProduced = $false
                    TenantPosture = [PSCustomObject]@{
                        Label = 'AttentionRequired'
                        HighestSeverity = 'High'
                        Confidence = 'High'
                        ObservationCount = @($Observations).Count
                        FindingCount = 1
                        RecommendationCount = 1
                        CorrelationCount = 1
                    }
                    AssessmentFindings = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.AssessmentFinding'
                            FindingId = 'FINDING-1'
                            Category = 'PermissionExposure'
                            Title = 'High-impact Microsoft Graph permission exposure detected'
                            Conclusion = 'Permission observations indicate high-impact permissions.'
                            Severity = 'High'
                            Confidence = 'High'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            MicrosoftReference = 'Microsoft reference'
                            Recommendation = 'Review high-impact permissions.'
                            Limitations = @()
                        }
                    )
                    AssessmentRecommendations = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.AssessmentRecommendation'
                            RecommendationId = 'REC-1'
                            Category = 'PermissionExposure'
                            Title = 'Review high-impact application permissions'
                            Action = 'Validate necessity and least privilege.'
                            Rationale = 'Application permissions can allow app-only access.'
                            Confidence = 'High'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            MicrosoftReference = 'Microsoft reference'
                            Limitations = @()
                        }
                    )
                    Correlations = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.AssessmentCorrelation'
                            CorrelationId = 'CORR-1'
                            CorrelationType = 'PermissionConsentCoOccurrence'
                            Title = 'High-impact permissions co-occur with consent observations'
                            Description = 'Co-occurrence signal only.'
                            Confidence = 'High'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            Limitations = @('Not an attack path.')
                        }
                    )
                    Limitations = @('Intelligence limitation')
                }
            }

            function New-TestTenantResult {
                param (
                    [object[]]$Observations = @((New-TestObservation)),
                    [object]$Intelligence = $null
                )

                $tenant = [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                    SchemaVersion = '0.10.0'
                    Status = 'Success'
                    GraphRequestsAtSnapshotCompletion = 0
                    GraphRequestsAtAssessmentCompletion = 0
                    GraphCallsAfterSnapshot = 0
                    ObjectInsights = @(
                        [PSCustomObject]@{
                            Input = 'sp-1'
                            Status = 'Resolved'
                            ResolutionType = 'ApplicationIdentity'
                            RelationshipCollection = [PSCustomObject]@{
                                Status = 'Success'
                                Completeness = 'Complete'
                                Evidence = @()
                            }
                            SecurityObservations = @($Observations)
                            Evidence = @(
                                [PSCustomObject]@{
                                    EvidenceId = 'ev-1'
                                    QueryName = 'SyntheticQuery'
                                    RequiredPermission = 'Application.Read.All'
                                    Status = 'Success'
                                }
                            )
                        }
                    )
                    SecurityObservations = @($Observations)
                    FailedObjects = @()
                    Summary = [PSCustomObject]@{
                        ObjectInsightCount = 1
                        SecurityObservationCount = @($Observations).Count
                    }
                }

                if ($null -ne $Intelligence) {
                    $tenant |
                        Add-Member `
                            -NotePropertyName 'AssessmentIntelligence' `
                            -NotePropertyValue $Intelligence `
                            -Force
                }

                return $tenant
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                throw 'Report generation must not call Graph.'
            }
        }

        It 'converts in-memory tenant result and intelligence into a report model without Graph calls' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence

            $model =
                ConvertTo-InspectorReportModel `
                    -InputObject $tenant `
                    -AssessmentName 'Report Model Test'

            $model.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.AssessmentReportModel'
            $model.SchemaVersion | Should -Be '0.12.0'
            $model.GraphCallsIssued | Should -Be 0
            $model.RiskScoreProduced | Should -BeFalse
            $model.AttackPathsProduced | Should -BeFalse
            $model.AssessmentFindings.Count | Should -Be 1
            $model.AssessmentRecommendations.Count | Should -Be 1
            $model.AssessmentCorrelations.Count | Should -Be 1

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'fails package validation when failed-object counts diverge' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                FailedCount = 0
                RawObservationCount = 1
                DeduplicatedObservationCount = 1
                DuplicateObservationCount = 0
                CategorySummary = @([PSCustomObject]@{ Category = 'Permissions'; Count = 1 })
                SeveritySummary = @([PSCustomObject]@{ Severity = 'High'; Count = 1 })
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
            }

            $manifest = [PSCustomObject]@{
                SourceStatus = 'Success'
                FailedObjectCount = 1
                EvidenceRecordCount = 1
                GroupedFindingCount = 0
                Artifacts = @(
                    [PSCustomObject]@{ Name = 'failed-objects.json'; RecordCount = 0 }
                    [PSCustomObject]@{ Name = 'failed-objects.csv'; RecordCount = 0 }
                )
            }

            $result =
                Test-InspectorReportPackageConsistency `
                    -Summary $summary `
                    -SecurityObservations @((New-TestObservation)) `
                    -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) `
                    -AssessmentFindings @() `
                    -FailedObjects @() `
                    -Manifest $manifest

            $result.Status | Should -Be 'Failed'
            $result.Errors.ErrorId | Should -Contain 'PKG-COUNT-FAILEDOBJECT-001'
            $result.Errors.Message | Should -Contain 'Failed object count differs across assessment package artifacts.'
        }

        It 'passes package validation when failed-object counts reconcile to zero' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                FailedCount = 0
                RawObservationCount = 1
                DeduplicatedObservationCount = 1
                DuplicateObservationCount = 0
                CategorySummary = @([PSCustomObject]@{ Category = 'Permissions'; Count = 1 })
                SeveritySummary = @([PSCustomObject]@{ Severity = 'High'; Count = 1 })
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
            }

            $manifest = [PSCustomObject]@{
                SourceStatus = 'Success'
                FailedObjectCount = 0
                EvidenceRecordCount = 1
                GroupedFindingCount = 0
                Artifacts = @(
                    [PSCustomObject]@{ Name = 'failed-objects.json'; RecordCount = 0 }
                    [PSCustomObject]@{ Name = 'failed-objects.csv'; RecordCount = 0 }
                )
            }

            $packagePath = Join-Path $TestDrive 'package-validation-files'
            New-Item -ItemType Directory -Path $packagePath -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $packagePath 'failed-objects.json') -Value '[]' -Encoding utf8
            Set-Content -LiteralPath (Join-Path $packagePath 'failed-objects.csv') -Value '' -Encoding utf8

            $result =
                Test-InspectorReportPackageConsistency `
                    -Summary $summary `
                    -SecurityObservations @((New-TestObservation)) `
                    -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) `
                    -AssessmentFindings @() `
                    -FailedObjects @() `
                    -Manifest $manifest `
                    -SourcePath $packagePath

            $result.Status | Should -Be 'Success'
            $result.ReleaseEligible | Should -BeTrue

            $summary.ScopeInventory = [PSCustomObject]@{
                FailedObjects = 0
                CollectionCompleteness = 'Partial'
                TruncatedCollections = @('Applications')
            }
            $boundedPackage = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest -SourcePath $packagePath
            $boundedPackage.Status | Should -Be 'Failed'
            $boundedPackage.ReleaseEligible | Should -BeFalse
            $boundedPackage.Errors.ErrorId | Should -Contain 'PKG-SCOPE-INCOMPLETE-001'
            $summary.ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }

            Remove-Item -LiteralPath (Join-Path $packagePath 'failed-objects.json') -Force
            $missingArtifact = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest -SourcePath $packagePath
            $missingArtifact.Status | Should -Be 'Failed'
            $missingArtifact.ReleaseEligible | Should -BeFalse
            $missingArtifact.Errors.ErrorId | Should -Contain 'PKG-ARTIFACT-MISSING-001'

            Set-Content -LiteralPath (Join-Path $packagePath 'failed-objects.json') -Value '[]' -Encoding utf8

            $physicalArtifactPath = Join-Path $packagePath 'physical-records.json'
            Set-Content -LiteralPath $physicalArtifactPath -Value '[{"id":1},{"id":2}]' -Encoding utf8
            $physicalArtifact = [PSCustomObject]@{
                Name = 'physical-records.json'
                Kind = 'json'
                RecordCount = 2
                SizeBytes = (Get-Item -LiteralPath $physicalArtifactPath).Length
            }
            $manifest.Artifacts = @($manifest.Artifacts) + $physicalArtifact
            $physicalValid = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest -SourcePath $packagePath
            $physicalValid.Status | Should -Be 'Success'

            $physicalArtifact.SizeBytes++
            $sizeMismatch = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest -SourcePath $packagePath
            @($sizeMismatch.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-ARTIFACT-SIZE-001'
            $physicalArtifact.SizeBytes = (Get-Item -LiteralPath $physicalArtifactPath).Length

            $physicalArtifact.RecordCount = 3
            $recordCountMismatch = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest -SourcePath $packagePath
            @($recordCountMismatch.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-ARTIFACT-RECORDCOUNT-001'
            $physicalArtifact.RecordCount = 2

            $summary.Status = ''
            $manifest.SourceStatus = ''
            $missingSourceStatus = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest -SourcePath $packagePath
            $missingSourceStatus.Status | Should -Be 'Failed'
            $missingSourceStatus.ReleaseEligible | Should -BeFalse
            $missingSourceStatus.Errors.ErrorId | Should -Contain 'PKG-SOURCE-STATUS-001'
        }

        It 'requires assessment evidence to be Success and Complete for release eligibility' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                FailedCount = 0
                RawObservationCount = 1
                DeduplicatedObservationCount = 1
                DuplicateObservationCount = 0
                CategorySummary = @([PSCustomObject]@{ Category = 'Permissions'; Count = 1 })
                SeveritySummary = @([PSCustomObject]@{ Severity = 'High'; Count = 1 })
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; AssessmentCoverageCompleteness = 'Complete'; TruncatedCollections = @() }
                AssessmentCoverage = [PSCustomObject]@{
                    ExpectedQueries = @('ApplicationOwners')
                    ExpectedEvidenceCount = 1
                    ActualRequiredEvidenceCount = 1
                    EvidencePlanMatches = $true
                    Completeness = 'Complete'
                }
            }
            $manifest = [PSCustomObject]@{
                SourceStatus = 'Success'
                FailedObjectCount = 0
                EvidenceRecordCount = 1
                GroupedFindingCount = 0
            }
            $evidenceRows = @([PSCustomObject]@{ EvidenceId = 'ev-1'; QueryName = 'ApplicationOwners'; Status = 'Success'; Completeness = 'Unknown' })

            $result = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows $evidenceRows -AssessmentFindings @() -FailedObjects @() -Manifest $manifest

            $result.Status | Should -Be 'Failed'
            $result.ReleaseEligible | Should -BeFalse
            $result.Errors.ErrorId | Should -Contain 'PKG-EVIDENCE-COVERAGE-001'
        }

        It 'requires current scope completeness to be exactly Complete' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                FailedCount = 0
                RawObservationCount = 1
                DeduplicatedObservationCount = 1
                DuplicateObservationCount = 0
                CategorySummary = @([PSCustomObject]@{ Category = 'Permissions'; Count = 1 })
                SeveritySummary = @([PSCustomObject]@{ Severity = 'High'; Count = 1 })
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
            }
            $manifest = [PSCustomObject]@{ SourceStatus = 'Success'; FailedObjectCount = 0; EvidenceRecordCount = 1; GroupedFindingCount = 0 }

            $complete = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest
            $summary.ScopeInventory.CollectionCompleteness = 'Unknown'
            $unknown = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest
            $summary.ScopeInventory.CollectionCompleteness = ''
            $empty = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest
            $summary.ScopeInventory.PSObject.Properties.Remove('CollectionCompleteness')
            $missingProperty = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest

            $complete.Status | Should -Be 'Success'
            $complete.ReleaseEligible | Should -BeTrue
            $unknown.Status | Should -Be 'Failed'
            $unknown.ReleaseEligible | Should -BeFalse
            $empty.Status | Should -Be 'Failed'
            $empty.ReleaseEligible | Should -BeFalse
            $missingProperty.Status | Should -Be 'Failed'
            $missingProperty.ReleaseEligible | Should -BeFalse
            @($unknown.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-SCOPE-INCOMPLETE-001'
            @($empty.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-SCOPE-INCOMPLETE-001'
            @($missingProperty.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-SCOPE-INCOMPLETE-001'
        }

        It 'fails release validation when post-snapshot Graph activity is measured' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                FailedCount = 0
                RawObservationCount = 1
                DeduplicatedObservationCount = 1
                DuplicateObservationCount = 0
                CategorySummary = @([PSCustomObject]@{ Category = 'Permissions'; Count = 1 })
                SeveritySummary = @([PSCustomObject]@{ Severity = 'High'; Count = 1 })
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
                GraphCallsAfterSnapshot = 1
                PackageValidationStatus = 'NotRun'
                ReleaseEligible = $false
            }
            $manifest = [PSCustomObject]@{ SourceStatus = 'Success'; FailedObjectCount = 0; EvidenceRecordCount = 1; GroupedFindingCount = 0; GraphCallsAfterSnapshot = 1; PackageValidationStatus = 'NotRun'; ReleaseEligible = $false }

            $result = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest
            $summary.PSObject.Properties.Remove('GraphCallsAfterSnapshot')
            $manifest.PSObject.Properties.Remove('GraphCallsAfterSnapshot')
            $missing = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest
            $summary | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue 'not-a-number' -Force
            $manifest | Add-Member -NotePropertyName GraphCallsAfterSnapshot -NotePropertyValue 0 -Force
            $nonNumeric = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @((New-TestObservation)) -EvidenceRows @([PSCustomObject]@{ EvidenceId = 'ev-1' }) -AssessmentFindings @() -FailedObjects @() -Manifest $manifest

            $result.Status | Should -Be 'Failed'
            $result.ReleaseEligible | Should -BeFalse
            @($result.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-GRAPH-POSTSNAPSHOT-001'
            $missing.ReleaseEligible | Should -BeFalse
            $nonNumeric.ReleaseEligible | Should -BeFalse
            @($missing.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-GRAPH-PROVENANCE-001'
            @($nonNumeric.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-GRAPH-PROVENANCE-001'
        }

        It 'requires finding evidence to exactly match contributing observation evidence' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                FailedCount = 0
                RawObservationCount = 1
                DeduplicatedObservationCount = 1
                DuplicateObservationCount = 0
                CategorySummary = @([PSCustomObject]@{ Category = 'Permissions'; Count = 1 })
                SeveritySummary = @([PSCustomObject]@{ Severity = 'High'; Count = 1 })
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
            }
            $manifest = [PSCustomObject]@{ SourceStatus = 'Success'; FailedObjectCount = 0; EvidenceRecordCount = 2; GroupedFindingCount = 1 }
            $observation = New-TestObservation
            $observation | Add-Member -NotePropertyName FindingEligible -NotePropertyValue $true -Force
            $evidenceRows = @(
                [PSCustomObject]@{ EvidenceId = 'ev-1' }
                [PSCustomObject]@{ EvidenceId = 'ev-extra' }
            )
            $validFinding = [PSCustomObject]@{
                FindingId = 'FINDING-1'
                ObservationIds = @('OBS-1')
                EvidenceIds = @('ev-1')
                AffectedObjects = @([PSCustomObject]@{ ObjectType = 'ServicePrincipal'; ObjectId = 'sp-1' })
                AffectedObjectCount = 1
            }
            $missingFinding = $validFinding.PSObject.Copy()
            $missingFinding.EvidenceIds = @()
            $extraFinding = $validFinding.PSObject.Copy()
            $extraFinding.EvidenceIds = @('ev-1','ev-extra')

            $valid = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @($observation) -EvidenceRows $evidenceRows -AssessmentFindings @($validFinding) -FailedObjects @() -Manifest $manifest
            $missing = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @($observation) -EvidenceRows $evidenceRows -AssessmentFindings @($missingFinding) -FailedObjects @() -Manifest $manifest
            $extra = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @($observation) -EvidenceRows $evidenceRows -AssessmentFindings @($extraFinding) -FailedObjects @() -Manifest $manifest

            @($valid.Errors | ForEach-Object { $_.ErrorId }) | Should -Not -Contain 'PKG-FINDING-EVIDENCE-RECONCILIATION-001'
            @($missing.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-FINDING-EVIDENCE-RECONCILIATION-001'
            @($extra.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-FINDING-EVIDENCE-RECONCILIATION-001'
        }

        It 'renders a self-contained HTML document with required sections' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence
            $model = ConvertTo-InspectorReportModel -InputObject $tenant -AssessmentName 'HTML Test'

            $html =
                New-InspectorHtmlReport `
                    -ReportModel $model

            $html | Should -Match '<!doctype html>'
            $html | Should -Match '<style>'
            $html | Should -Match 'Client / Tenant Details'
            $html | Should -Match 'Executive Summary'
            $html | Should -Match 'Summary Metrics'
            $html | Should -Match 'Grouped Findings'
            $html | Should -Match 'Assessment Signals by Category'
            $html | Should -Not -Match 'Runtime Telemetry'
            $html | Should -Not -Match 'Top Actions / Recommended Next Actions'
            $html | Should -Not -Match 'Boundaries &amp; Trust'
            $html | Should -Not -Match 'Evidence References'
            $html | Should -Not -Match 'Assessment Limitations'
        }

        It 'shows a fail-closed package validation banner in the main report' {
            $tenant = New-TestTenantResult -Observations @((New-TestObservation)) -Intelligence (New-TestIntelligence)
            $model = ConvertTo-InspectorReportModel -InputObject $tenant -AssessmentName 'Failed Validation Report'
            $model.PackageValidationStatus = 'Failed'
            $model.DiagnosticsReportFileName = 'client-entra-assessment-diagnostics.html'

            $html = New-InspectorHtmlReport -ReportModel $model

            $html | Should -Match 'ASSESSMENT PACKAGE VALIDATION FAILED'
            $html | Should -Match 'Package validation: Failed'
            $html | Should -Match 'client-entra-assessment-diagnostics.html'
        }

        It 'exports a report from in-memory objects' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations

            $result =
                Export-EntraAssessmentReport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -AssessmentName 'Report Export Test' `
                    -OutputPath (Join-Path $TestDrive 'report.html') `
                    -Force

            $result.PSObject.TypeNames[0] | Should -Be 'EntraObjectInspector.AssessmentReportResult'
            $result.Status | Should -Be 'Success'
            $result.GraphCallsIssued | Should -Be 0
            $result.IntelligenceAdded | Should -BeFalse
            $result.RiskScoreProduced | Should -BeFalse
            $result.SelfContainedHtml | Should -BeTrue
            $result.PerformanceProfile | Should -Not -BeNullOrEmpty
            ($result.PerformanceProfile.TotalDurationMs -ge 0) | Should -BeTrue
            ($result.PerformanceProfile.HtmlRenderDurationMs -ge 0) | Should -BeTrue
            Test-Path -LiteralPath $result.ReportPath | Should -BeTrue
            Test-Path -LiteralPath $result.DiagnosticsReportPath | Should -BeTrue
            Test-Path -LiteralPath $result.EvidenceReportPath | Should -BeTrue
            (Get-Content -LiteralPath $result.ReportPath -Raw) | Should -Match 'Report Export Test'
            (Get-Content -LiteralPath $result.EvidenceReportPath -Raw) | Should -Match 'ev-1'
            (Get-Content -LiteralPath $result.EvidenceReportPath -Raw) | Should -Match 'SyntheticQuery'
        }

        It 'exports a report from an assessment export directory' {
            $exportDir =
                Join-Path $TestDrive 'exported-assessment'

            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations

            $manifest = [PSCustomObject]@{
                SchemaVersion = '0.10.0'
                AssessmentName = 'Export Directory Test'
                SourceStatus = 'Success'
                GraphCallsIssued = 0
                GraphRequestsAtSnapshotCompletion = 0
                GraphRequestsAtAssessmentCompletion = 0
                GraphCallsAfterSnapshot = 0
                IntelligenceAdded = $false
                PackageValidationStatus = 'NotRun'
                ReleaseEligible = $false
                Artifacts = @(
                    [PSCustomObject]@{ Name = 'assessment-manifest.json'; Kind = 'json'; Path = 'stale'; RecordCount = 1; SizeBytes = 1 },
                    [PSCustomObject]@{ Name = 'assessment-summary.json'; Kind = 'json'; Path = 'stale'; RecordCount = 1; SizeBytes = 1 },
                    [PSCustomObject]@{ Name = 'assessment-summary.md'; Kind = 'markdown'; Path = 'stale'; RecordCount = 1; SizeBytes = 1 }
                )
            }

            $coverage = [PSCustomObject]@{
                Status = 'Success'
                Completeness = 'Complete'
                EvidencePlanMatches = $true
                ExpectedEvidenceCount = 1
                ActualRequiredEvidenceCount = 1
                RequiredEvidenceCount = 1
                SuccessfulRequiredEvidenceCount = 1
                IncompleteRequiredEvidenceCount = 0
                MissingExpectedEvidenceCount = 0
                UnexpectedRequiredEvidenceCount = 0
                DuplicateRequiredEvidenceCount = 0
                ExpectedQueries = @('SyntheticQuery')
                IncompleteQueryDetails = @()
            }
            $manifest | Add-Member -NotePropertyName AssessmentCoverage -NotePropertyValue $coverage -Force
            $manifest | Add-Member -NotePropertyName ScopeInventory -NotePropertyValue ([PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; AssessmentCoverageCompleteness = 'Complete'; TruncatedCollections = @() }) -Force

            $summary = [PSCustomObject]@{
                Status = 'Success'
                ObjectInsightCount = 1
                SecurityObservationCount = 1
                AssessmentCoverage = $coverage
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; AssessmentCoverageCompleteness = 'Complete'; TruncatedCollections = @() }
                GraphRequestsAtSnapshotCompletion = 0
                GraphRequestsAtAssessmentCompletion = 0
                GraphCallsAfterSnapshot = 0
                PackageValidationStatus = 'NotRun'
                ReleaseEligible = $false
            }

            $objectIndex = @(
                [PSCustomObject]@{
                    Input = 'sp-1'
                    Status = 'Resolved'
                    ResolutionType = 'ApplicationIdentity'
                    RelationshipStatus = 'Success'
                    RelationshipCompleteness = 'Complete'
                    SecurityObservationCount = 1
                }
            )

            $evidence = @(
                [PSCustomObject]@{
                    ParentInput = 'sp-1'
                    ParentResolutionType = 'ApplicationIdentity'
                    EvidenceId = 'ev-1'
                    QueryName = 'SyntheticQuery'
                    RequiredPermission = 'Application.Read.All'
                    Status = 'Success'
                    Completeness = 'Complete'
                }
            )

            $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-manifest.json')
            $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-summary.json')
            $observations | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $exportDir 'security-observations.json')
            $objectIndex | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $exportDir 'object-index.json')
            $evidence | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $exportDir 'evidence-index.json')
            @() | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $exportDir 'failed-objects.json')
            $intelligence | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-intelligence.json')
            $intelligence.TenantPosture | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $exportDir 'tenant-posture.json')
            $intelligence.AssessmentFindings | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-findings.json')
            $intelligence.AssessmentRecommendations | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-recommendations.json')
            $intelligence.Correlations | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-correlations.json')
            @($intelligence.Limitations | ForEach-Object { [PSCustomObject]@{ Limitation = [string]$_ } }) | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-limitations.json')
            '# Pre-existing structured-export Markdown summary' | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-summary.md') -Encoding UTF8

            for ($artifactRefreshPass = 0; $artifactRefreshPass -lt 3; $artifactRefreshPass++) {
                Update-InspectorExportArtifactSizes -Manifest $manifest -BasePath $exportDir
                $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $exportDir 'assessment-manifest.json')
            }

            $result =
                Export-EntraAssessmentReport `
                    -ExportDirectory $exportDir `
                    -AssessmentName 'Directory Report' `
                    -OutputPath (Join-Path $TestDrive 'directory-report.html') `
                    -Force

            $result.Status | Should -Be 'Success'
            $result.SourceKind | Should -Be 'ExportDirectory'
            Test-Path -LiteralPath $result.ReportPath | Should -BeTrue
            Test-Path -LiteralPath $result.DiagnosticsReportPath | Should -BeTrue
            Test-Path -LiteralPath $result.EvidenceReportPath | Should -BeTrue
            (Get-Content -LiteralPath $result.ReportPath -Raw) | Should -Match 'Directory Report'

            $refreshedMarkdown = Get-Content -LiteralPath (Join-Path $exportDir 'assessment-summary.md') -Raw
            $refreshedMarkdown | Should -Match '## Assessment Findings'
            $refreshedMarkdown | Should -Match 'High-impact Microsoft Graph permission exposure detected'
            $refreshedMarkdown | Should -Match '## Assessment Recommendations'
            $refreshedMarkdown | Should -Match 'Review high-impact application permissions'
            $refreshedMarkdown | Should -Not -Match '@\{Limitation='

            $refreshedManifest = Get-Content -LiteralPath (Join-Path $exportDir 'assessment-manifest.json') -Raw | ConvertFrom-Json
            $summaryArtifact = @($refreshedManifest.Artifacts | Where-Object Name -eq 'assessment-summary.json')[0]
            $markdownArtifact = @($refreshedManifest.Artifacts | Where-Object Name -eq 'assessment-summary.md')[0]
            $summaryArtifact.SizeBytes | Should -Be (Get-Item -LiteralPath (Join-Path $exportDir 'assessment-summary.json')).Length
            $markdownArtifact.SizeBytes | Should -Be (Get-Item -LiteralPath (Join-Path $exportDir 'assessment-summary.md')).Length

            $diagnosticsHtml = Get-Content -LiteralPath $result.DiagnosticsReportPath -Raw
            $diagnosticsHtml | Should -Match 'Assessment Coverage'
            $diagnosticsHtml | Should -Match 'Expected required evidence'
            $diagnosticsHtml | Should -Match 'No missing, unexpected, duplicate, or incomplete required evidence queries.'

            $refreshedIntelligence = Get-Content -LiteralPath (Join-Path $exportDir 'assessment-intelligence.json') -Raw | ConvertFrom-Json
            $refreshedPosture = Get-Content -LiteralPath (Join-Path $exportDir 'tenant-posture.json') -Raw | ConvertFrom-Json
            foreach ($packageArtifact in @($refreshedIntelligence, $refreshedPosture)) {
                $packageArtifact.RunId | Should -Be $result.RunId
                $packageArtifact.ReportId | Should -Be $result.ReportId
                $packageArtifact.PackageValidationStatus | Should -Be $result.PackageValidationStatus
                $packageArtifact.ReleaseEligible | Should -Be $result.ReleaseEligible
                $packageArtifact.FailedObjectCount | Should -Be 0
            }
        }

        It 'links partial main report state to diagnostics sidecar with failed object detail' {
            $observations = @((New-TestObservation))
            $intelligence = New-TestIntelligence -Observations $observations
            $tenant = New-TestTenantResult -Observations $observations -Intelligence $intelligence
            $tenant.Status = 'Partial'
            $tenant.FailedObjects = @(
                [PSCustomObject]@{
                    ObjectKey = 'User:user-1'
                    ObjectType = 'User'
                    ObjectId = 'user-1'
                    InspectionIdentity = 'user1@contoso.com'
                    Attempts = 1
                    Error = "The property 'Count' cannot be found on this object."
                }
            )
            $tenant.Summary | Add-Member -NotePropertyName FailedCount -NotePropertyValue 1 -Force

            $result =
                Export-EntraAssessmentReport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -AssessmentName 'Partial Report Test' `
                    -OutputPath (Join-Path $TestDrive 'partial-report.html') `
                    -Force

            $main = Get-Content -LiteralPath $result.ReportPath -Raw
            $diagnostics = Get-Content -LiteralPath $result.DiagnosticsReportPath -Raw

            $main | Should -Match 'Review diagnostics report'
            $main | Should -Match 'partial-report-diagnostics\.html'
            $diagnostics | Should -Match 'Failed Objects'
            $diagnostics | Should -Match 'user1@contoso\.com'
            $diagnostics | Should -Match 'The property &#39;Count&#39; cannot be found on this object\.'
        }

        It 'prevents accidental report overwrite unless Force is used' {
            $tenant = New-TestTenantResult -Intelligence (New-TestIntelligence)
            $path = Join-Path $TestDrive 'overwrite.html'

            Export-EntraAssessmentReport `
                -InputObject $tenant `
                -OutputPath $path |
                Out-Null

            {
                Export-EntraAssessmentReport `
                    -InputObject $tenant `
                    -OutputPath $path
            } | Should -Throw
        }

        It 'renders even when assessment intelligence is absent' {
            $tenant = New-TestTenantResult -Observations @((New-TestObservation))

            $result =
                Export-EntraAssessmentReport `
                    -InputObject $tenant `
                    -AssessmentName 'No Intelligence Report' `
                    -OutputPath (Join-Path $TestDrive 'no-intelligence.html') `
                    -Force

            $result.Status | Should -Be 'Success'
            (Get-Content -LiteralPath $result.ReportPath -Raw) | Should -Match 'No Intelligence Report'
        }
    }
}
