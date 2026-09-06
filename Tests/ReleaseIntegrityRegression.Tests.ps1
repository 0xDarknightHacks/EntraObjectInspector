$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'Final release integrity regressions' {
    InModuleScope EntraObjectInspector {
        BeforeAll {
            function New-ReleaseTestInsight {
                param (
                    [object[]]$SourceObjects = @(),
                    [object[]]$Relationships = @(),
                    [object[]]$Artifacts = @(),
                    [object[]]$Evidence = @(),
                    [object[]]$PermissionInsights = @(),
                    [object[]]$RuleResults = @(),
                    [object]$ApplicationIdentity = $null,
                    [string]$Input = 'app-1'
                )

                [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.ObjectInsight'
                    Input = $Input
                    SourceObjects = @($SourceObjects)
                    Relationships = @($Relationships)
                    Artifacts = @($Artifacts)
                    Evidence = @($Evidence)
                    PermissionInsights = @($PermissionInsights)
                    RuleResults = @($RuleResults)
                    ApplicationIdentity = $ApplicationIdentity
                }
            }
        }

        It 'normalizes native password credential shape into an Inspector credential artifact with provenance properties' {
            $rawCredential = [PSCustomObject]@{
                keyId = 'key-1'
                displayName = 'secret-1'
                startDateTime = (Get-Date).ToUniversalTime().AddDays(-10).ToString('o')
                endDateTime = (Get-Date).ToUniversalTime().AddDays(30).ToString('o')
            }

            $artifact = ConvertTo-InspectorCredentialArtifact -SourceObjectType 'Application' -SourceObjectId 'app-1' -CredentialType 'Password' -Credential $rawCredential

            $artifact.PSObject.Properties.Name | Should -Contain 'EvidenceId'
            $artifact.PSObject.Properties.Name | Should -Contain 'ParentEvidenceId'
            $artifact.EvidenceId | Should -BeNullOrEmpty
            $artifact.ParentEvidenceId | Should -BeNullOrEmpty
            $artifact.KeyId | Should -Be 'key-1'
        }

        It 'rules tolerate a credential artifact that does not define EvidenceId under StrictMode' {
            $artifact = [PSCustomObject]@{
                ArtifactType = 'CredentialMetadata'
                CredentialType = 'Password'
                SourceObjectType = 'Application'
                SourceObjectId = 'app-1'
                KeyId = 'key-1'
                DisplayName = 'secret-1'
                StartDateTime = (Get-Date).ToUniversalTime().AddDays(-10).ToString('o')
                EndDateTime = (Get-Date).ToUniversalTime().AddDays(10).ToString('o')
            }
            $insight = New-ReleaseTestInsight -Artifacts @($artifact)

            { Invoke-InspectorRules -ObjectInsight $insight | Out-Null } | Should -Not -Throw
        }

        It 'observation engine tolerates a credential artifact that does not define EvidenceId under StrictMode' {
            $artifact = [PSCustomObject]@{
                ArtifactType = 'CredentialMetadata'
                CredentialType = 'Password'
                SourceObjectType = 'Application'
                SourceObjectId = 'app-1'
                KeyId = 'key-1'
                DisplayName = 'secret-1'
                StartDateTime = (Get-Date).ToUniversalTime().AddDays(-10).ToString('o')
                EndDateTime = (Get-Date).ToUniversalTime().AddDays(10).ToString('o')
            }
            $insight = New-ReleaseTestInsight -Artifacts @($artifact)

            { Invoke-InspectorObservationEngine -ObjectInsight $insight | Out-Null } | Should -Not -Throw
        }

        It 'candidate normalization always defines EvidenceId even when the raw Graph object does not' {
            $rawApplication = [PSCustomObject]@{
                id = 'app-1'
                appId = 'client-1'
                displayName = 'Application One'
            }

            $candidate = ConvertTo-InspectorSnapshotCandidate -ObjectType 'Application' -RawObject $rawApplication -MatchBasis 'ObjectId'

            $candidate.PSObject.Properties.Name | Should -Contain 'EvidenceId'
            $candidate.EvidenceId | Should -BeNullOrEmpty
        }

        It 'consistent partial package can validate structurally but is never release eligible when failed objects exist' {
            $failedObject = [PSCustomObject]@{ ObjectType = 'Application'; ObjectId = 'app-1'; Error = 'failure' }
            $summary = [PSCustomObject]@{
                Status = 'Partial'
                RawObservationCount = 0
                DeduplicatedObservationCount = 0
                DuplicateObservationCount = 0
                DiscoveredCount = 1
                ProcessedCount = 0
                FailedCount = 1
                SkippedCount = 0
                GroupedFindingCount = 0
                AssessmentRecommendationCount = 0
                CategorySummary = @()
                SeveritySummary = @()
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 1; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
            }
            $manifest = [PSCustomObject]@{
                SourceStatus = 'Partial'
                EvidenceRecordCount = 0
                FailedObjectCount = 1
                GroupedFindingCount = 0
                RecommendationCount = 0
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 1; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
                Artifacts = @(
                    [PSCustomObject]@{ Name = 'failed-objects.json'; RecordCount = 1 },
                    [PSCustomObject]@{ Name = 'failed-objects.csv'; RecordCount = 1 }
                )
            }

            $validation = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @() -EvidenceRows @() -AssessmentFindings @() -FailedObjects @($failedObject) -Manifest $manifest

            $validation.Status | Should -Be 'Success'
            $validation.ReleaseEligible | Should -BeFalse
            $validation.FailedObjectCount | Should -Be 1
        }

        It 'package validation rejects inconsistent object processing counts' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                RawObservationCount = 0
                DeduplicatedObservationCount = 0
                DuplicateObservationCount = 0
                DiscoveredCount = 2
                ProcessedCount = 1
                FailedCount = 0
                SkippedCount = 0
                GroupedFindingCount = 0
                AssessmentRecommendationCount = 0
                CategorySummary = @()
                SeveritySummary = @()
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
            }
            $manifest = [PSCustomObject]@{
                SourceStatus = 'Success'
                EvidenceRecordCount = 0
                FailedObjectCount = 0
                GroupedFindingCount = 0
                RecommendationCount = 0
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
                Artifacts = @(
                    [PSCustomObject]@{ Name = 'failed-objects.json'; RecordCount = 0 },
                    [PSCustomObject]@{ Name = 'failed-objects.csv'; RecordCount = 0 }
                )
            }

            $validation = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @() -EvidenceRows @() -AssessmentFindings @() -FailedObjects @() -Manifest $manifest

            $validation.Status | Should -Be 'Failed'
            $validation.ReleaseEligible | Should -BeFalse
            @($validation.Errors).ErrorId | Should -Contain 'PKG-COUNT-OBJECTPROCESSING-001'
        }

        It 'successful consistent package is release eligible' {
            $summary = [PSCustomObject]@{
                Status = 'Success'
                RawObservationCount = 0
                DeduplicatedObservationCount = 0
                DuplicateObservationCount = 0
                DiscoveredCount = 1
                ProcessedCount = 1
                FailedCount = 0
                SkippedCount = 0
                GroupedFindingCount = 0
                AssessmentRecommendationCount = 0
                CategorySummary = @()
                SeveritySummary = @()
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
            }
            $manifest = [PSCustomObject]@{
                SourceStatus = 'Success'
                EvidenceRecordCount = 0
                FailedObjectCount = 0
                GroupedFindingCount = 0
                RecommendationCount = 0
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @() }
                Artifacts = @(
                    [PSCustomObject]@{ Name = 'failed-objects.json'; RecordCount = 0 },
                    [PSCustomObject]@{ Name = 'failed-objects.csv'; RecordCount = 0 }
                )
            }

            $validation = Test-InspectorReportPackageConsistency -Summary $summary -SecurityObservations @() -EvidenceRows @() -AssessmentFindings @() -FailedObjects @() -Manifest $manifest

            $validation.Status | Should -Be 'Success'
            $validation.ReleaseEligible | Should -BeTrue

            # Required evidence may still be exported and rendered for diagnostics,
            # but incomplete collection coverage must fail closed for release.
            $incompleteEvidence = @(
                [PSCustomObject]@{
                    EvidenceId = 'ev-sp-owner-failed'
                    QueryName = 'ServicePrincipalOwners:sp-1'
                    CollectorName = 'ServicePrincipalOwners:sp-1'
                    Status = 'InsufficientPermission'
                    Completeness = 'Partial'
                    EvidenceScope = 'ObjectRelationship'
                    SubjectObjectType = 'ServicePrincipal'
                    SubjectObjectId = 'sp-1'
                }
            )
            $manifestWithIncompleteEvidence = $manifest.PSObject.Copy()
            $manifestWithIncompleteEvidence.EvidenceRecordCount = 1

            $coverageValidation =
                Test-InspectorReportPackageConsistency `
                    -Summary $summary `
                    -SecurityObservations @() `
                    -EvidenceRows $incompleteEvidence `
                    -AssessmentFindings @() `
                    -FailedObjects @() `
                    -Manifest $manifestWithIncompleteEvidence

            $coverageValidation.Status | Should -Be 'Failed'
            $coverageValidation.ReleaseEligible | Should -BeFalse
            @($coverageValidation.Errors).ErrorId | Should -Contain 'PKG-EVIDENCE-COVERAGE-001'

            $eligibleObservation = [PSCustomObject]@{
                ObservationId = 'OBS-ELIGIBLE'
                FindingEligible = $true
                EvidenceIds = @('ev-plan')
            }
            $contextualObservation = [PSCustomObject]@{
                ObservationId = 'OBS-CONTEXT'
                FindingEligible = $false
                EvidenceIds = @('ev-plan')
            }
            $planEvidence = [PSCustomObject]@{
                EvidenceId = 'ev-plan'
                QueryName = 'Applications'
                Status = 'Success'
                Completeness = 'Complete'
            }
            $assessmentCoverage = [PSCustomObject]@{
                Status = 'Success'
                Completeness = 'Complete'
                EvidencePlanMatches = $true
                ExpectedEvidenceCount = 1
                ActualRequiredEvidenceCount = 1
                ExpectedQueries = @('Applications')
            }
            $integritySummary = [PSCustomObject]@{
                Status = 'Success'
                RawObservationCount = 2
                DeduplicatedObservationCount = 2
                DuplicateObservationCount = 0
                DiscoveredCount = 1
                ProcessedCount = 1
                FailedCount = 0
                SkippedCount = 0
                GroupedFindingCount = 1
                AssessmentRecommendationCount = 0
                CategorySummary = @()
                SeveritySummary = @()
                AssessmentCoverage = $assessmentCoverage
                ScopeInventory = [PSCustomObject]@{ FailedObjects = 0; CollectionCompleteness = 'Complete'; TruncatedCollections = @(); AssessmentCoverageCompleteness = 'Complete' }
            }
            $integrityManifest = [PSCustomObject]@{
                SourceStatus = 'Success'
                EvidenceRecordCount = 1
                FailedObjectCount = 0
                GroupedFindingCount = 1
                RecommendationCount = 0
                AssessmentCoverage = $assessmentCoverage
                ScopeInventory = $integritySummary.ScopeInventory
                Artifacts = @(
                    [PSCustomObject]@{ Name = 'failed-objects.json'; RecordCount = 0 },
                    [PSCustomObject]@{ Name = 'failed-objects.csv'; RecordCount = 0 }
                )
            }
            $eligibleFinding = [PSCustomObject]@{
                FindingId = 'FINDING-ELIGIBLE'
                ObservationIds = @('OBS-ELIGIBLE')
                EvidenceIds = @('ev-plan')
                AffectedObjects = @()
                AffectedObjectCount = 0
            }

            $integrityValidation = Test-InspectorReportPackageConsistency -Summary $integritySummary -SecurityObservations @($eligibleObservation, $contextualObservation) -EvidenceRows @($planEvidence) -AssessmentFindings @($eligibleFinding) -FailedObjects @() -Manifest $integrityManifest
            $integrityValidation.Status | Should -Be 'Success'
            $integrityValidation.ReleaseEligible | Should -BeTrue

            $missingEvidenceManifest = $integrityManifest.PSObject.Copy()
            $missingEvidenceManifest.EvidenceRecordCount = 0
            $missingPlanValidation = Test-InspectorReportPackageConsistency -Summary $integritySummary -SecurityObservations @($eligibleObservation, $contextualObservation) -EvidenceRows @() -AssessmentFindings @($eligibleFinding) -FailedObjects @() -Manifest $missingEvidenceManifest
            $missingPlanValidation.ReleaseEligible | Should -BeFalse
            @($missingPlanValidation.Errors).ErrorId | Should -Contain 'PKG-EVIDENCE-PLAN-001'

            $missingFindingManifest = $integrityManifest.PSObject.Copy()
            $missingFindingManifest.GroupedFindingCount = 0
            $missingFindingSummary = $integritySummary.PSObject.Copy()
            $missingFindingSummary.GroupedFindingCount = 0
            $missingFindingValidation = Test-InspectorReportPackageConsistency -Summary $missingFindingSummary -SecurityObservations @($eligibleObservation, $contextualObservation) -EvidenceRows @($planEvidence) -AssessmentFindings @() -FailedObjects @() -Manifest $missingFindingManifest
            @($missingFindingValidation.Errors).ErrorId | Should -Contain 'PKG-FINDING-ELIGIBILITY-001'

            $coverageWithoutPlan = $assessmentCoverage.PSObject.Copy()
            $coverageWithoutPlan.ExpectedQueries = @()
            $missingPlanMetadataSummary = $integritySummary.PSObject.Copy()
            $missingPlanMetadataSummary.AssessmentCoverage = $coverageWithoutPlan
            $missingPlanMetadataManifest = $integrityManifest.PSObject.Copy()
            $missingPlanMetadataManifest.AssessmentCoverage = $coverageWithoutPlan
            $missingPlanMetadataValidation = Test-InspectorReportPackageConsistency -Summary $missingPlanMetadataSummary -SecurityObservations @($eligibleObservation, $contextualObservation) -EvidenceRows @($planEvidence) -AssessmentFindings @($eligibleFinding) -FailedObjects @() -Manifest $missingPlanMetadataManifest
            $missingPlanMetadataValidation.ReleaseEligible | Should -BeFalse
            @($missingPlanMetadataValidation.Errors).ErrorId | Should -Contain 'PKG-EVIDENCE-PLAN-001'

            $contextualFinding = $eligibleFinding.PSObject.Copy()
            $contextualFinding.ObservationIds = @('OBS-ELIGIBLE','OBS-CONTEXT')
            $contextualLeakValidation = Test-InspectorReportPackageConsistency -Summary $integritySummary -SecurityObservations @($eligibleObservation, $contextualObservation) -EvidenceRows @($planEvidence) -AssessmentFindings @($contextualFinding) -FailedObjects @() -Manifest $integrityManifest
            @($contextualLeakValidation.Errors).ErrorId | Should -Contain 'PKG-FINDING-ELIGIBILITY-002'

            $duplicateObservationSummary = $integritySummary.PSObject.Copy()
            $duplicateObservationSummary.RawObservationCount = 2
            $duplicateObservationSummary.DeduplicatedObservationCount = 2
            $duplicateObservation = $contextualObservation.PSObject.Copy()
            $duplicateObservation.ObservationId = 'OBS-ELIGIBLE'
            $duplicateObservationValidation = Test-InspectorReportPackageConsistency -Summary $duplicateObservationSummary -SecurityObservations @($eligibleObservation, $duplicateObservation) -EvidenceRows @($planEvidence) -AssessmentFindings @($eligibleFinding) -FailedObjects @() -Manifest $integrityManifest
            @($duplicateObservationValidation.Errors).ErrorId | Should -Contain 'PKG-OBSERVATION-ID-002'
        }

        It 'Microsoft-published ownerless service principal is contextual and not finding eligible when owner collection succeeded' {
            foreach ($microsoftApplication in @(
                [PSCustomObject]@{ DisplayName = 'Graph Explorer'; AppId = 'de8bc8b5-d9f9-48b1-a8ad-b748da725064' },
                [PSCustomObject]@{ DisplayName = 'Microsoft Graph Command Line Tools'; AppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e' }
            )) {
                $rawServicePrincipal = [PSCustomObject]@{
                    id = "sp-$($microsoftApplication.AppId)"
                    appId = $microsoftApplication.AppId
                    displayName = $microsoftApplication.DisplayName
                    servicePrincipalType = 'Application'
                    # Deliberately omit owner-tenant proof here so this regression
                    # exercises the exact Microsoft-documented AppId fallback.
                    appOwnerOrganizationId = $null
                    publisherName = 'Microsoft Corporation'
                    verifiedPublisher = $null
                }

                $discovered = ConvertTo-InspectorSnapshotDiscoveredObject -ObjectType 'ServicePrincipal' -RawObject $rawServicePrincipal
                $discovered.Metadata.PublisherClassification | Should -Be 'MicrosoftPublished'
                (Get-InspectorPublisherClassification -ObjectType 'ServicePrincipal' -ServicePrincipalType 'Application' -AppId $microsoftApplication.AppId) | Should -Be 'MicrosoftPublished'
            }

            $verifiedExternal = Get-InspectorPublisherClassification -ObjectType 'ServicePrincipal' -ServicePrincipalType 'Application' -AppOwnerOrganizationId '11111111-1111-1111-1111-111111111111' -VerifiedPublisher ([PSCustomObject]@{ displayName = 'Verified Publisher'; verifiedPublisherId = '22222222-2222-2222-2222-222222222222' })
            $verifiedExternal | Should -Be 'ExternalVerified'

            $publisherNameOnlyObject = [PSCustomObject]@{
                id = 'sp-external-name-only'
                appId = '33333333-3333-3333-3333-333333333333'
                displayName = 'External Name Only'
                servicePrincipalType = 'Application'
                appOwnerOrganizationId = '11111111-1111-1111-1111-111111111111'
                publisherName = 'External Publisher Name'
                verifiedPublisher = $null
            }
            (ConvertTo-InspectorSnapshotDiscoveredObject -ObjectType 'ServicePrincipal' -RawObject $publisherNameOnlyObject).Metadata.PublisherClassification | Should -Be 'ExternalUnverified'

            $source = [PSCustomObject]@{
                ObjectType = 'ServicePrincipal'
                ObjectId = 'sp-ms'
                DisplayName = 'Microsoft Service'
                AppId = 'client-ms'
                Properties = [PSCustomObject]@{ displayName = 'Microsoft Service'; appId = 'client-ms'; accountEnabled = $true }
                Metadata = [PSCustomObject]@{
                    PublisherClassification = 'MicrosoftPublished'
                    TenantOwnershipClassification = 'MicrosoftPublished'
                    ClassificationConfidence = 'ConservativeMetadata'
                    ServicePrincipalType = 'Application'
                }
            }
            $evidence = [PSCustomObject]@{
                EvidenceId = 'ev-owner-zero'
                QueryName = 'ServicePrincipalOwners:sp-ms'
                CollectorName = 'ServicePrincipalOwners:sp-ms'
                Status = 'Success'
                ResultCount = 0
                EvidenceScope = 'ObjectRelationship'
                SubjectObjectType = 'ServicePrincipal'
                SubjectObjectId = 'sp-ms'
            }

            $result = Invoke-InspectorObservationEngine -ObjectInsight (New-ReleaseTestInsight -SourceObjects @($source) -Evidence @($evidence))
            $observation = @($result.Observations | Where-Object { $_.Title -eq 'ServicePrincipal has no owner' })[0]

            $observation | Should -Not -BeNullOrEmpty
            $observation.Severity | Should -Be 'Informational'
            $observation.SignalDisposition | Should -Be 'Contextual'
            $observation.FindingEligible | Should -BeFalse
            $observation.AffectedObject.PublisherClassification | Should -Be 'MicrosoftPublished'
        }

        It 'finding eligibility excludes contextual consent inventory from the grouped consent headline' {
            $actionable = New-InspectorSecurityObservation -Category 'Consent' -Title 'Tenant-wide delegated consent grant' -Description 'tenant wide' -Severity 'Medium' -Confidence 'High' -AffectedObject (New-InspectorAffectedObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1') -EvidenceIds @('ev-consent') -MicrosoftReference 'ref' -WhyItMatters 'matter' -Recommendation 'review'
            $contextual = New-InspectorSecurityObservation -Category 'Consent' -Title 'Delegated consent grants present' -Description 'inventory' -Severity 'Informational' -Confidence 'High' -AffectedObject (New-InspectorAffectedObject -ObjectType 'ServicePrincipal' -ObjectId 'sp-1') -EvidenceIds @('ev-consent') -MicrosoftReference 'ref' -WhyItMatters 'matter' -Recommendation 'review' -Metadata @{ SignalDisposition = 'Contextual' }
            $input = [PSCustomObject]@{
                Status = 'Success'
                SchemaVersion = '1.0'
                ObjectInsights = @()
                SecurityObservations = @($actionable, $contextual)
            }

            $intelligence = Invoke-InspectorAssessmentIntelligence -InputObject $input -AssessmentName 'test'
            $finding = @($intelligence.AssessmentFindings | Where-Object { $_.Category -eq 'ConsentGovernance' })[0]

            $finding | Should -Not -BeNullOrEmpty
            $finding.ObservationCount | Should -Be 1
            @($finding.ObservationIds).Count | Should -Be 1
        }
    }
}


Describe 'Final release-integrity package guards' {
    InModuleScope EntraObjectInspector {
        BeforeAll {
            function New-CurrentPackageEnvelopeFixture {
                param (
                    [switch]$WithRequiredEvidence
                )

                $coverage = [PSCustomObject]@{
                    Status = 'Success'
                    Completeness = 'Complete'
                    EvidencePlanMatches = $true
                    ExpectedEvidenceCount = $(if ($WithRequiredEvidence) { 1 } else { 0 })
                    ActualRequiredEvidenceCount = $(if ($WithRequiredEvidence) { 1 } else { 0 })
                    RequiredEvidenceCount = $(if ($WithRequiredEvidence) { 1 } else { 0 })
                    SuccessfulRequiredEvidenceCount = $(if ($WithRequiredEvidence) { 1 } else { 0 })
                    IncompleteRequiredEvidenceCount = 0
                    MissingExpectedEvidenceCount = 0
                    UnexpectedRequiredEvidenceCount = 0
                    DuplicateRequiredEvidenceCount = 0
                    ExpectedQueries = $(if ($WithRequiredEvidence) { @('Applications') } else { @() })
                }
                $scope = [PSCustomObject]@{
                    FailedObjects = 0
                    CollectionCompleteness = 'Complete'
                    TruncatedCollections = @()
                    AssessmentCoverageCompleteness = 'Complete'
                }
                $summary = [PSCustomObject]@{
                    SchemaVersion = '0.10.0'
                    Status = 'Success'
                    FailedCount = 0
                    GraphRequestsAtSnapshotCompletion = 0
                    GraphRequestsAtAssessmentCompletion = 0
                    GraphCallsAfterSnapshot = 0
                    ScopeInventory = $scope
                    AssessmentCoverage = $coverage
                }
                $manifest = [PSCustomObject]@{
                    SchemaVersion = '0.10.0'
                    SourceStatus = 'Success'
                    FailedObjectCount = 0
                    GraphRequestsAtSnapshotCompletion = 0
                    GraphRequestsAtAssessmentCompletion = 0
                    GraphCallsAfterSnapshot = 0
                    ScopeInventory = $scope
                    AssessmentCoverage = $coverage
                    PackageValidationStatus = 'NotRun'
                    ReleaseEligible = $false
                    Artifacts = @()
                }
                $evidence = if ($WithRequiredEvidence) {
                    @([PSCustomObject]@{
                        EvidenceId = 'ev-apps'
                        QueryName = 'Applications'
                        Status = 'Success'
                        Completeness = 'Complete'
                        EvidenceScope = 'TenantCollection'
                    })
                } else { @() }

                [PSCustomObject]@{ Summary = $summary; Manifest = $manifest; Coverage = $coverage; Scope = $scope; Evidence = @($evidence) }
            }
        }

        It 'fails current packages when ScopeInventory or AssessmentCoverage is absent' {
            $fixture = New-CurrentPackageEnvelopeFixture

            $missingScopeSummary = $fixture.Summary.PSObject.Copy()
            $missingScopeSummary.PSObject.Properties.Remove('ScopeInventory')
            $missingScopeManifest = $fixture.Manifest.PSObject.Copy()
            $missingScopeManifest.PSObject.Properties.Remove('ScopeInventory')
            $missingScope = Test-InspectorReportPackageConsistency -Summary $missingScopeSummary -Manifest $missingScopeManifest
            @($missingScope.Errors).ErrorId | Should -Contain 'PKG-SCOPE-MISSING-001'
            $missingScope.ReleaseEligible | Should -BeFalse

            $missingCoverageSummary = $fixture.Summary.PSObject.Copy()
            $missingCoverageSummary.PSObject.Properties.Remove('AssessmentCoverage')
            $missingCoverageManifest = $fixture.Manifest.PSObject.Copy()
            $missingCoverageManifest.PSObject.Properties.Remove('AssessmentCoverage')
            $missingCoverage = Test-InspectorReportPackageConsistency -Summary $missingCoverageSummary -Manifest $missingCoverageManifest
            @($missingCoverage.Errors).ErrorId | Should -Contain 'PKG-COVERAGE-MISSING-001'
            $missingCoverage.ReleaseEligible | Should -BeFalse
        }

        It 'fails current required-evidence packages when ExpectedQueries is missing or empty' {
            $fixture = New-CurrentPackageEnvelopeFixture -WithRequiredEvidence

            $coverageMissing = $fixture.Coverage.PSObject.Copy()
            $coverageMissing.PSObject.Properties.Remove('ExpectedQueries')
            $summaryMissing = $fixture.Summary.PSObject.Copy(); $summaryMissing.AssessmentCoverage = $coverageMissing
            $manifestMissing = $fixture.Manifest.PSObject.Copy(); $manifestMissing.AssessmentCoverage = $coverageMissing
            $missing = Test-InspectorReportPackageConsistency -Summary $summaryMissing -Manifest $manifestMissing -EvidenceRows $fixture.Evidence
            @($missing.Errors).ErrorId | Should -Contain 'PKG-EVIDENCE-PLAN-001'

            $coverageEmpty = $fixture.Coverage.PSObject.Copy(); $coverageEmpty.ExpectedQueries = @()
            $summaryEmpty = $fixture.Summary.PSObject.Copy(); $summaryEmpty.AssessmentCoverage = $coverageEmpty
            $manifestEmpty = $fixture.Manifest.PSObject.Copy(); $manifestEmpty.AssessmentCoverage = $coverageEmpty
            $empty = Test-InspectorReportPackageConsistency -Summary $summaryEmpty -Manifest $manifestEmpty -EvidenceRows $fixture.Evidence
            @($empty.Errors).ErrorId | Should -Contain 'PKG-EVIDENCE-PLAN-001'
        }

        It 'enforces the mandatory current artifact inventory while leaving optional exports optional' {
            $fixture = New-CurrentPackageEnvelopeFixture
            $packagePath = Join-Path $TestDrive 'mandatory-artifact-package'
            New-Item -ItemType Directory -Path $packagePath -Force | Out-Null

            $artifactRows = [System.Collections.Generic.List[object]]::new()
            foreach ($artifactName in @(Get-InspectorCurrentMandatoryArtifactNames)) {
                $kind = 'json'
                $recordCount = if ($artifactName -in @('assessment-manifest.json','assessment-summary.json')) { 1 } else { 0 }
                $artifactRows.Add([PSCustomObject]@{ Name = $artifactName; Kind = $kind; Path = $artifactName; RecordCount = $recordCount; SizeBytes = 0 })
                if ($artifactName -notin @('assessment-manifest.json','assessment-summary.json')) {
                    Write-InspectorJsonFile -Path (Join-Path $packagePath $artifactName) -Value @()
                }
            }
            $fixture.Manifest.Artifacts = @($artifactRows)
            Write-InspectorJsonFile -Path (Join-Path $packagePath 'assessment-summary.json') -Value $fixture.Summary
            Write-InspectorJsonFile -Path (Join-Path $packagePath 'assessment-manifest.json') -Value $fixture.Manifest
            for ($pass = 0; $pass -lt 4; $pass++) {
                Update-InspectorExportArtifactSizes -Manifest $fixture.Manifest -BasePath $packagePath
                Write-InspectorJsonFile -Path (Join-Path $packagePath 'assessment-manifest.json') -Value $fixture.Manifest
            }

            $clean = Test-InspectorReportPackageConsistency -Summary $fixture.Summary -Manifest $fixture.Manifest -SourcePath $packagePath
            @($clean.Errors | ForEach-Object { $_.ErrorId }) | Should -Not -Contain 'PKG-ARTIFACT-INVENTORY-001'

            $missingRowManifest = $fixture.Manifest.PSObject.Copy()
            $missingRowManifest.Artifacts = @($fixture.Manifest.Artifacts | Where-Object Name -ne 'evidence-index.json')
            $missingRow = Test-InspectorReportPackageConsistency -Summary $fixture.Summary -Manifest $missingRowManifest -SourcePath $packagePath
            @($missingRow.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-ARTIFACT-INVENTORY-001'

            Remove-Item -LiteralPath (Join-Path $packagePath 'failed-objects.json') -Force
            $missingFile = Test-InspectorReportPackageConsistency -Summary $fixture.Summary -Manifest $fixture.Manifest -SourcePath $packagePath
            @($missingFile.Errors | ForEach-Object { $_.ErrorId }) | Should -Contain 'PKG-ARTIFACT-MISSING-001'

            # object-insights-full.json and CSV/Markdown variants are optional.
            @($fixture.Manifest.Artifacts.Name) | Should -Not -Contain 'object-insights-full.json'
        }
    }
}
