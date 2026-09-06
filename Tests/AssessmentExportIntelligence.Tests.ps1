$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'assessment intelligence export integration' {

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
                    SourceRuleIds = @()
                    Metadata = [PSCustomObject]@{
                        PermissionName = 'Directory.ReadWrite.All'
                    }
                }
            }

            function New-TestTenantResult {
                param (
                    [object[]]$Observations = @((New-TestObservation)),
                    [object]$AssessmentIntelligence = $null
                )

                $tenant = [PSCustomObject]@{
                    PSTypeName = 'EntraObjectInspector.TenantInspectionResult'
                    SchemaVersion = '0.8.0'
                    StartedAt = '2026-08-30T10:00:00Z'
                    CompletedAt = '2026-08-30T10:01:00Z'
                    Status = 'Success'
                    Discovery = [PSCustomObject]@{
                        Evidence = @()
                    }
                    Pipeline = [PSCustomObject]@{}
                    ObjectInsights = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.ObjectInsight'
                            Input = 'sp-1'
                            Status = 'Resolved'
                            ResolutionType = 'ApplicationIdentity'
                            SecurityObservations = @($Observations)
                            Evidence = @()
                            RelationshipCollection = [PSCustomObject]@{
                                Evidence = @()
                            }
                        }
                    )
                    SecurityObservations = @($Observations)
                    FailedObjects = @()
                    Logs = @()
                    Summary = [PSCustomObject]@{
                        DiscoveredCount = 1
                        ProcessedCount = 1
                        FailedCount = 0
                        SkippedCount = 0
                        ObjectInsightCount = 1
                        SecurityObservationCount = @($Observations).Count
                    }
                }

                if ($null -ne $AssessmentIntelligence) {
                    $tenant |
                        Add-Member `
                            -NotePropertyName 'AssessmentIntelligence' `
                            -NotePropertyValue $AssessmentIntelligence `
                            -Force
                }

                return $tenant
            }

            function New-TestAssessmentIntelligence {
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
                        Confidence = 'Medium'
                        ObservationCount = 2
                        FindingCount = 1
                        RecommendationCount = 1
                        CorrelationCount = 1
                    }
                    AssessmentFindings = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.AssessmentFinding'
                            SchemaVersion = '0.9.0'
                            FindingId = 'FINDING-1'
                            Category = 'PermissionExposure'
                            Title = 'High-impact Microsoft Graph permission exposure detected'
                            Conclusion = 'Permission observations indicate high-impact permissions.'
                            Severity = 'High'
                            Confidence = 'High'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            AffectedObjects = @()
                            MicrosoftReference = 'Microsoft reference'
                            Recommendation = 'Review high-impact permissions.'
                            Limitations = @()
                            Metadata = [PSCustomObject]@{}
                        }
                    )
                    AssessmentRecommendations = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.AssessmentRecommendation'
                            SchemaVersion = '0.9.0'
                            RecommendationId = 'REC-1'
                            Category = 'PermissionExposure'
                            Title = 'Review high-impact application permissions'
                            Action = 'Validate necessity and least privilege.'
                            Rationale = 'High-impact permissions can allow app-only access.'
                            MicrosoftReference = 'Microsoft reference'
                            Confidence = 'High'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            Limitations = @()
                        }
                    )
                    Correlations = @(
                        [PSCustomObject]@{
                            PSTypeName = 'EntraObjectInspector.AssessmentCorrelation'
                            SchemaVersion = '0.9.0'
                            CorrelationId = 'CORR-1'
                            CorrelationType = 'PermissionConsentCoOccurrence'
                            Title = 'High-impact permissions co-occur with consent observations'
                            Description = 'Description'
                            Confidence = 'Medium'
                            ObservationIds = @('OBS-1')
                            EvidenceIds = @('ev-1')
                            AffectedObjects = @()
                            Limitations = @('Not an attack path')
                        }
                    )
                    Limitations = @(
                        'Assessment intelligence does not call Microsoft Graph.',
                        'Not an attack path'
                    )
                }
            }
        }

        BeforeEach {
            Mock Invoke-InspectorGraphRequest {
                throw 'Export must not call Graph.'
            }
        }

        It 'converts explicit assessment intelligence into export datasets' {
            $intelligence = New-TestAssessmentIntelligence
            $tenant = New-TestTenantResult

            $model =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -AssessmentName 'Assessment Export Unit Test'

            $model.SchemaVersion | Should -Be '0.10.0'
            $model.Manifest.AssessmentIntelligenceIncluded | Should -BeTrue
            $model.Manifest.GraphCallsIssued | Should -Be 0
            $model.Manifest.IntelligenceAdded | Should -BeFalse
            $model.TenantPosture.Label | Should -Be 'AttentionRequired'
            $model.AssessmentFindingRows.Count | Should -Be 1
            $model.AssessmentRecommendationRows.Count | Should -Be 1
            $model.AssessmentCorrelationRows.Count | Should -Be 1
            $model.AssessmentLimitationRows.Count | Should -Be 2

            Should-Invoke Invoke-InspectorGraphRequest -Times 0
        }

        It 'discovers attached AssessmentIntelligence from the tenant result' {
            $intelligence = New-TestAssessmentIntelligence
            $tenant = New-TestTenantResult -AssessmentIntelligence $intelligence

            $model =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant

            $model.Manifest.AssessmentIntelligenceIncluded | Should -BeTrue
            $model.AssessmentFindings.Count | Should -Be 1
        }

        It 'continues to export successfully when assessment intelligence is absent' {
            $tenant = New-TestTenantResult

            $model =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant

            $model.Manifest.AssessmentIntelligenceIncluded | Should -BeFalse
            $model.AssessmentFindings.Count | Should -Be 0
            $model.AssessmentRecommendations.Count | Should -Be 0
            $model.AssessmentCorrelations.Count | Should -Be 0
        }

        It 'updates Markdown with assessment intelligence sections' {
            $intelligence = New-TestAssessmentIntelligence
            $tenant = New-TestTenantResult
            $model =
                ConvertTo-InspectorAssessmentExport `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -AssessmentName 'Markdown Assessment Export'

            $markdown =
                New-InspectorAssessmentMarkdown `
                    -ExportModel $model

            $markdown | Should -Match '## Tenant Posture'
            $markdown | Should -Match '## Assessment Findings'
            $markdown | Should -Match '## Assessment Recommendations'
            $markdown | Should -Match '## Assessment Correlations'
            $markdown | Should -Match 'High-impact Microsoft Graph permission exposure detected'
        }

        It 'writes intelligence JSON and CSV artifacts' {
            $intelligence = New-TestAssessmentIntelligence
            $tenant = New-TestTenantResult

            $result =
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Assessment Export Test' `
                    -ExportDirectoryName 'assessment-export-export' `
                    -Force

            $result.Status | Should -Be 'Success'
            $result.SchemaVersion | Should -Be '0.10.0'
            $result.AssessmentIntelligenceIncluded | Should -BeTrue
            $result.GraphCallsIssued | Should -Be 0
            $result.IntelligenceAdded | Should -BeFalse

            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-intelligence.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'tenant-posture.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-findings.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-findings.csv') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-recommendations.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-recommendations.csv') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-correlations.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-correlations.csv') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-limitations.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-limitations.csv') | Should -BeTrue

            $intelligenceArtifact = Get-Content -LiteralPath (Join-Path $result.ExportDirectory 'assessment-intelligence.json') -Raw | ConvertFrom-Json
            $postureArtifact = Get-Content -LiteralPath (Join-Path $result.ExportDirectory 'tenant-posture.json') -Raw | ConvertFrom-Json
            foreach ($packageArtifact in @($intelligenceArtifact, $postureArtifact)) {
                $packageArtifact.RunId | Should -Be $result.RunId
                $packageArtifact.ReportId | Should -Be $result.ReportId
                $packageArtifact.FailedObjectCount | Should -Be 0
                $packageArtifact.PackageValidationStatus | Should -Be 'NotRun'
                $packageArtifact.ReleaseEligible | Should -BeFalse
            }
        }

        It 'suppresses intelligence CSV artifacts when NoCsv is used' {
            $intelligence = New-TestAssessmentIntelligence
            $tenant = New-TestTenantResult

            $result =
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Assessment Json Export' `
                    -ExportDirectoryName 'assessment-export-json' `
                    -NoCsv `
                    -Force

            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-findings.json') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-findings.csv') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-recommendations.csv') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $result.ExportDirectory 'assessment-correlations.csv') | Should -BeFalse
        }

        It 'records intelligence artifact counts in the export result' {
            $intelligence = New-TestAssessmentIntelligence
            $tenant = New-TestTenantResult

            $result =
                Export-EntraTenantInspection `
                    -InputObject $tenant `
                    -AssessmentIntelligence $intelligence `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Assessment Artifact Count' `
                    -ExportDirectoryName 'assessment-export-artifacts' `
                    -Force

            ($result.Artifacts | Where-Object Name -eq 'assessment-findings.json').RecordCount | Should -Be 1
            ($result.Artifacts | Where-Object Name -eq 'assessment-recommendations.json').RecordCount | Should -Be 1
            ($result.Artifacts | Where-Object Name -eq 'assessment-correlations.json').RecordCount | Should -Be 1
            ($result.Artifacts | Where-Object Name -eq 'assessment-limitations.json').RecordCount | Should -Be 2
        }

        It 'supports pipeline input with explicit assessment intelligence' {
            $intelligence = New-TestAssessmentIntelligence
            $tenant = New-TestTenantResult

            $result =
                $tenant |
                Export-EntraTenantInspection `
                    -AssessmentIntelligence $intelligence `
                    -OutputDirectory $TestDrive `
                    -AssessmentName 'Pipeline Assessment Export' `
                    -ExportDirectoryName 'assessment-export-pipeline' `
                    -Force

            $result.Status | Should -Be 'Success'
            $result.AssessmentIntelligenceIncluded | Should -BeTrue
        }
    }
}

