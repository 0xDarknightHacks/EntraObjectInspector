$modulePath = Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'
Import-Module $modulePath -Force

Describe 'Portable snapshot, targeting, comparison, and policy primitives' {
    InModuleScope EntraObjectInspector {
        BeforeAll {
            function New-TestContractSnapshot {
                param (
                    [string]$SnapshotId = 'snapshot-current',
                    [object[]]$ApplicationOwners = @(),
                    [object[]]$GroupOwners = @(),
                    [object[]]$ApplicationCredentials = @(),
                    [object[]]$GroupMembers = @(),
                    [object[]]$RequiredResourceAccess = @(),
                    [object[]]$OAuth2PermissionGrants = @()
                )

                $collections = [PSCustomObject][ordered]@{
                    Applications = @([PSCustomObject]@{ id='app-1'; appId='11111111-1111-1111-1111-111111111111'; displayName='App One'; keyCredentials=@(); passwordCredentials=@(); requiredResourceAccess=@(); appRoles=@(); EvidenceId="ev-app-$SnapshotId" })
                    ServicePrincipals = @([PSCustomObject]@{ id='sp-1'; appId='11111111-1111-1111-1111-111111111111'; displayName='SP One'; keyCredentials=@(); passwordCredentials=@(); appRoles=@(); EvidenceId="ev-sp-$SnapshotId" })
                    Users = @([PSCustomObject]@{ id='user-1'; userPrincipalName='user1@contoso.com'; displayName='User One'; EvidenceId="ev-user-$SnapshotId" })
                    Groups = @([PSCustomObject]@{ id='group-1'; displayName='Group One'; EvidenceId="ev-group-$SnapshotId" })
                    Organization = @([PSCustomObject]@{ id='tenant-1'; displayName='Contoso'; EvidenceId="ev-org-$SnapshotId" })
                    OAuth2PermissionGrants = @($OAuth2PermissionGrants)
                    DirectoryRoleAssignments = @()
                    ApplicationOwners = @($ApplicationOwners)
                    ServicePrincipalOwners = @()
                    ServicePrincipalOwnedObjects = @()
                    ServicePrincipalGroupMemberships = @()
                    GroupOwners = @($GroupOwners)
                    GroupMembers = @($GroupMembers)
                    GroupMemberships = @()
                    UserTransitiveMemberships = @()
                    AppRoleAssignments = @()
                    AppRoleAssignedTo = @()
                    ApplicationCredentials = @($ApplicationCredentials)
                    ServicePrincipalCredentials = @()
                    RequiredResourceAccess = @($RequiredResourceAccess)
                    ExposedAppRoles = @()
                }

                $evidence = @(
                    'app','sp','user','group','org','owner','credential','member','permission','grant' |
                        ForEach-Object {
                            [PSCustomObject][ordered]@{
                                EvidenceId = "ev-$_-$SnapshotId"
                                QueryName = "Test:$_"
                                Status = 'Success'
                                Completeness = 'Complete'
                            }
                        }
                )

                $snapshot = [PSCustomObject][ordered]@{
                    PSTypeName = 'EntraObjectInspector.TenantSnapshot'
                    SchemaVersion = '1.1.0'
                    SnapshotId = $SnapshotId
                    CreatedAt = '2026-09-07T10:00:00.0000000Z'
                    CollectionMode = 'GraphIngestionOnly'
                    PersistenceMode = 'PortableCapable'
                    GraphCallsAllowedAfterSnapshot = $false
                    SourceTenantId = 'tenant-1'
                    SourceClientId = 'client-1'
                    CollectionScope = [PSCustomObject]@{ Mode='Targeted'; ObjectTypes=@('Application','ServicePrincipal','User','Group'); ResolvedTargets=@(); ResolvedObjectKeys=@('Application|app-1'); ScopeSignature='SCOPE-TEST' }
                    Collections = $collections
                    CollectionSummary = [PSCustomObject]@{}
                    AssessmentCoverage = [PSCustomObject]@{ Status='Success'; Completeness='Complete' }
                    TenantMetadata = [PSCustomObject]@{ TenantId='tenant-1'; TenantDisplayName='Contoso' }
                    ScopeInventory = [PSCustomObject]@{}
                    Evidence = @($evidence)
                    Limitations = @()
                }
                $snapshot | Add-Member -NotePropertyName Indexes -NotePropertyValue (New-InspectorTenantSnapshotIndexes -Collections $collections) -Force
                return $snapshot
            }

            function Update-TestPortableEnvelopeHash {
                param (
                    [Parameter(Mandatory)]
                    [object]$Envelope
                )

                $payloadJson = $Envelope.Snapshot | ConvertTo-Json -Depth 100 -Compress
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $hash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) | ForEach-Object { $_.ToString('x2') })
                }
                finally {
                    $sha.Dispose()
                }
                $Envelope.Integrity.PayloadHash = $hash.ToUpperInvariant()
            }

            function New-TestSourceObservation {
                return New-InspectorSecurityObservation `
                    -Category 'Permissions' `
                    -Title 'High impact permission' `
                    -Description 'A high impact permission is present.' `
                    -Severity 'High' `
                    -Confidence 'High' `
                    -AffectedObject ([PSCustomObject]@{ ObjectType='ServicePrincipal'; ObjectId='sp-1'; DisplayName='SP One' }) `
                    -EvidenceIds @('ev-source') `
                    -MicrosoftReference 'https://learn.microsoft.com/' `
                    -WhyItMatters 'The permission can materially expand access.' `
                    -Recommendation 'Review the permission.' `
                    -SourceRuleIds @('BUILTIN-1') `
                    -Metadata @{ PermissionName='Directory.ReadWrite.All'; SignalDisposition='Actionable' }
            }
        }

        It 'round-trips a portable snapshot and rebuilds indexes without Graph' {
            $path = Join-Path $TestDrive 'portable-snapshot.json'
            $snapshot = New-TestContractSnapshot
            Mock Invoke-InspectorGraphRequest { throw 'Portable import must not call Graph.' }

            $export = Export-InspectorTenantSnapshot -TenantSnapshot $snapshot -Path $path
            $imported = Import-InspectorTenantSnapshot -Path $path

            $export.Status | Should -Be 'Success'
            $imported.SnapshotId | Should -Be $snapshot.SnapshotId
            $imported.PersistenceMode | Should -Be 'PortableJsonImported'
            $imported.GraphCallsAllowedAfterSnapshot | Should -BeFalse
            $imported.Indexes.ApplicationByObjectId.ContainsKey('app-1') | Should -BeTrue
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'rejects tampered portable snapshot content' {
            $path = Join-Path $TestDrive 'tampered-snapshot.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $content = Get-Content -LiteralPath $path -Raw
            $content.Replace('App One','App Tampered') | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*payload hash mismatch*'
        }

        It 'rejects a portable snapshot with missing Integrity metadata' {
            $path = Join-Path $TestDrive 'missing-integrity.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope.PSObject.Properties.Remove('Integrity')
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*Integrity is required*'
        }

        It 'rejects a portable snapshot with a missing payload hash' {
            $path = Join-Path $TestDrive 'missing-hash.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope.Integrity.PSObject.Properties.Remove('PayloadHash')
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*Integrity.PayloadHash is required*'
        }

        It 'rejects a portable snapshot with a missing integrity algorithm' {
            $path = Join-Path $TestDrive 'missing-algorithm.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope.Integrity.PSObject.Properties.Remove('Algorithm')
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*Integrity.Algorithm is required*'
        }

        It 'requires the integrity algorithm to be exactly SHA256' {
            $path = Join-Path $TestDrive 'wrong-algorithm.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope.Integrity.Algorithm = 'sha256'
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw "*must be exactly 'SHA256'*"
        }

        It 'rejects a malformed mandatory payload hash' {
            $path = Join-Path $TestDrive 'malformed-hash.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope.Integrity.PayloadHash = 'ABC123'
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*64-character hexadecimal SHA256 hash*'
        }

        It 'rejects blank EvidenceId values even when the payload hash is valid' {
            $path = Join-Path $TestDrive 'blank-evidence-id.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope.Snapshot.Evidence[0].EvidenceId = '   '
            Update-TestPortableEnvelopeHash -Envelope $envelope
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*nonblank EvidenceId*'
        }

        It 'rejects duplicate EvidenceId values even when the payload hash is valid' {
            $path = Join-Path $TestDrive 'duplicate-evidence-id.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope.Snapshot.Evidence[1].EvidenceId = $envelope.Snapshot.Evidence[0].EvidenceId
            Update-TestPortableEnvelopeHash -Envelope $envelope
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*EvidenceId values must be unique*'
        }

        It 'rejects envelope properties not declared by the portable snapshot schema' {
            $path = Join-Path $TestDrive 'unexpected-envelope-property.json'
            Export-InspectorTenantSnapshot -TenantSnapshot (New-TestContractSnapshot) -Path $path | Out-Null
            $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
            $envelope | Add-Member -NotePropertyName 'UnexpectedProperty' -NotePropertyValue 'not-allowed'
            $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8

            { Import-InspectorTenantSnapshot -Path $path } | Should -Throw '*not allowed by the contract schema*'
        }

        It 'parses deterministic TXT and CSV target specifications' {
            $txt = Join-Path $TestDrive 'targets.txt'
            $csv = Join-Path $TestDrive 'targets.csv'
            @('# comment','Application|app-1','sp-1') | Set-Content -LiteralPath $txt
            @([PSCustomObject]@{ ObjectType='Group'; Identity='group-1' }) | Export-Csv -LiteralPath $csv -NoTypeInformation

            $txtTargets = @(Import-InspectorTargetSpecification -TargetFile $txt)
            $csvTargets = @(Import-InspectorTargetSpecification -TargetFile $csv)

            $txtTargets.Count | Should -Be 2
            ($txtTargets | Where-Object Identity -eq 'app-1').ObjectType | Should -Be 'Application'
            $csvTargets[0].ObjectType | Should -Be 'Group'
            $csvTargets[0].Identity | Should -Be 'group-1'
        }

        It 'fails target resolution when a human-readable identity is ambiguous' {
            Mock New-InspectorSnapshotCollectionResult {
                param($Name)
                $type = if ($Name -like 'TargetResolve:Application:*') { 'Application' } else { 'ServicePrincipal' }
                $item = if ($type -eq 'Application') {
                    [PSCustomObject]@{ id='app-1'; displayName='Duplicate Name' }
                }
                else {
                    [PSCustomObject]@{ id='sp-1'; displayName='Duplicate Name' }
                }
                [PSCustomObject]@{
                    Status='Success'; Items=@($item); Limitations=@();
                    Evidence=[PSCustomObject]@{ EvidenceId="ev-$type"; QueryName=$Name; Status='Success'; Completeness='Complete' }
                }
            }

            $spec = [PSCustomObject]@{ ObjectType=''; Identity='Duplicate Name'; Source='test' }
            { Resolve-InspectorAssessmentTargets -TargetSpecification @($spec) -ObjectType @('Application','ServicePrincipal') } | Should -Throw '*ambiguous*'
        }

        It 'fails target resolution when no exact target exists' {
            Mock New-InspectorSnapshotCollectionResult {
                param($Name)
                [PSCustomObject]@{
                    Status='Success'; Items=@(); Limitations=@();
                    Evidence=[PSCustomObject]@{ EvidenceId="ev-$Name"; QueryName=$Name; Status='Success'; Completeness='Complete' }
                }
            }

            $spec = [PSCustomObject]@{ ObjectType='Application'; Identity='Missing App'; Source='test' }
            { Resolve-InspectorAssessmentTargets -TargetSpecification @($spec) -ObjectType @('Application') } | Should -Throw '*could not be resolved*'
        }

        It 'emits deterministic owner, credential, membership, and permission drift records' {
            $previous = New-TestContractSnapshot `
                -SnapshotId 'previous' `
                -ApplicationOwners @([PSCustomObject]@{ SourceObjectId='app-1'; Owner=[PSCustomObject]@{ id='owner-old' }; EvidenceId='ev-owner-previous' }) `
                -ApplicationCredentials @([PSCustomObject]@{ SourceObjectId='app-1'; CredentialType='Password'; Credential=[PSCustomObject]@{ keyId='cred-1'; displayName='Credential'; startDateTime='2026-01-01T00:00:00Z'; endDateTime='2026-10-01T00:00:00Z' }; EvidenceId='ev-credential-previous' }) `
                -GroupMembers @([PSCustomObject]@{ SourceObjectId='group-1'; Member=[PSCustomObject]@{ id='user-old' }; EvidenceId='ev-member-previous' }) `
                -RequiredResourceAccess @([PSCustomObject]@{ SourceObjectId='app-1'; Access=[PSCustomObject]@{ resourceAppId='graph'; resourceAccess=@([PSCustomObject]@{ id='perm-old'; type='Role' }) }; EvidenceId='ev-permission-previous' })

            $current = New-TestContractSnapshot `
                -SnapshotId 'current' `
                -ApplicationOwners @([PSCustomObject]@{ SourceObjectId='app-1'; Owner=[PSCustomObject]@{ id='owner-new' }; EvidenceId='ev-owner-current' }) `
                -ApplicationCredentials @([PSCustomObject]@{ SourceObjectId='app-1'; CredentialType='Password'; Credential=[PSCustomObject]@{ keyId='cred-1'; displayName='Credential'; startDateTime='2026-01-01T00:00:00Z'; endDateTime='2027-10-01T00:00:00Z' }; EvidenceId='ev-credential-current' }) `
                -GroupMembers @([PSCustomObject]@{ SourceObjectId='group-1'; Member=[PSCustomObject]@{ id='user-new' }; EvidenceId='ev-member-current' }) `
                -RequiredResourceAccess @([PSCustomObject]@{ SourceObjectId='app-1'; Access=[PSCustomObject]@{ resourceAppId='graph'; resourceAccess=@([PSCustomObject]@{ id='perm-new'; type='Role' }) }; EvidenceId='ev-permission-current' })

            $comparison = Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current
            $comparison2 = Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current

            $comparison.Changes.Category | Should -Contain 'OwnerRemoved'
            $comparison.Changes.Category | Should -Contain 'OwnerAdded'
            $comparison.Changes.Category | Should -Contain 'CredentialChanged'
            $comparison.Changes.Category | Should -Contain 'GroupMemberRemoved'
            $comparison.Changes.Category | Should -Contain 'GroupMemberAdded'
            $comparison.Changes.Category | Should -Contain 'PermissionRemoved'
            $comparison.Changes.Category | Should -Contain 'PermissionAdded'
            @($comparison.Changes.ChangeId) | Should -Be @($comparison2.Changes.ChangeId)
        }

        It 'compares canonical group owners including reconstructed service-principal owners' {
            $previous = New-TestContractSnapshot `
                -SnapshotId 'previous' `
                -GroupOwners @([PSCustomObject]@{ SourceObjectId='group-1'; Owner=[PSCustomObject]@{ id='sp-owner-old'; '@odata.type'='#microsoft.graph.servicePrincipal' }; EvidenceId='ev-sp-owner-previous' })

            $current = New-TestContractSnapshot `
                -SnapshotId 'current' `
                -GroupOwners @([PSCustomObject]@{ SourceObjectId='group-1'; Owner=[PSCustomObject]@{ id='sp-owner-new'; '@odata.type'='#microsoft.graph.servicePrincipal' }; EvidenceId='ev-sp-owner-current' })

            $comparison = Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current

            $comparison.Changes.Category | Should -Contain 'OwnerRemoved'
            $comparison.Changes.Category | Should -Contain 'OwnerAdded'
            $comparison.Changes.SemanticKey | Should -Contain 'Owner|Group|group-1|sp-owner-old'
            $comparison.Changes.SemanticKey | Should -Contain 'Owner|Group|group-1|sp-owner-new'
        }

        It 'does not emit definitive group-owner drift when owner evidence is explicitly incomplete' {
            $previous = New-TestContractSnapshot `
                -SnapshotId 'previous' `
                -GroupOwners @([PSCustomObject]@{ SourceObjectId='group-1'; Owner=[PSCustomObject]@{ id='sp-owner-old'; '@odata.type'='#microsoft.graph.servicePrincipal' }; EvidenceId='ev-group-owner-previous' })
            $current = New-TestContractSnapshot `
                -SnapshotId 'current' `
                -GroupOwners @([PSCustomObject]@{ SourceObjectId='group-1'; Owner=[PSCustomObject]@{ id='sp-owner-new'; '@odata.type'='#microsoft.graph.servicePrincipal' }; EvidenceId='ev-group-owner-current' })

            foreach ($snapshot in @($previous, $current)) {
                $snapshot.Evidence += [PSCustomObject][ordered]@{
                    EvidenceId='ev-group-owner-current'
                    QueryName='GroupOwners:group-1'
                    Status='Partial'
                    Completeness='Partial'
                    EvidenceScope='ObjectRelationship'
                    SubjectObjectType='Group'
                    SubjectObjectId='group-1'
                }
                $snapshot.Indexes = New-InspectorTenantSnapshotIndexes -Collections $snapshot.Collections -Evidence $snapshot.Evidence
            }

            $comparison = Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current

            @($comparison.Changes | Where-Object { $_.Category -in @('OwnerAdded','OwnerRemoved') -and $_.SubjectObjectType -eq 'Group' }).Count | Should -Be 0
        }

        It 'refuses comparison across different deterministic collection scopes' {
            $previous = New-TestContractSnapshot -SnapshotId 'previous'
            $current = New-TestContractSnapshot -SnapshotId 'current'
            $current.CollectionScope.ScopeSignature = 'DIFFERENT-SCOPE'

            { Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current } | Should -Throw '*collection scope differs*'
        }

        It 'rejects executable or unsupported rule-pack predicate operators' {
            $path = Join-Path $TestDrive 'bad-rule-pack.json'
            @{
                ContractName='EntraObjectInspector.RulePack'; SchemaVersion='1.0.0'; RulePackId='test-pack'; Rules=@(
                    @{ RuleId='CUSTOM-1'; Category='Permissions'; Title='Custom'; Description='Custom'; Severity='High'; WhyItMatters='Why'; RecommendedAction='Review'; Predicates=@(@{ Path='Category'; Operator='Script'; Value='anything' }) }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path

            { Import-InspectorRulePack -Path $path } | Should -Throw '*unsupported predicate operator*'
        }

        It 'rejects rule packs that omit the required Rules collection but accepts an explicit empty collection' {
            $missingRulesPath = Join-Path $TestDrive 'missing-rules.json'
            @{
                ContractName='EntraObjectInspector.RulePack'; SchemaVersion='1.0.0'; RulePackId='test-pack'
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $missingRulesPath

            { Import-InspectorRulePack -Path $missingRulesPath } | Should -Throw '*requires Rules*'

            $emptyRulesPath = Join-Path $TestDrive 'empty-rules.json'
            @{
                ContractName='EntraObjectInspector.RulePack'; SchemaVersion='1.0.0'; RulePackId='test-pack'; Rules=@()
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $emptyRulesPath

            { Import-InspectorRulePack -Path $emptyRulesPath } | Should -Not -Throw
        }

        It 'applies declarative custom rules while preserving source evidence provenance' {
            $path = Join-Path $TestDrive 'rule-pack.json'
            @{
                ContractName='EntraObjectInspector.RulePack'; SchemaVersion='1.0.0'; RulePackId='test-pack'; Rules=@(
                    @{ RuleId='CUSTOM-1'; Category='Permissions'; Title='Custom permission policy'; Description='Custom policy matched.'; Severity='High'; Confidence='High'; WhyItMatters='Custom policy says this matters.'; RecommendedAction='Review this permission.'; Predicates=@(@{ Path='Category'; Operator='Equals'; Value='Permissions' }) }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path

            $source = New-TestSourceObservation
            $result = Invoke-InspectorAssessmentPolicy -Observations @($source) -RulePackPath $path
            $custom = @($result.Observations | Where-Object { $_.Metadata.CustomRule -eq $true })

            $custom.Count | Should -Be 1
            $custom[0].EvidenceIds | Should -Contain 'ev-source'
            $custom[0].Metadata.SourceObservationId | Should -Be $source.ObservationId
            $result.CustomObservationCount | Should -Be 1
        }

        It 'marks baseline matches without deleting or altering underlying observations' {
            $source = New-TestSourceObservation
            $path = Join-Path $TestDrive 'baseline.json'
            @{
                ContractName='EntraObjectInspector.AssessmentBaseline'; SchemaVersion='1.0.0'; Entries=@(
                    @{ Kind='Observation'; SemanticKey=$source.SemanticKey; Reason='Accepted for test' }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path

            $result = Invoke-InspectorAssessmentPolicy -Observations @($source) -BaselinePath $path

            $result.Observations.Count | Should -Be 1
            $result.Observations[0].ObservationId | Should -Be $source.ObservationId
            $result.Observations[0].EvidenceIds | Should -Contain 'ev-source'
            $result.Observations[0].BaselineState | Should -Be 'Accepted'
        }

        It 'rejects baselines that omit the required Entries collection but accepts an explicit empty collection' {
            $missingEntriesPath = Join-Path $TestDrive 'missing-entries.json'
            @{
                ContractName='EntraObjectInspector.AssessmentBaseline'; SchemaVersion='1.0.0'
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $missingEntriesPath

            { Import-InspectorAssessmentBaseline -Path $missingEntriesPath } | Should -Throw '*requires Entries*'

            $emptyEntriesPath = Join-Path $TestDrive 'empty-entries.json'
            @{
                ContractName='EntraObjectInspector.AssessmentBaseline'; SchemaVersion='1.0.0'; Entries=@()
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $emptyEntriesPath

            { Import-InspectorAssessmentBaseline -Path $emptyEntriesPath } | Should -Not -Throw
        }

        It 'adds explicit finding explanation and exact observation evidence proof' {
            $source = New-TestSourceObservation
            $source | Add-Member -NotePropertyName BaselineState -NotePropertyValue 'Accepted' -Force
            $finding = New-InspectorAssessmentFinding `
                -Category 'PermissionExposure' `
                -Title 'Permission exposure' `
                -Conclusion 'A high-impact permission is present.' `
                -Severity 'High' `
                -Confidence 'High' `
                -RelatedObservations @($source) `
                -Recommendation 'Review this permission.' `
                -MicrosoftReference 'https://learn.microsoft.com/'

            $finding.WhatHappened | Should -Be $finding.Conclusion
            $finding.WhyItMatters | Should -Not -BeNullOrEmpty
            $finding.RecommendedAction | Should -Be 'Review this permission.'
            $finding.AffectedObjects.Count | Should -Be 1
            $finding.ObservationIds | Should -Be @($source.ObservationId)
            $finding.EvidenceIds | Should -Be @('ev-source')
            $finding.EvidenceProof[0].EvidenceIds | Should -Be @('ev-source')
            $finding.BaselineState | Should -Be 'Accepted'
        }
    }
}
