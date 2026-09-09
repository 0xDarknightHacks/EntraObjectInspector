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
                    [object[]]$OAuth2PermissionGrants = @(),
                    [object[]]$DirectoryRoleAssignments = @(),
                    [object[]]$RoleAssignmentScheduleInstances = @(),
                    [object[]]$RoleEligibilityScheduleInstances = @(),
                    [object[]]$AdministrativeUnits = @(),
                    [object[]]$AdministrativeUnitMembers = @(),
                    [object[]]$RiskyUsers = @()
                )

                $collections = [PSCustomObject][ordered]@{
                    Applications = @([PSCustomObject]@{ id='app-1'; appId='11111111-1111-1111-1111-111111111111'; displayName='App One'; keyCredentials=@(); passwordCredentials=@(); requiredResourceAccess=@(); appRoles=@(); EvidenceId="ev-app-$SnapshotId" })
                    ServicePrincipals = @([PSCustomObject]@{ id='sp-1'; appId='11111111-1111-1111-1111-111111111111'; displayName='SP One'; keyCredentials=@(); passwordCredentials=@(); appRoles=@(); EvidenceId="ev-sp-$SnapshotId" })
                    Users = @([PSCustomObject]@{ id='user-1'; userPrincipalName='user1@contoso.com'; displayName='User One'; EvidenceId="ev-user-$SnapshotId" })
                    Groups = @([PSCustomObject]@{ id='group-1'; displayName='Group One'; EvidenceId="ev-group-$SnapshotId" })
                    Organization = @([PSCustomObject]@{ id='tenant-1'; displayName='Contoso'; EvidenceId="ev-org-$SnapshotId" })
                    OAuth2PermissionGrants = @($OAuth2PermissionGrants)
                    DirectoryRoleDefinitions = @()
                    DirectoryRoleAssignments = @($DirectoryRoleAssignments)
                    RoleAssignmentScheduleInstances = @($RoleAssignmentScheduleInstances)
                    RoleEligibilityScheduleInstances = @($RoleEligibilityScheduleInstances)
                    AdministrativeUnits = @($AdministrativeUnits)
                    AdministrativeUnitMembers = @($AdministrativeUnitMembers)
                    AdministrativeUnitScopedRoleMembers = @()
                    RiskyUsers = @($RiskyUsers)
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
            $imported.TenantMetadata.LicenseValidation.PrivilegedIdentityManagement.Status | Should -Be 'Unknown'
            $imported.TenantMetadata.LicenseValidation.IdentityProtectionRiskyUsers.Status | Should -Be 'Unknown'
            $imported.Indexes.ApplicationByObjectId.ContainsKey('app-1') | Should -BeTrue
            Should -Invoke Invoke-InspectorGraphRequest -Times 0 -Exactly
        }

        It 'round-trips privileged identity context collections and rebuilds indexes' {
            $path = Join-Path $TestDrive 'privileged-context-snapshot.json'
            $snapshot = New-TestContractSnapshot `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Assigned'; EvidenceId='ev-active' }) `
                -RoleEligibilityScheduleInstances @([PSCustomObject]@{ id='eligible-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-eligible' }) `
                -AdministrativeUnits @([PSCustomObject]@{ id='au-1'; displayName='AU One'; EvidenceId='ev-au' }) `
                -AdministrativeUnitMembers @([PSCustomObject]@{ AdministrativeUnitId='au-1'; Member=[PSCustomObject]@{ id='user-1'; displayName='User One' }; EvidenceId='ev-au-member' }) `
                -RiskyUsers @([PSCustomObject]@{ id='user-1'; riskLevel='high'; riskState='atRisk'; EvidenceId='ev-risk' })

            Export-InspectorTenantSnapshot -TenantSnapshot $snapshot -Path $path | Out-Null
            $imported = Import-InspectorTenantSnapshot -Path $path

            $imported.Collections.DirectoryRoleAssignments.Count | Should -Be 1
            $imported.Collections.RoleAssignmentScheduleInstances.Count | Should -Be 1
            $imported.Collections.RoleEligibilityScheduleInstances.Count | Should -Be 1
            $imported.Collections.AdministrativeUnits.Count | Should -Be 1
            $imported.Collections.AdministrativeUnitMembers.Count | Should -Be 1
            $imported.Collections.RiskyUsers.Count | Should -Be 1
            $imported.Indexes.DirectoryRoleAssignmentsByPrincipalId['user-1'].Count | Should -Be 1
            $imported.Indexes.RoleAssignmentScheduleInstancesByPrincipalId['user-1'].Count | Should -Be 1
            $imported.Indexes.RoleAssignmentScheduleInstancesByPrincipalId['user-1'][0].assignmentType | Should -Be 'Assigned'
            $imported.Indexes.RoleEligibilityScheduleInstancesByPrincipalId['user-1'].Count | Should -Be 1
            $imported.Indexes.AdministrativeUnitMembersByMemberId['user-1'].Count | Should -Be 1
            $imported.Indexes.RiskyUsersByUserId['user-1'].Count | Should -Be 1
        }

        It 'reconciles overlapping RBAC and PIM active state into one canonical privilege relationship' {
            $snapshot = New-TestContractSnapshot `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Activated'; roleAssignmentOriginId='assignment-1'; roleAssignmentScheduleId='schedule-1'; startDateTime='2026-01-01T00:00:00Z'; endDateTime='2026-01-01T01:00:00Z'; memberType='Direct'; EvidenceId='ev-active' })
            $snapshot | Add-Member -NotePropertyName Indexes -NotePropertyValue (New-InspectorTenantSnapshotIndexes -Collections $snapshot.Collections -Evidence $snapshot.Evidence) -Force
            $resolution = [PSCustomObject]@{
                DirectMatches = @([PSCustomObject]@{
                    ObjectType = 'User'
                    Identifiers = [PSCustomObject]@{ ObjectId = 'user-1' }
                    RawObject = [PSCustomObject]@{ id='user-1'; displayName='User One'; userPrincipalName='user1@contoso.com'; EvidenceId='ev-user' }
                    EvidenceId = 'ev-user'
                })
                RelatedObjects = @()
            }

            $relationships = (Get-InspectorSnapshotRelationships -Resolution $resolution -TenantSnapshot $snapshot).Relationships
            $privilegedRelationships = @($relationships | Where-Object { $_.RelationshipType -in @('AssignedDirectoryRole','ActiveDirectoryRoleScheduleInstance') })

            $privilegedRelationships.Count | Should -Be 1
            $privilegedRelationships[0].RelationshipType | Should -Be 'ActiveDirectoryRoleScheduleInstance'
            $privilegedRelationships[0].Metadata.AssignmentType | Should -Be 'Activated'
            @($privilegedRelationships[0].Metadata.EvidenceIds) | Should -Contain 'ev-role'
            @($privilegedRelationships[0].Metadata.EvidenceIds) | Should -Contain 'ev-active'
            $privilegedRelationships[0].Metadata.EndDateTime | Should -Be '2026-01-01T01:00:00Z'
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

        It 'uses documented targeted role-assignment query parameters without top' {
            $script:targetedUris = [System.Collections.Generic.List[string]]::new()
            Mock New-InspectorSnapshotCollectionResult {
                param($Name, $Uri, $RequiredPermission, $EvidenceScope, $SubjectObjectType, $SubjectObjectId, $RuntimeTelemetry)
                $script:targetedUris.Add([string]$Uri)
                [PSCustomObject]@{
                    Status='Success'; Items=@(); Limitations=@();
                    Evidence=[PSCustomObject]@{ EvidenceId="ev-$Name"; QueryName=$Name; Status='Success'; Completeness='Complete' }
                }
            }
            $targetResolution = [PSCustomObject]@{
                Collections = [PSCustomObject]@{
                    ServicePrincipals = @([PSCustomObject]@{ id='sp-1' })
                    Users = @([PSCustomObject]@{ id='user-1' })
                    Groups = @()
                }
            }

            Get-InspectorTargetedTenantCollections -TargetResolution $targetResolution -RuntimeTelemetry $null | Out-Null

            $script:targetedUris | Should -Contain "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId%20eq%20%27user-1%27&`$expand=roleDefinition"
            @($script:targetedUris | Where-Object { $_ -like '*roleManagement/directory/roleAssignments*' -and $_ -like '*$top=999*' }).Count | Should -Be 0
            $script:targetedUris | Should -Contain "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId%20eq%20%27sp-1%27"
            $script:targetedUris | Should -Contain "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=resourceId%20eq%20%27sp-1%27"
            @($script:targetedUris | Where-Object { $_ -like '*oauth2PermissionGrants*' -and ($_ -like '*$top=*' -or $_ -like '*$select=*') }).Count | Should -Be 0
            (Get-InspectorTargetQueryDefinition -ObjectType 'ServicePrincipal' -Identity 'sp-1').Uri | Should -Match '\$top=100$'
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

        It 'emits deterministic privileged identity and risky-user drift records' {
            $previous = New-TestContractSnapshot `
                -SnapshotId 'previous' `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-old'; principalId='user-1'; roleDefinitionId='role-def-old'; directoryScopeId='/'; EvidenceId='ev-role-previous' }) `
                -RiskyUsers @([PSCustomObject]@{ id='user-1'; riskLevel='low'; riskState='atRisk'; riskDetail='none'; EvidenceId='ev-risk-previous' })

            $current = New-TestContractSnapshot `
                -SnapshotId 'current' `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-new'; principalId='user-1'; roleDefinitionId='role-def-new'; directoryScopeId='/administrativeUnits/au-1'; EvidenceId='ev-role-current' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-1'; principalId='user-1'; roleDefinitionId='role-def-new'; directoryScopeId='/administrativeUnits/au-1'; memberType='Direct'; assignmentType='Assigned'; roleAssignmentOriginId='assignment-new'; EvidenceId='ev-active-current' }) `
                -AdministrativeUnits @([PSCustomObject]@{ id='au-1'; displayName='AU One'; EvidenceId='ev-au-current' }) `
                -AdministrativeUnitMembers @([PSCustomObject]@{ AdministrativeUnitId='au-1'; Member=[PSCustomObject]@{ id='user-1' }; EvidenceId='ev-au-member-current' }) `
                -RiskyUsers @([PSCustomObject]@{ id='user-1'; riskLevel='high'; riskState='atRisk'; riskDetail='adminConfirmedUserCompromised'; EvidenceId='ev-risk-current' })

            $comparison = Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current

            $comparison.Changes.Category | Should -Contain 'DirectoryRoleAssignmentRemoved'
            $comparison.Changes.Category | Should -Contain 'DirectoryRoleAssignmentAdded'
            $comparison.Changes.Category | Should -Not -Contain 'ActiveDirectoryRoleScheduleInstanceAdded'
            $comparison.Changes.Category | Should -Contain 'AdministrativeUnitMemberAdded'
            $comparison.Changes.Category | Should -Contain 'RiskyUserChanged'
            @($comparison.Changes | Where-Object Category -eq 'RiskyUserChanged')[0].CurrentValue.RiskLevel | Should -Be 'high'
        }

        It 'suppresses an overlapping Assigned active schedule instance in comparison drift' {
            $snapshot = New-TestContractSnapshot `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-assigned'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Assigned'; roleAssignmentOriginId='assignment-1'; EvidenceId='ev-active' })

            $records = @(ConvertTo-InspectorSnapshotComparableRecords -TenantSnapshot $snapshot)

            @($records | Where-Object RecordType -eq 'DirectoryRoleAssignment').Count | Should -Be 1
            @($records | Where-Object RecordType -eq 'ActiveDirectoryRoleScheduleInstance').Count | Should -Be 0
        }

        It 'retains an overlapping Activated schedule instance as active PIM comparison state' {
            $snapshot = New-TestContractSnapshot `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-activated'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Activated'; roleAssignmentOriginId='assignment-1'; memberType='Direct'; EvidenceId='ev-active' })

            $records = @(ConvertTo-InspectorSnapshotComparableRecords -TenantSnapshot $snapshot)
            $active = @($records | Where-Object RecordType -eq 'ActiveDirectoryRoleScheduleInstance')

            @($records | Where-Object RecordType -eq 'DirectoryRoleAssignment').Count | Should -Be 1
            $active.Count | Should -Be 1
            $active[0].Value.AssignmentType | Should -Be 'Activated'
        }

        It 'emits active PIM drift when an overlapping assignment changes from Assigned to Activated' {
            $previous = New-TestContractSnapshot `
                -SnapshotId 'previous' `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role-previous' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-assigned'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Assigned'; roleAssignmentOriginId='assignment-1'; EvidenceId='ev-active-previous' })
            $current = New-TestContractSnapshot `
                -SnapshotId 'current' `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role-current' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-activated'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Activated'; roleAssignmentOriginId='assignment-1'; memberType='Direct'; EvidenceId='ev-active-current' })

            $comparison = Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current

            $comparison.Changes.Category | Should -Contain 'ActiveDirectoryRoleScheduleInstanceAdded'
            @($comparison.Changes | Where-Object Category -eq 'DirectoryRoleAssignmentChanged').Count | Should -Be 0
        }

        It 'emits active PIM removal when an overlapping activation ends' {
            $previous = New-TestContractSnapshot `
                -SnapshotId 'previous' `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role-previous' }) `
                -RoleAssignmentScheduleInstances @([PSCustomObject]@{ id='active-activated'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Activated'; roleAssignmentOriginId='assignment-1'; memberType='Direct'; EvidenceId='ev-active-previous' })
            $current = New-TestContractSnapshot `
                -SnapshotId 'current' `
                -DirectoryRoleAssignments @([PSCustomObject]@{ id='assignment-1'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; EvidenceId='ev-role-current' })

            $comparison = Compare-InspectorTenantSnapshots -PreviousSnapshot $previous -CurrentSnapshot $current

            $comparison.Changes.Category | Should -Contain 'ActiveDirectoryRoleScheduleInstanceRemoved'
            @($comparison.Changes | Where-Object Category -eq 'DirectoryRoleAssignmentChanged').Count | Should -Be 0
        }

        It 'retains unmatched active schedule instances regardless of assignment type' {
            $snapshot = New-TestContractSnapshot `
                -RoleAssignmentScheduleInstances @(
                    [PSCustomObject]@{ id='active-unmatched-assigned'; principalId='user-1'; roleDefinitionId='role-def-1'; directoryScopeId='/'; assignmentType='Assigned'; roleAssignmentOriginId='missing-assignment'; EvidenceId='ev-active-assigned' },
                    [PSCustomObject]@{ id='active-unmatched-activated'; principalId='user-1'; roleDefinitionId='role-def-2'; directoryScopeId='/'; assignmentType='Activated'; roleAssignmentOriginId='missing-activation'; EvidenceId='ev-active-activated' }
                )

            $records = @(ConvertTo-InspectorSnapshotComparableRecords -TenantSnapshot $snapshot)
            $active = @($records | Where-Object RecordType -eq 'ActiveDirectoryRoleScheduleInstance')

            $active.Count | Should -Be 2
            $active.Value.AssignmentType | Should -Contain 'Activated'
            $active.Value.AssignmentType | Should -Contain 'Assigned'
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
