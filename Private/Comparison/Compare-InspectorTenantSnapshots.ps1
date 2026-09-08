function Compare-InspectorTenantSnapshots {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$PreviousSnapshot,

        [Parameter(Mandatory)]
        [object]$CurrentSnapshot
    )

    Test-InspectorTenantSnapshotContract -TenantSnapshot $PreviousSnapshot -ThrowOnError | Out-Null
    Test-InspectorTenantSnapshotContract -TenantSnapshot $CurrentSnapshot -ThrowOnError | Out-Null

    $previousTenant = [string](Get-InspectorSnapshotProperty -InputObject $PreviousSnapshot -Name 'SourceTenantId')
    $currentTenant = [string](Get-InspectorSnapshotProperty -InputObject $CurrentSnapshot -Name 'SourceTenantId')
    if (-not [string]::IsNullOrWhiteSpace($previousTenant) -and
        -not [string]::IsNullOrWhiteSpace($currentTenant) -and
        $previousTenant -ne $currentTenant) {
        throw 'Snapshot comparison refused because SourceTenantId differs.'
    }

    $previousScope = Get-InspectorSnapshotScopeSignature -TenantSnapshot $PreviousSnapshot
    $currentScope = Get-InspectorSnapshotScopeSignature -TenantSnapshot $CurrentSnapshot
    if ($previousScope -ne $currentScope) {
        throw "Snapshot comparison refused because collection scope differs. Previous=$previousScope Current=$currentScope"
    }

    $previousRecords = @(ConvertTo-InspectorSnapshotComparableRecords -TenantSnapshot $PreviousSnapshot)
    $currentRecords = @(ConvertTo-InspectorSnapshotComparableRecords -TenantSnapshot $CurrentSnapshot)
    $previousByKey = @{}
    $currentByKey = @{}

    foreach ($record in $previousRecords) {
        $previousByKey[[string](Get-InspectorSnapshotProperty -InputObject $record -Name 'SemanticKey')] = $record
    }
    foreach ($record in $currentRecords) {
        $currentByKey[[string](Get-InspectorSnapshotProperty -InputObject $record -Name 'SemanticKey')] = $record
    }

    $changes = [System.Collections.Generic.List[object]]::new()
    $keys = @($previousByKey.Keys + $currentByKey.Keys | Sort-Object -Unique)

    foreach ($key in $keys) {
        $before = if ($previousByKey.ContainsKey($key)) { $previousByKey[$key] } else { $null }
        $after = if ($currentByKey.ContainsKey($key)) { $currentByKey[$key] } else { $null }
        $beforeFingerprint = [string](Get-InspectorSnapshotProperty -InputObject $before -Name 'Fingerprint')
        $afterFingerprint = [string](Get-InspectorSnapshotProperty -InputObject $after -Name 'Fingerprint')

        if ($null -ne $before -and $null -ne $after -and $beforeFingerprint -eq $afterFingerprint) {
            continue
        }

        $changeType = if ($null -eq $before) { 'Added' } elseif ($null -eq $after) { 'Removed' } else { 'Changed' }
        $record = if ($null -ne $after) { $after } else { $before }
        $recordType = [string](Get-InspectorSnapshotProperty -InputObject $record -Name 'RecordType')
        $category = switch ($recordType) {
            'Owner' {
                if ($changeType -eq 'Added') { 'OwnerAdded' } elseif ($changeType -eq 'Removed') { 'OwnerRemoved' } else { 'OwnerChanged' }
            }
            'Credential' {
                if ($changeType -eq 'Added') { 'CredentialAdded' } elseif ($changeType -eq 'Removed') { 'CredentialRemoved' } else { 'CredentialChanged' }
            }
            'GroupMember' {
                if ($changeType -eq 'Added') { 'GroupMemberAdded' } elseif ($changeType -eq 'Removed') { 'GroupMemberRemoved' } else { 'GroupMemberChanged' }
            }
            'Permission' {
                if ($changeType -eq 'Added') { 'PermissionAdded' } elseif ($changeType -eq 'Removed') { 'PermissionRemoved' } else { 'PermissionChanged' }
            }
            default { "$recordType$changeType" }
        }

        $previousEvidenceIds = if ($null -ne $before) {
            @(Get-InspectorSnapshotProperty -InputObject $before -Name 'EvidenceIds')
        }
        else { @() }
        $currentEvidenceIds = if ($null -ne $after) {
            @(Get-InspectorSnapshotProperty -InputObject $after -Name 'EvidenceIds')
        }
        else { @() }
        $baselineState = if ($changeType -eq 'Added') { 'New' } elseif ($changeType -eq 'Removed') { 'Resolved' } else { 'Changed' }
        $changeFingerprint = "$changeType|$key|$beforeFingerprint|$afterFingerprint"

        $changes.Add([PSCustomObject][ordered]@{
            PSTypeName          = 'EntraObjectInspector.SnapshotChange'
            SchemaVersion       = '1.0.0'
            ChangeId            = "CHANGE-$(Get-InspectorComparisonHash -Value $changeFingerprint)"
            ChangeType          = $changeType
            Category            = $category
            SemanticKey         = $key
            SubjectObjectType   = [string](Get-InspectorSnapshotProperty -InputObject $record -Name 'SubjectObjectType')
            SubjectObjectId     = [string](Get-InspectorSnapshotProperty -InputObject $record -Name 'SubjectObjectId')
            RelatedObjectId     = [string](Get-InspectorSnapshotProperty -InputObject $record -Name 'RelatedObjectId')
            PreviousValue       = if ($null -ne $before) { Get-InspectorSnapshotProperty -InputObject $before -Name 'Value' } else { $null }
            CurrentValue        = if ($null -ne $after) { Get-InspectorSnapshotProperty -InputObject $after -Name 'Value' } else { $null }
            PreviousEvidenceIds = @($previousEvidenceIds)
            CurrentEvidenceIds  = @($currentEvidenceIds)
            BaselineState       = $baselineState
        })
    }

    $addedCount = @($changes | Where-Object { $_.ChangeType -eq 'Added' }).Count
    $removedCount = @($changes | Where-Object { $_.ChangeType -eq 'Removed' }).Count
    $changedCount = @($changes | Where-Object { $_.ChangeType -eq 'Changed' }).Count
    $currentChangedCount = @($changes | Where-Object { $_.ChangeType -ne 'Removed' }).Count

    return [PSCustomObject][ordered]@{
        PSTypeName           = 'EntraObjectInspector.SnapshotComparison'
        SchemaVersion        = '1.0.0'
        PreviousSnapshotId   = [string](Get-InspectorSnapshotProperty -InputObject $PreviousSnapshot -Name 'SnapshotId')
        CurrentSnapshotId    = [string](Get-InspectorSnapshotProperty -InputObject $CurrentSnapshot -Name 'SnapshotId')
        ScopeSignature       = $currentScope
        ChangeCount          = $changes.Count
        AddedCount           = $addedCount
        RemovedCount         = $removedCount
        ChangedCount         = $changedCount
        UnchangedRecordCount = [math]::Max(0, ($currentRecords.Count - $currentChangedCount))
        Changes              = @($changes | Sort-Object Category, SemanticKey)
    }
}
