function Invoke-InspectorAssessmentPolicy {
    [CmdletBinding()]
    param (
        [object[]]$Observations = @(),
        [AllowNull()]
        [object]$SnapshotComparison,
        [string]$RulePackPath,
        [string]$BaselinePath
    )

    $rulePack = Import-InspectorRulePack -Path $RulePackPath
    $baseline = Import-InspectorAssessmentBaseline -Path $BaselinePath
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($observation in @($Observations)) {
        if ($null -ne $observation) { $all.Add($observation) }
    }

    if ($null -ne $rulePack) {
        $rulePackId = [string](Get-InspectorSnapshotProperty -InputObject $rulePack -Name 'RulePackId')
        foreach ($rule in @(Get-InspectorSnapshotProperty -InputObject $rulePack -Name 'Rules')) {
            $sourceRuleId = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'RuleId')
            $category = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Category')
            $title = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Title')
            $description = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Description')
            $severity = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Severity')
            $confidence = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Confidence')
            $microsoftReference = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'MicrosoftReference')
            $whyItMatters = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'WhyItMatters')
            $recommendedAction = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'RecommendedAction')
            $signalDisposition = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'SignalDisposition')

            if ([string]::IsNullOrWhiteSpace($confidence)) { $confidence = 'High' }
            if ([string]::IsNullOrWhiteSpace($microsoftReference)) { $microsoftReference = 'Custom rule pack policy.' }
            if ([string]::IsNullOrWhiteSpace($signalDisposition)) {
                $signalDisposition = if ($severity -eq 'Informational') { 'Contextual' } elseif ($severity -eq 'Low') { 'Review' } else { 'Actionable' }
            }

            foreach ($source in @($Observations)) {
                if ($null -eq $source) { continue }
                $matched = $true
                foreach ($predicate in @(Get-InspectorSnapshotProperty -InputObject $rule -Name 'Predicates')) {
                    if (-not (Test-InspectorRulePredicate -Observation $source -Predicate $predicate)) {
                        $matched = $false
                        break
                    }
                }
                if (-not $matched) { continue }

                $affected = Get-InspectorSnapshotProperty -InputObject $source -Name 'AffectedObject'
                if ($null -eq $affected) { continue }

                $metadata = @{
                    RulePackId          = $rulePackId
                    CustomRule          = $true
                    SourceObservationId = [string](Get-InspectorSnapshotProperty -InputObject $source -Name 'ObservationId')
                    SignalDisposition   = $signalDisposition
                }

                $custom = New-InspectorSecurityObservation `
                    -Category $category `
                    -Title $title `
                    -Description $description `
                    -Severity $severity `
                    -Confidence $confidence `
                    -AffectedObject $affected `
                    -EvidenceIds @(Get-InspectorSnapshotProperty -InputObject $source -Name 'EvidenceIds') `
                    -MicrosoftReference $microsoftReference `
                    -WhyItMatters $whyItMatters `
                    -Recommendation $recommendedAction `
                    -SourceRuleIds @($sourceRuleId) `
                    -Metadata $metadata
                $all.Add($custom)
            }
        }
    }

    $baselineEntries = @(Get-InspectorBaselineEntries -Baseline $baseline)
    $acceptedObservationKeys = @{}
    $acceptedComparable = @{}
    foreach ($entry in $baselineEntries) {
        $kind = [string](Get-InspectorSnapshotProperty -InputObject $entry -Name 'Kind')
        $key = [string](Get-InspectorSnapshotProperty -InputObject $entry -Name 'SemanticKey')
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if ($kind -eq 'ComparableRecord') { $acceptedComparable[$key] = $entry }
        else { $acceptedObservationKeys[$key] = $entry }
    }

    foreach ($observation in @($all)) {
        $key = [string](Get-InspectorSnapshotProperty -InputObject $observation -Name 'SemanticKey')
        $state = if ($acceptedObservationKeys.ContainsKey($key)) { 'Accepted' } else { 'Existing' }
        $observation | Add-Member -NotePropertyName 'BaselineState' -NotePropertyValue $state -Force
    }

    if ($null -ne $SnapshotComparison) {
        foreach ($change in @(Get-InspectorSnapshotProperty -InputObject $SnapshotComparison -Name 'Changes')) {
            $key = [string](Get-InspectorSnapshotProperty -InputObject $change -Name 'SemanticKey')
            $changeType = [string](Get-InspectorSnapshotProperty -InputObject $change -Name 'ChangeType')
            if (-not $acceptedComparable.ContainsKey($key) -or $changeType -eq 'Removed') { continue }

            $entry = $acceptedComparable[$key]
            $acceptedFingerprint = [string](Get-InspectorSnapshotProperty -InputObject $entry -Name 'Fingerprint')
            $currentValue = Get-InspectorSnapshotProperty -InputObject $change -Name 'CurrentValue'
            $currentFingerprint = if ($null -ne $currentValue) {
                Get-InspectorComparisonHash -Value ($currentValue | ConvertTo-Json -Depth 30 -Compress)
            }
            else { '' }

            if ([string]::IsNullOrWhiteSpace($acceptedFingerprint) -or $acceptedFingerprint -eq $currentFingerprint) {
                $change | Add-Member -NotePropertyName 'BaselineState' -NotePropertyValue 'Accepted' -Force
            }
        }
    }

    $customObservationCount = @(
        $all |
            Where-Object {
                (Get-InspectorSnapshotProperty -InputObject (Get-InspectorSnapshotProperty -InputObject $_ -Name 'Metadata') -Name 'CustomRule') -eq $true
            }
    ).Count
    $acceptedObservationCount = @(
        $all | Where-Object { [string](Get-InspectorSnapshotProperty -InputObject $_ -Name 'BaselineState') -eq 'Accepted' }
    ).Count

    return [PSCustomObject][ordered]@{
        PSTypeName                = 'EntraObjectInspector.AssessmentPolicyResult'
        SchemaVersion             = '1.0.0'
        RulePackApplied           = $null -ne $rulePack
        BaselineApplied           = $null -ne $baseline
        RulePackId                = if ($null -ne $rulePack) { [string](Get-InspectorSnapshotProperty -InputObject $rulePack -Name 'RulePackId') } else { '' }
        ObservationCount          = $all.Count
        CustomObservationCount    = $customObservationCount
        AcceptedObservationCount  = $acceptedObservationCount
        Observations              = @($all)
        SnapshotComparison        = $SnapshotComparison
    }
}
