function Import-InspectorAssessmentBaseline {
    [CmdletBinding()]
    param (
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Assessment baseline was not found: $Path"
    }

    $baseline = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([string](Get-InspectorSnapshotProperty -InputObject $baseline -Name 'ContractName') -ne 'EntraObjectInspector.AssessmentBaseline') {
        throw 'Baseline ContractName must be EntraObjectInspector.AssessmentBaseline.'
    }
    if ([string](Get-InspectorSnapshotProperty -InputObject $baseline -Name 'SchemaVersion') -ne '1.0.0') {
        throw 'Unsupported assessment baseline SchemaVersion.'
    }
    if ($null -eq $baseline.PSObject.Properties['Entries']) {
        throw 'Assessment baseline requires Entries.'
    }

    $seen = @{}
    foreach ($entry in @(Get-InspectorSnapshotProperty -InputObject $baseline -Name 'Entries')) {
        $kind = [string](Get-InspectorSnapshotProperty -InputObject $entry -Name 'Kind')
        $semanticKey = [string](Get-InspectorSnapshotProperty -InputObject $entry -Name 'SemanticKey')
        if ($kind -notin @('Observation','ComparableRecord')) {
            throw "Baseline entry Kind '$kind' is unsupported. Use Observation or ComparableRecord."
        }
        if ([string]::IsNullOrWhiteSpace($semanticKey)) {
            throw 'Every baseline entry requires SemanticKey.'
        }
        $dedupeKey = "$kind|$semanticKey"
        if ($seen.ContainsKey($dedupeKey)) {
            throw "Duplicate baseline entry '$dedupeKey'."
        }
        $seen[$dedupeKey] = $true
    }

    return $baseline
}

function Import-InspectorRulePack {
    [CmdletBinding()]
    param (
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Rule pack was not found: $Path"
    }

    $pack = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([string](Get-InspectorSnapshotProperty -InputObject $pack -Name 'ContractName') -ne 'EntraObjectInspector.RulePack') {
        throw 'Rule pack ContractName must be EntraObjectInspector.RulePack.'
    }
    if ([string](Get-InspectorSnapshotProperty -InputObject $pack -Name 'SchemaVersion') -ne '1.0.0') {
        throw 'Unsupported rule-pack SchemaVersion.'
    }

    $rulePackId = [string](Get-InspectorSnapshotProperty -InputObject $pack -Name 'RulePackId')
    if ([string]::IsNullOrWhiteSpace($rulePackId)) { throw 'RulePackId is required.' }
    if ($null -eq $pack.PSObject.Properties['Rules']) {
        throw 'Rule pack requires Rules.'
    }

    $ids = @{}
    foreach ($rule in @(Get-InspectorSnapshotProperty -InputObject $pack -Name 'Rules')) {
        $id = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'RuleId')
        if ([string]::IsNullOrWhiteSpace($id)) { throw 'Every rule-pack rule requires RuleId.' }
        if ($ids.ContainsKey($id)) { throw "Duplicate rule-pack RuleId '$id'." }
        $ids[$id] = $true

        foreach ($requiredField in @('Title','Description','WhyItMatters','RecommendedAction')) {
            if ([string]::IsNullOrWhiteSpace([string](Get-InspectorSnapshotProperty -InputObject $rule -Name $requiredField))) {
                throw "Rule '$id' requires $requiredField."
            }
        }

        $category = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Category')
        if ($category -notin @('IdentityGovernance','Credentials','Permissions','ServicePrincipal','Consent','Users','Groups')) {
            throw "Rule '$id' has unsupported Category '$category'."
        }

        $severity = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Severity')
        if ($severity -notin @('Informational','Low','Medium','High')) {
            throw "Rule '$id' has unsupported Severity '$severity'."
        }

        $confidence = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'Confidence')
        if (-not [string]::IsNullOrWhiteSpace($confidence) -and $confidence -notin @('High','Medium','Low')) {
            throw "Rule '$id' has unsupported Confidence '$confidence'."
        }

        $signalDisposition = [string](Get-InspectorSnapshotProperty -InputObject $rule -Name 'SignalDisposition')
        if (-not [string]::IsNullOrWhiteSpace($signalDisposition) -and $signalDisposition -notin @('Actionable','Review','Contextual')) {
            throw "Rule '$id' has unsupported SignalDisposition '$signalDisposition'."
        }

        $predicates = @(Get-InspectorSnapshotProperty -InputObject $rule -Name 'Predicates')
        if ($predicates.Count -eq 0) { throw "Rule '$id' requires at least one predicate." }
        foreach ($predicate in $predicates) {
            $path = [string](Get-InspectorSnapshotProperty -InputObject $predicate -Name 'Path')
            $operator = [string](Get-InspectorSnapshotProperty -InputObject $predicate -Name 'Operator')
            if ([string]::IsNullOrWhiteSpace($path)) { throw "Rule '$id' contains a predicate without Path." }
            if ($operator -notin @('Equals','NotEquals','Contains','In','Exists')) {
                throw "Rule '$id' uses unsupported predicate operator '$operator'."
            }
        }
    }

    return $pack
}

function Test-InspectorRulePredicate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Observation,

        [Parameter(Mandatory)]
        [object]$Predicate
    )

    $path = [string](Get-InspectorSnapshotProperty -InputObject $Predicate -Name 'Path')
    $operator = [string](Get-InspectorSnapshotProperty -InputObject $Predicate -Name 'Operator')
    $expected = Get-InspectorSnapshotProperty -InputObject $Predicate -Name 'Value'
    $value = $Observation

    foreach ($segment in @($path -split '\.')) {
        $value = Get-InspectorSnapshotProperty -InputObject $value -Name $segment
        if ($null -eq $value) { break }
    }

    switch ($operator) {
        'Exists' { return $null -ne $value }
        'Equals' { return [string]$value -eq [string]$expected }
        'NotEquals' { return [string]$value -ne [string]$expected }
        'Contains' { return [string]$value -like "*$([string]$expected)*" }
        'In' { return [string]$value -in @($expected | ForEach-Object { [string]$_ }) }
    }

    return $false
}

function Get-InspectorBaselineEntries {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [object]$Baseline
    )

    if ($null -eq $Baseline) { return @() }
    return @(
        (Get-InspectorSnapshotProperty -InputObject $Baseline -Name 'Entries') |
            Where-Object { $null -ne $_ }
    )
}
