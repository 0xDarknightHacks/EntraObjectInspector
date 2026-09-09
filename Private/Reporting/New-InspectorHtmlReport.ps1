function Get-InspectorReportSharedCss {
    [CmdletBinding()]
    param ()

    return @'
:root {
  color-scheme: dark;
  --font: "Segoe UI Variable Text","Segoe UI",Inter,system-ui,Arial,sans-serif;
  --radius: 10px;
  --radius-sm: 7px;
  --bg: #14181c;
  --panel: #1b2126;
  --panel-soft: #212830;
  --text: #e7ecef;
  --muted: #a6b0b8;
  --faint: #74818b;
  --line: #2b333b;
  --line-soft: #232a31;
  --accent: #4fd1c5;
  --accent-strong: #6ee8dc;
  --accent-soft: rgba(79, 209, 197, .14);
  --high: #e2716b;
  --medium: #e0a94c;
  --low: #79a6d2;
  --info: #4fd1c5;
  --high-bg: rgba(226, 113, 107, .14);
  --medium-bg: rgba(224, 169, 76, .14);
  --low-bg: rgba(121, 166, 210, .14);
  --info-bg: rgba(79, 209, 197, .14);
  --highlight-bg: #fde68a;
  --highlight-text: #111827;
  --highlight-border: #f59e0b;
  --shadow: 0 4px 18px rgba(0, 0, 0, .35);
}

[data-theme="light"] {
  color-scheme: light;
  --bg: #f5f7f8;
  --panel: #ffffff;
  --panel-soft: #eef1f2;
  --text: #1b2126;
  --muted: #4c565d;
  --faint: #77828a;
  --line: #dde3e6;
  --line-soft: #e6eaec;
  --accent: #0f8c80;
  --accent-strong: #0b6b62;
  --accent-soft: rgba(15, 140, 128, .10);
  --high: #b64842;
  --medium: #a8701c;
  --low: #35618f;
  --info: #0f8c80;
  --high-bg: rgba(182, 72, 66, .09);
  --medium-bg: rgba(168, 112, 28, .10);
  --low-bg: rgba(53, 97, 143, .09);
  --info-bg: rgba(15, 140, 128, .10);
  --highlight-bg: #fef3c7;
  --highlight-text: #111827;
  --highlight-border: #d97706;
  --shadow: 0 2px 10px rgba(20, 30, 35, .08);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: var(--font);
  font-size: 15.5px;
  line-height: 1.5;
  background: var(--bg);
  color: var(--text);
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); }
.shell { max-width: 980px; margin: 0 auto; padding: 28px 20px 80px; }
.hero { border-bottom: 1px solid var(--line-soft); }
.hero-grid {
  max-width: 980px;
  margin: 0 auto;
  padding: 28px 20px 20px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 16px;
  align-items: start;
}
.brand { color: var(--muted); font-size: 14.5px; font-weight: 600; letter-spacing: .2px; }
h1 { margin: 4px 0 8px; font-size: 22px; line-height: 1.15; font-weight: 650; letter-spacing: 0; }
h2 { margin: 0 0 14px; font-size: 15.5px; font-weight: 650; letter-spacing: 0; }
h3 { margin: 0; font-size: 13.2px; font-weight: 650; letter-spacing: 0; }
.hero p { margin: 8px 0 0; max-width: 780px; color: var(--muted); }
.hero-meta, .finding-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; justify-content: end; }
button, .filter-button {
  min-height: 34px;
  border: 1px solid var(--line);
  background: var(--panel);
  color: var(--muted);
  border-radius: var(--radius-sm);
  padding: 6px 12px;
  font: inherit;
  font-size: 12.8px;
  font-weight: 600;
  cursor: pointer;
}
button:hover, .filter-button:hover, .filter-button.is-active { border-color: var(--accent); color: var(--accent); background: var(--accent-soft); }
#themeToggle { border-radius: 999px; }
.pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid var(--line);
  white-space: nowrap;
}
.severity-high, .status-danger { background: var(--high-bg); color: var(--high); }
.severity-medium, .status-warning { background: var(--medium-bg); color: var(--medium); }
.severity-low, .status-info { background: var(--low-bg); color: var(--low); }
.severity-info, .status-success { background: var(--info-bg); color: var(--info); }
.status-default { background: var(--panel-soft); color: var(--muted); }
.metric-grid, .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 18px 0 22px; }
.metric-card, .finding-card, .category-card, .trust-box, .section {
  background: var(--panel);
  border: 1px solid var(--line-soft);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.metric-card { padding: 12px; }
.metric-label { color: var(--faint); font-size: 11.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .4px; }
.metric-value { margin-top: 3px; font-size: 20px; font-weight: 650; }
.metric-hint { margin-top: 5px; color: var(--faint); font-size: 12.5px; }
.section { margin: 0 0 34px; padding: 0; background: transparent; border: 0; box-shadow: none; }
.section-header { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; margin-bottom: 10px; }
.muted { color: var(--muted); }
.empty-state { margin: 0; padding: 14px; color: var(--muted); background: var(--panel); border: 1px dashed var(--line-soft); border-radius: var(--radius); }
.filter-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
.investigation-bar {
  display: grid;
  grid-template-columns: minmax(240px, 1fr) minmax(150px, .35fr) auto;
  gap: 8px;
  margin-bottom: 10px;
}
.investigation-bar input, .investigation-bar select {
  min-height: 38px;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  background: var(--panel-soft);
  color: var(--text);
  padding: 8px 10px;
  font: inherit;
}
.finding-list { display: grid; gap: 12px; }
.finding-card { padding: 14px 16px; border-left: 3px solid var(--line); }
.finding-card[data-severity="High"] { border-left-color: var(--high); }
.finding-card[data-severity="Medium"] { border-left-color: var(--medium); }
.finding-card[data-severity="Low"] { border-left-color: var(--low); }
.finding-card[data-severity="Informational"] { border-left-color: var(--info); }
.finding-card[hidden] { display: none; }
.finding-top { display: flex; justify-content: space-between; gap: 12px; align-items: start; }
.finding-title { margin: 8px 0 5px; font-weight: 600; font-size: 14.8px; }
.finding-action { margin-top: 10px; padding: 10px; background: var(--panel-soft); border-radius: var(--radius-sm); font-size: 13.4px; }
mark.search-hit {
  background: var(--highlight-bg);
  color: var(--highlight-text);
  border: 1px solid var(--highlight-border);
  border-radius: 4px;
  padding: 0 2px;
  font-weight: 800;
}
details.evidence { margin-top: 10px; border-top: 1px solid var(--line); padding-top: 9px; }
details.evidence > summary { cursor: pointer; color: var(--muted); font-weight: 600; font-size: 12.6px; list-style: none; }
details.evidence > summary::-webkit-details-marker { display: none; }
details.evidence > summary::before { content: ">"; display: inline-block; margin-right: 6px; color: var(--faint); transition: transform .12s ease; }
details.evidence[open] > summary::before { transform: rotate(90deg); }
.evidence-list { margin: 9px 0 0; padding: 11px 13px 11px 28px; color: var(--muted); font-size: 13px; background: var(--panel-soft); border: 1px solid var(--line-soft); border-radius: var(--radius-sm); }
.official-references { margin-top: 8px; color: var(--text); }
.official-references ul { margin: 6px 0 0; padding-left: 18px; }
.official-references li { margin-bottom: 5px; }
.action-list { margin: 0; padding-left: 22px; }
.action-list li { margin-bottom: 10px; }
.category-grid, .trust-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; }
.category-card, .trust-box { padding: 13px 14px; }
.category-count { font-size: 19px; font-weight: 650; margin-top: 4px; color: var(--accent); }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.table-wrap { overflow-x: auto; }
th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 9px; vertical-align: top; }
th { color: var(--muted); background: var(--panel-soft); }
.footer { color: var(--muted); text-align: center; font-size: 12.5px; padding: 22px 24px 30px; }
@media (max-width: 760px) {
  .hero-grid { grid-template-columns: 1fr; }
  .toolbar { justify-content: start; }
  .investigation-bar { grid-template-columns: 1fr; }
  .shell { padding: 14px; }
}
@media print {
  :root, [data-theme="light"] {
    --bg: #ffffff; --panel: #ffffff; --panel-soft: #f7f7f7; --text: #111827; --muted: #4b5563; --faint: #6b7280; --line: #d1d5db; --line-soft: #e5e7eb; --shadow: none;
  }
  .toolbar, .filter-row { display: none; }
  .hero, .section, .metric-card, .finding-card, .category-card, .trust-box { box-shadow: none; break-inside: avoid; }
  details.evidence:not([open]) > * { display: block; }
  mark.search-hit { border: 1px solid #92400e; background: #fef3c7; color: #111827; }
}
.report-nav { display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end; }
.report-nav .pill { text-decoration:none; }
.report-nav .is-active { border-color:var(--accent); color:var(--accent); background:var(--accent-soft); }
.filter { margin:0 0 14px; width:100%; min-height:38px; border:1px solid var(--line); border-radius:var(--radius-sm); background:var(--panel-soft); color:var(--text); padding:8px 10px; font:inherit; }
.card { background:var(--panel); border:1px solid var(--line-soft); border-radius:var(--radius); box-shadow:var(--shadow); padding:14px 16px; margin:0 0 12px; }

'@
}

function New-InspectorReportHtmlDocument {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Body,
        [string]$Subtitle = '',
        [string]$GeneratedAt = '',
        [string]$ReportId = '',
        [string]$PostureLabel = '',
        [string]$MainReportFileName = '',
        [string]$EvidenceReportFileName = '',
        [string]$DiagnosticsReportFileName = '',
        [ValidateSet('Assessment','Evidence','Diagnostics')][string]$ActiveView = 'Assessment',
        [string]$Script = ''
    )

    $encodedTitle = ConvertTo-InspectorHtmlEncodedText $Title
    $encodedSubtitle = ConvertTo-InspectorHtmlEncodedText $Subtitle
    $css = Get-InspectorReportSharedCss

    $metaItems = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($GeneratedAt)) {
        $metaItems.Add('<span class="pill">Generated ' + (ConvertTo-InspectorHtmlEncodedText $GeneratedAt) + ' UTC</span>')
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportId)) {
        $metaItems.Add('<span class="pill">Report ID: ' + (ConvertTo-InspectorHtmlEncodedText $ReportId) + '</span>')
    }
    if (-not [string]::IsNullOrWhiteSpace($PostureLabel)) {
        $metaItems.Add('<span class="pill ' + (Get-InspectorReportStatusClass -Value $PostureLabel) + '">Tenant posture: ' + (ConvertTo-InspectorHtmlEncodedText $PostureLabel) + '</span>')
    }
    $heroMetaHtml = if ($metaItems.Count -gt 0) { '<div class="hero-meta">' + ($metaItems -join '') + '</div>' } else { '' }

    $navItems = [System.Collections.Generic.List[string]]::new()
    foreach ($navDefinition in @(
        [PSCustomObject]@{ Label = 'Assessment'; FileName = $MainReportFileName; View = 'Assessment' }
        [PSCustomObject]@{ Label = 'Evidence'; FileName = $EvidenceReportFileName; View = 'Evidence' }
        [PSCustomObject]@{ Label = 'Diagnostics'; FileName = $DiagnosticsReportFileName; View = 'Diagnostics' }
    )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$navDefinition.FileName)) {
            $activeClass = if ($ActiveView -eq $navDefinition.View) { ' is-active' } else { '' }
            $navItems.Add('<a class="pill' + $activeClass + '" href="' + (ConvertTo-InspectorHtmlEncodedText $navDefinition.FileName) + '">' + $navDefinition.Label + '</a>')
        }
    }
    $navItems.Add('<a class="pill" href="https://entra.microsoft.com/" target="_blank" rel="noopener noreferrer">Open Microsoft Entra admin center</a>')
    $navigationHtml = '<nav class="report-nav" aria-label="Report navigation">' + ($navItems -join '') + '<button id="themeToggle" type="button">Toggle theme</button></nav>'

    $subtitleHtml = if (-not [string]::IsNullOrWhiteSpace($encodedSubtitle)) { '<p>' + $encodedSubtitle + '</p>' } else { '' }
    $scriptHtml = if (-not [string]::IsNullOrWhiteSpace($Script)) { "<script>`n$Script`n</script>" } else { '' }

    return @"
<!doctype html>
<html lang="en" data-theme="dark" data-eoi-report-shell="1.0">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$encodedTitle</title>
  <style>
$css
  </style>
</head>
<body>
  <header class="hero">
    <div class="hero-grid">
      <div>
        <div class="brand">Entra Object Inspector</div>
        <h1>$encodedTitle</h1>
        $heroMetaHtml
        $subtitleHtml
      </div>
      <div class="toolbar">$navigationHtml</div>
    </div>
  </header>
  <main class="shell">
$Body
  </main>
  <footer class="footer">Generated by Entra Object Inspector. Static HTML report. Offline compatible.</footer>
  $scriptHtml
</body>
</html>
"@
}

function New-InspectorHtmlReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $title = ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportProperty -InputObject $ReportModel -Name 'AssessmentName')
    $generatedAt = ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportProperty -InputObject $ReportModel -Name 'GeneratedAt')
    $reportId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'ReportId')

    if ([string]::IsNullOrWhiteSpace($reportId)) {
        $reportId = 'Not provided'
    }

    $posture = Get-InspectorReportProperty -InputObject $ReportModel -Name 'TenantPosture'
    $postureLabel = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $posture -Name 'Label')

    if ([string]::IsNullOrWhiteSpace($postureLabel)) {
        $postureLabel = 'Not available'
    }

    $script = @'
(function () {
  var globalSearch = null;
  var severityFilter = null;
  var findingFilterDebounce = null;
  var printOpenedDetails = [];
  function sortTable(table, columnIndex) {
    return { table: table, columnIndex: columnIndex };
  }
  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  function clearSearchHighlights() {
    document.querySelectorAll('mark.search-hit').forEach(function (mark) {
      var text = document.createTextNode(mark.textContent || '');
      mark.parentNode.replaceChild(text, mark);
      if (text.parentNode) text.parentNode.normalize();
    });
  }
  function highlightTextNode(node, pattern) {
    var text = node.nodeValue || '';
    var match = text.match(pattern);
    if (!match) return;
    var wrapper = document.createDocumentFragment();
    var lastIndex = 0;
    text.replace(pattern, function (value, _capture, offset) {
      if (offset > lastIndex) wrapper.appendChild(document.createTextNode(text.slice(lastIndex, offset)));
      var mark = document.createElement('mark');
      mark.className = 'search-hit';
      mark.textContent = value;
      wrapper.appendChild(mark);
      lastIndex = offset + value.length;
      return value;
    });
    if (lastIndex < text.length) wrapper.appendChild(document.createTextNode(text.slice(lastIndex)));
    node.parentNode.replaceChild(wrapper, node);
  }
  function highlightSearchMatches(query) {
    clearSearchHighlights();
    if (!query) return;
    var pattern = new RegExp('(' + escapeRegExp(query) + ')', 'ig');
    document.querySelectorAll('.finding-card:not([hidden]) [data-highlight-target]').forEach(function (element) {
      if (element.closest('pre, code, .raw-evidence')) return;
      var walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, {
        acceptNode: function (node) {
          return node.parentNode && node.parentNode.nodeName.toLowerCase() !== 'mark'
            ? NodeFilter.FILTER_ACCEPT
            : NodeFilter.FILTER_REJECT;
        }
      });
      var nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach(function (node) { highlightTextNode(node, pattern); });
    });
  }
  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('eoi-theme', theme); } catch (error) {}
  }
  function getFilterState() {
    var activeSeverity = document.querySelector('[data-filter-severity].is-active');
    return {
      query: ((document.getElementById('findingSearch') || {}).value || '').toLowerCase().trim(),
      severity: activeSeverity ? activeSeverity.getAttribute('data-filter-severity') : 'All',
      objectType: ((document.getElementById('objectTypeFilter') || {}).value || '')
    };
  }
  function updateFindingResultCount(visible, total) {
    var resultCount = document.getElementById('findingResultCount');
    if (resultCount) resultCount.textContent = visible + ' of ' + total + ' grouped findings';
    var emptyState = document.getElementById('noFindingResults');
    if (emptyState) emptyState.hidden = visible !== 0;
  }
  function applyFindingFilters() {
    var state = getFilterState();
    var cards = document.querySelectorAll('.finding-card');
    var visible = 0;
    cards.forEach(function (card) {
      var matchesSearch = !state.query || (card.getAttribute('data-search') || '').indexOf(state.query) !== -1;
      var matchesSeverity = state.severity === 'All' || (card.getAttribute('data-severity') || '') === state.severity;
      var objectTypes = (card.getAttribute('data-object-types') || card.getAttribute('data-object-type') || '').split(/\s+/);
      var matchesObjectType = !state.objectType || objectTypes.indexOf(state.objectType) !== -1;
      var isVisible = matchesSearch && matchesSeverity && matchesObjectType;
      card.hidden = !isVisible;
      if (isVisible) visible += 1;
    });
    updateFindingResultCount(visible, cards.length);
    highlightSearchMatches(state.query);
  }
  function scheduleFindingFilters() {
    window.clearTimeout(findingFilterDebounce);
    findingFilterDebounce = window.setTimeout(applyFindingFilters, 125);
  }
  function applyFindingFilter(severity) {
    document.querySelectorAll('[data-filter-severity]').forEach(function (button) {
      button.classList.toggle('is-active', button.getAttribute('data-filter-severity') === severity);
    });
    applyFindingFilters();
  }
  document.addEventListener('DOMContentLoaded', function () {
    var saved = 'dark';
    try { saved = localStorage.getItem('eoi-theme') || 'dark'; } catch (error) {}
    setTheme(saved);
    var themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', function () {
        setTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
      });
    }
    document.querySelectorAll('[data-filter-severity]').forEach(function (button) {
      button.addEventListener('click', function () {
        applyFindingFilter(button.getAttribute('data-filter-severity'));
      });
    });
    ['findingSearch', 'objectTypeFilter'].forEach(function (id) {
      var control = document.getElementById(id);
      if (control) {
        control.addEventListener('input', scheduleFindingFilters);
        control.addEventListener('change', scheduleFindingFilters);
      }
    });
    var clearFilters = document.getElementById('clearFindingFilters');
    if (clearFilters) {
      clearFilters.addEventListener('click', function () {
        var search = document.getElementById('findingSearch');
        var objectType = document.getElementById('objectTypeFilter');
        if (search) search.value = '';
        if (objectType) objectType.value = '';
        applyFindingFilter('All');
      });
    }
    window.addEventListener('beforeprint', function () {
      printOpenedDetails = [];
      document.querySelectorAll('details').forEach(function (details) {
        if (!details.open) {
          printOpenedDetails.push(details);
          details.open = true;
        }
      });
    });
    window.addEventListener('afterprint', function () {
      printOpenedDetails.forEach(function (details) { details.open = false; });
      printOpenedDetails = [];
    });
    var params = new URLSearchParams(window.location.search);
    var querySearch = params.has('q') ? params.get('q') : (params.get('object') || '');
    var findingSearch = document.getElementById('findingSearch');
    if (querySearch && findingSearch) {
      findingSearch.value = querySearch;
    }
    document.addEventListener('keydown', function (event) {
      if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
      var target = event.target;
      var tagName = target && target.tagName ? target.tagName.toLowerCase() : '';
      if (tagName === 'input' || tagName === 'textarea' || tagName === 'select' || tagName === 'button' || (target && target.isContentEditable)) return;
      var search = document.getElementById('findingSearch');
      if (search) {
        event.preventDefault();
        search.focus();
      }
    });
    applyFindingFilters();
  });
})();
'@

    $body = @(
        New-InspectorClientTenantDetailsHtml -ReportModel $ReportModel
        New-InspectorScopeStatementHtml -ReportModel $ReportModel
        New-InspectorScopeInventoryHtml -ReportModel $ReportModel
        New-InspectorTenantCapabilitiesHtml -ReportModel $ReportModel
        New-InspectorExecutiveSummaryHtml -ReportModel $ReportModel
        New-InspectorAssessmentAccountingHtml -ReportModel $ReportModel
        New-InspectorSeverityMethodologyHtml -ReportModel $ReportModel
        New-InspectorSummaryMetricsHtml -ReportModel $ReportModel
        New-InspectorFindingsByCategoryHtml -ReportModel $ReportModel
        New-InspectorPriorityFindingsHtml -ReportModel $ReportModel
    ) -join [Environment]::NewLine

    return New-InspectorReportHtmlDocument `
        -Title (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'AssessmentName')) `
        -Body $body `
        -Subtitle 'Read-only, snapshot-first assessment output for administrator triage. Findings preserve evidence and can be reviewed offline without Microsoft Graph calls.' `
        -GeneratedAt (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'GeneratedAt')) `
        -ReportId $reportId `
        -PostureLabel $postureLabel `
        -MainReportFileName (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'ReportFileName')) `
        -EvidenceReportFileName (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'EvidenceReportFileName')) `
        -DiagnosticsReportFileName (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'DiagnosticsReportFileName')) `
        -ActiveView 'Assessment' `
        -Script $script
}

function New-InspectorSidecarHtmlDocument {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][object]$ReportModel,
        [string]$Title,
        [string]$Body,
        [string]$Subtitle = '',
        [ValidateSet('Evidence','Diagnostics')][string]$ActiveView
    )

    $sidecarScript = @'
(function(){
  function setTheme(theme){
    document.documentElement.setAttribute('data-theme',theme);
    try{localStorage.setItem('eoi-theme',theme)}catch(error){}
  }
  function revealHashTarget(){
    if(!window.location.hash)return;
    var id=decodeURIComponent(window.location.hash.substring(1));
    var target=document.getElementById(id);
    if(!target)return;
    if(target.tagName==='DETAILS')target.open=true;
    var parent=target.parentElement;
    while(parent){if(parent.tagName==='DETAILS')parent.open=true;parent=parent.parentElement;}
    try{target.scrollIntoView({block:'start'});}catch(error){}
  }
  document.addEventListener('DOMContentLoaded',function(){
    var saved='dark';
    try{saved=localStorage.getItem('eoi-theme')||'dark'}catch(error){}
    setTheme(saved);
    var toggle=document.getElementById('themeToggle');
    if(toggle)toggle.addEventListener('click',function(){setTheme(document.documentElement.getAttribute('data-theme')==='light'?'dark':'light')});
    var search=document.getElementById('sidecarSearch');
    if(search)search.addEventListener('input',function(){
      var value=(search.value||'').toLowerCase();
      document.querySelectorAll('[data-search]').forEach(function(row){row.hidden=value && (row.getAttribute('data-search')||'').indexOf(value)===-1});
    });
    revealHashTarget();
  });
  window.addEventListener('hashchange',revealHashTarget);
})();
'@

    return New-InspectorReportHtmlDocument `
        -Title $Title `
        -Body $Body `
        -Subtitle $Subtitle `
        -GeneratedAt (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'GeneratedAt')) `
        -ReportId (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'ReportId')) `
        -MainReportFileName (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'ReportFileName')) `
        -EvidenceReportFileName (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'EvidenceReportFileName')) `
        -DiagnosticsReportFileName (ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'DiagnosticsReportFileName')) `
        -ActiveView $ActiveView `
        -Script $sidecarScript
}

function New-InspectorEvidenceHtmlReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $evidenceRows =
        @($ReportModel.EvidenceRows) |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [string](Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceId')
            )
        } |
        Sort-Object EvidenceId -Unique

    $observations =
        @($ReportModel.SecurityObservations) |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [string](Get-InspectorReportProperty -InputObject $_ -Name 'ObservationId')
            )
        } |
        Sort-Object ObservationId -Unique

    $findings =
        @($ReportModel.AssessmentFindings) |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [string](Get-InspectorReportProperty -InputObject $_ -Name 'FindingId')
            )
        } |
        Sort-Object {
            Get-InspectorReportSeverityOrder -Severity ([string](Get-InspectorReportProperty -InputObject $_ -Name 'Severity'))
        }, Category, Title

    $evidenceIndex = New-InspectorReportEvidenceIndex -EvidenceRows $evidenceRows
    $observationIndex = New-InspectorReportObservationIndex -SecurityObservations $observations

    $findingCards = @(
        foreach ($finding in $findings) {
            $findingId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'FindingId')
            $title = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Title')
            $severity = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Severity')
            $category = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Category')
            $resultState = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'ResultState')
            $confidence = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Confidence')
            $conclusion = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'Conclusion')
            $criterion = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'CriterionSummary')
            $evidenceSupport = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $finding -Name 'EvidenceSupportStatus')
            $observationIds = @(Get-InspectorReportProperty -InputObject $finding -Name 'ObservationIds') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique
            $declaredEvidenceIds = @(Get-InspectorReportProperty -InputObject $finding -Name 'EvidenceIds') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            $issueGroups = @(Get-InspectorReportProperty -InputObject $finding -Name 'IssueGroups') | Where-Object { $null -ne $_ }
            $affectedObjects = @(Get-InspectorReportProperty -InputObject $finding -Name 'AffectedObjects') | Where-Object { $null -ne $_ }

            $findingObservations = @(
                foreach ($observationId in $observationIds) {
                    $key = ConvertTo-InspectorReportString $observationId
                    if ($observationIndex.ContainsKey($key)) { $observationIndex[$key] }
                }
            )

            # The finding contract should already contain the union of supporting
            # evidence IDs. Rebuild that union defensively from its canonical
            # observations so the sidecar never hides provenance while grouping.
            $evidenceIds = @(
                @($declaredEvidenceIds)
                @($findingObservations | ForEach-Object { @(Get-InspectorReportProperty -InputObject $_ -Name 'EvidenceIds') })
            ) | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

            $findingEvidence = @(
                foreach ($evidenceId in $evidenceIds) {
                    $key = ConvertTo-InspectorReportString $evidenceId
                    if ($evidenceIndex.ContainsKey($key)) { @($evidenceIndex[$key]) | Select-Object -First 1 }
                }
            )

            $overviewRows = @(
                [PSCustomObject]@{ Field = 'Finding ID'; Value = $findingId }
                [PSCustomObject]@{ Field = 'Category'; Value = $category }
                [PSCustomObject]@{ Field = 'Severity'; Value = $severity }
                [PSCustomObject]@{ Field = 'Result state'; Value = $resultState }
                [PSCustomObject]@{ Field = 'Confidence'; Value = $confidence }
                [PSCustomObject]@{ Field = 'Affected objects'; Value = @($affectedObjects).Count }
                [PSCustomObject]@{ Field = 'Contributing observations'; Value = @($observationIds).Count }
                [PSCustomObject]@{ Field = 'Unique evidence records'; Value = @($evidenceIds).Count }
                [PSCustomObject]@{ Field = 'Evidence support'; Value = $evidenceSupport }
            )

            $conditionRows = @(
                foreach ($group in $issueGroups) {
                    [PSCustomObject][ordered]@{
                        Condition = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'Condition')
                        Severity = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'Severity')
                        Confidence = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'Confidence')
                        Criterion = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'Criterion')
                        AffectedObjects = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'ObjectCount')
                        Observations = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $group -Name 'ObservationCount')
                    }
                }
            )

            $observationRows = @(
                foreach ($observation in $findingObservations) {
                    $affected = Get-InspectorReportProperty -InputObject $observation -Name 'AffectedObject'
                    [PSCustomObject][ordered]@{
                        ObservationId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'ObservationId')
                        Severity = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'Severity')
                        ResultState = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'ResultState')
                        Condition = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'Title')
                        AffectedObject = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $affected -Name 'DisplayName')
                        EvidenceIds = @(Get-InspectorReportProperty -InputObject $observation -Name 'EvidenceIds')
                    }
                }
            )

            $findingEvidenceRows = @(
                foreach ($row in $findingEvidence) {
                    $scope = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'EvidenceScope')
                    $status = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'Status')
                    $subjectType = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'SubjectObjectType')
                    $subjectId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'SubjectObjectId')
                    $subject = @($subjectType, $subjectId) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                    $interpretation =
                        switch ($scope) {
                            'TenantCollection' { 'Tenant-wide source collection used as direct context or to prove tenant-level presence/absence.' }
                            'ObjectRelationship' { 'Object-specific relationship collection used to prove ownership, membership, consent, or assignment state.' }
                            'ObjectCollection' { 'Object-scoped collection used to support this condition.' }
                            default { 'Collected provenance supporting this finding.' }
                        }
                    if ($status -ne 'Success') {
                        $interpretation += ' This collection did not complete successfully; coverage is incomplete.'
                    }

                    [PSCustomObject][ordered]@{
                        EvidenceId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'EvidenceId')
                        QueryName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'QueryName')
                        Scope = $scope
                        Subject = @($subject) -join ': '
                        Status = $status
                        Completeness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'Completeness')
                        ResultCount = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'ResultCount')
                        CollectorGraphPermission = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'RequiredPermission')
                        Interpretation = $interpretation
                    }
                }
            )

            $search = ConvertTo-InspectorReportSearchAttribute -Values @(
                $findingId, $title, $severity, $category, $resultState, $confidence, $conclusion, $criterion,
                @($affectedObjects | ForEach-Object { Get-InspectorReportProperty -InputObject $_ -Name 'DisplayName' }),
                @($findingObservations | ForEach-Object {
                    @(
                        Get-InspectorReportProperty -InputObject $_ -Name 'ObservationId'
                        Get-InspectorReportProperty -InputObject $_ -Name 'Title'
                    )
                }),
                @($findingEvidenceRows | ForEach-Object { @($_.EvidenceId, $_.QueryName, $_.Status, $_.Subject) })
            )

            @"
<details id="finding-$([System.Uri]::EscapeDataString($findingId))" class="card" data-search="$search">
  <summary><span class="pill $(Get-InspectorReportStatusClass -Value $severity)">$(ConvertTo-InspectorHtmlEncodedText $severity)</span> <strong>$(ConvertTo-InspectorHtmlEncodedText $title)</strong> <span class="muted">$(@($evidenceIds).Count) evidence records</span></summary>
  <p>$(ConvertTo-InspectorHtmlEncodedText $conclusion)</p>
  <p class="muted"><strong>Criterion:</strong> $(ConvertTo-InspectorHtmlEncodedText $criterion)</p>
  <h3>Finding context</h3>
  $(New-InspectorHtmlTable -Rows $overviewRows -Columns @('Field','Value') -SuppressRowAnchors)
  <h3>Conditions detected</h3>
  $(New-InspectorHtmlTable -Rows $conditionRows -Columns @('Condition','Severity','Confidence','Criterion','AffectedObjects','Observations') -EmptyMessage 'No condition groups were supplied.' -SuppressRowAnchors)
  <h3>Contributing observations</h3>
  <p class="muted">Observations are normalized assessment signals. Select an Observation ID to inspect its canonical record below.</p>
  $(New-InspectorHtmlTable -Rows $observationRows -Columns @('ObservationId','Severity','ResultState','Condition','AffectedObject','EvidenceIds') -EmptyMessage 'No contributing observations were supplied.' -SuppressRowAnchors -EnableReferenceLinks)
  <h3>Evidence used by this finding</h3>
  <p class="muted">These are the Graph collection records that support the observations above. Select an Evidence ID for full query provenance.</p>
  $(New-InspectorHtmlTable -Rows $findingEvidenceRows -Columns @('EvidenceId','QueryName','Scope','Subject','Status','Completeness','ResultCount','CollectorGraphPermission','Interpretation') -EmptyMessage 'No evidence records were supplied.' -SuppressRowAnchors -EnableReferenceLinks)
</details>
"@
        }
    ) -join [Environment]::NewLine

    $evidenceCardsBuilder = [System.Text.StringBuilder]::new()
    foreach ($row in $evidenceRows) {
        $evidenceId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'EvidenceId')
        $search = ConvertTo-InspectorReportSearchAttribute -Values @($evidenceId, (Get-InspectorReportProperty -InputObject $row -Name 'Endpoint'), (Get-InspectorReportProperty -InputObject $row -Name 'QueryName'), (Get-InspectorReportProperty -InputObject $row -Name 'Status'), (Get-InspectorReportProperty -InputObject $row -Name 'RequiredPermission'), (Get-InspectorReportProperty -InputObject $row -Name 'ParentInput'))
        $displayRow = [PSCustomObject][ordered]@{
            EvidenceId = $evidenceId
            QueryName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'QueryName')
            CollectorName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'CollectorName')
            Endpoint = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'Endpoint')
            CollectorGraphPermission = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'RequiredPermission')
            CollectionTime = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'CollectionTime')
            Status = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'Status')
            Completeness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'Completeness')
            ResultCount = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'ResultCount')
            SourceResultCount = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'SourceResultCount')
            Limitations = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'Limitations')
            ParentInput = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'ParentInput')
            ParentResolutionType = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'ParentResolutionType')
            EvidenceScope = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'EvidenceScope')
            SubjectObjectType = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'SubjectObjectType')
            SubjectObjectId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $row -Name 'SubjectObjectId')
        }
        $fragment = "<details id=""evidence-$([System.Uri]::EscapeDataString($evidenceId))"" class=""card"" data-search=""$search""><summary><strong>$(ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportProperty -InputObject $row -Name 'QueryName'))</strong> <span class=""pill $(Get-InspectorReportStatusClass -Value ([string](Get-InspectorReportProperty -InputObject $row -Name 'Status')))"">$(ConvertTo-InspectorHtmlEncodedText (Get-InspectorReportProperty -InputObject $row -Name 'Status'))</span> <span class=""muted"">$(ConvertTo-InspectorHtmlEncodedText $evidenceId)</span></summary>$(New-InspectorHtmlTable -Rows @($displayRow) -Columns @('EvidenceId','QueryName','CollectorName','Endpoint','CollectorGraphPermission','CollectionTime','Status','Completeness','ResultCount','SourceResultCount','Limitations','ParentInput','ParentResolutionType','EvidenceScope','SubjectObjectType','SubjectObjectId') -SuppressRowAnchors)</details>"
        if ($evidenceCardsBuilder.Length -gt 0) {
            [void]$evidenceCardsBuilder.Append([Environment]::NewLine)
        }
        [void]$evidenceCardsBuilder.Append($fragment)
    }
    $evidenceCards = $evidenceCardsBuilder.ToString()

    $observationCardsBuilder = [System.Text.StringBuilder]::new()
    foreach ($observation in $observations) {
        $observationId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'ObservationId')
        $evidenceIds = @(Get-InspectorReportProperty -InputObject $observation -Name 'EvidenceIds')
        $row = [PSCustomObject][ordered]@{
            ObservationId = $observationId
            Category = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'Category')
            Severity = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'Severity')
            ResultState = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'ResultState')
            Title = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $observation -Name 'Title')
            AffectedObject = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject (Get-InspectorReportProperty -InputObject $observation -Name 'AffectedObject') -Name 'DisplayName')
            EvidenceIds = @($evidenceIds)
        }
        $search = ConvertTo-InspectorReportSearchAttribute -Values @($observationId, $row.Category, $row.Severity, $row.ResultState, $row.Title, $row.AffectedObject, $evidenceIds)
        $fragment = "<details id=""observation-$([System.Uri]::EscapeDataString($observationId))"" class=""card"" data-search=""$search""><summary><strong>$(ConvertTo-InspectorHtmlEncodedText $row.Title)</strong> <span class=""muted"">$(ConvertTo-InspectorHtmlEncodedText $observationId)</span></summary>$(New-InspectorHtmlTable -Rows @($row) -Columns @('ObservationId','Category','Severity','ResultState','Title','AffectedObject','EvidenceIds') -SuppressRowAnchors -EnableReferenceLinks)</details>"
        if ($observationCardsBuilder.Length -gt 0) {
            [void]$observationCardsBuilder.Append([Environment]::NewLine)
        }
        [void]$observationCardsBuilder.Append($fragment)
    }
    $observationCards = $observationCardsBuilder.ToString()

    $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
    $packageValidationStatus = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $ReportModel -Name 'PackageValidationStatus')
    if ([string]::IsNullOrWhiteSpace($packageValidationStatus)) { $packageValidationStatus = 'Not provided' }

    $validationWarning = ''
    if ($packageValidationStatus -ne 'Success' -and $packageValidationStatus -ne 'Not provided') {
        $validationWarning = '<section class="section"><div class="section-header"><h2>ASSESSMENT PACKAGE VALIDATION FAILED</h2></div><p>This report package failed internal consistency or required-evidence coverage validation. Do not rely on it for remediation decisions until the validation errors are resolved.</p></section>'
    }

    $contextRows = @(
        [PSCustomObject]@{ Field = 'Tenant ID'; Value = Get-InspectorReportProperty -InputObject $summary -Name 'TenantId' }
        [PSCustomObject]@{ Field = 'Run ID'; Value = Get-InspectorReportProperty -InputObject $ReportModel -Name 'RunId' }
        [PSCustomObject]@{ Field = 'Report ID'; Value = Get-InspectorReportProperty -InputObject $ReportModel -Name 'ReportId' }
        [PSCustomObject]@{ Field = 'Grouped findings'; Value = @($findings).Count }
        [PSCustomObject]@{ Field = 'Canonical observations'; Value = @($observations).Count }
        [PSCustomObject]@{ Field = 'Evidence records'; Value = @($evidenceRows).Count }
        [PSCustomObject]@{ Field = 'Package validation status'; Value = $packageValidationStatus }
    )

    $body = @"
$validationWarning
<section class="section">
  <div class="section-header"><h2>How to Read This Report</h2><span class="muted">Finding → Observation → Evidence</span></div>
  <p><strong>Start with a grouped finding.</strong> Each finding below mirrors the grouped finding in the Assessment report and collects its conditions, contributing observations, and supporting Graph evidence in one place.</p>
  <p><strong>Observation</strong> means a normalized assessment signal derived from collected tenant state. <strong>Evidence</strong> is the provenance of the Graph collection used to support that signal; it is not a separate security finding.</p>
  <p><strong>Status = Success</strong> means the Inspector collection query completed. A result count of 0 can be meaningful proof of absence only when the relevant collection is complete. <strong>RequiredPermission</strong> is the Microsoft Graph permission required by Entra Object Inspector to collect the evidence; it is not a permission held by the assessed object.</p>
  <p><strong>EvidenceScope</strong> explains whether the proof is tenant-wide or object-specific. Use the grouped view for assessment decisions; use the raw Evidence Record Catalog only when you need endpoint/query-level provenance.</p>
</section>
<section class="section">
  <div class="section-header"><h2>Package Context</h2></div>
  $(New-InspectorHtmlTable -Rows $contextRows -Columns @('Field','Value'))
</section>
<section class="section">
  <div class="section-header"><h2>Evidence Search</h2><span class="muted">Search grouped findings, observations, or raw evidence</span></div>
  <input id="sidecarSearch" class="filter" type="search" placeholder="Search finding, condition, object, evidence ID, query, status, Graph permission, or endpoint">
</section>
<section class="section">
  <div class="section-header"><h2>Evidence by Grouped Finding</h2><span class="muted">$(@($findings).Count) grouped findings</span></div>
  <p class="muted">This is the primary evidence view. Expand the finding you are reviewing in the Assessment report.</p>
  $findingCards
</section>
<details class="section">
  <summary><strong>Canonical Observation Index</strong> <span class="muted">$(@($observations).Count) observations — drill-down reference</span></summary>
  <p class="muted">Use this index when you need to inspect one normalized signal referenced by a finding.</p>
  $observationCards
</details>
<details class="section">
  <summary><strong>Evidence Record Catalog</strong> <span class="muted">$(@($evidenceRows).Count) records — raw provenance</span></summary>
  <p class="muted">Low-level collection provenance. This section is intentionally secondary to the finding-oriented evidence map above.</p>
  $evidenceCards
</details>
"@

    return New-InspectorSidecarHtmlDocument -ReportModel $ReportModel -ActiveView 'Evidence' -Title "$($ReportModel.AssessmentName) Evidence" -Subtitle 'Finding-oriented offline evidence map. No Graph calls are made.' -Body $body
}

function New-InspectorDiagnosticsHtmlReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$ReportModel
    )

    $summary = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Summary'
    $manifest = Get-InspectorReportProperty -InputObject $ReportModel -Name 'Manifest'
    $runtime = Get-InspectorReportProperty -InputObject $ReportModel -Name 'RuntimeTelemetry'
    $orchestration = Get-InspectorReportProperty -InputObject $ReportModel -Name 'OrchestrationTelemetry'
    $graphSummary = Get-InspectorReportProperty -InputObject $runtime -Name 'GraphRequestSummary'
    if ($null -eq $graphSummary) { $graphSummary = Get-InspectorReportProperty -InputObject $orchestration -Name 'GraphRequestSummary' }
    $retrySummary = Get-InspectorReportProperty -InputObject $runtime -Name 'RetrySummary'
    if ($null -eq $retrySummary) { $retrySummary = Get-InspectorReportProperty -InputObject $orchestration -Name 'RetrySummary' }
    $throttlingSummary = Get-InspectorReportProperty -InputObject $runtime -Name 'ThrottlingSummary'
    if ($null -eq $throttlingSummary) { $throttlingSummary = Get-InspectorReportProperty -InputObject $orchestration -Name 'ThrottlingSummary' }
    $externalSummary = Get-InspectorReportProperty -InputObject $runtime -Name 'ExternalEndpointSummary'
    if ($null -eq $externalSummary) { $externalSummary = Get-InspectorReportProperty -InputObject $orchestration -Name 'ExternalEndpointSummary' }
    $outputSummary = Get-InspectorReportProperty -InputObject $runtime -Name 'OutputArtifactSummary'
    if ($null -eq $outputSummary) { $outputSummary = Get-InspectorReportProperty -InputObject $orchestration -Name 'OutputArtifactSummary' }

    $failedRows = @($ReportModel.FailedObjects)
    $failedTypeSummary = @($failedRows | Group-Object ObjectType | ForEach-Object { [PSCustomObject]@{ ObjectType = $_.Name; Count = $_.Count } })
    $errorSummary = @($failedRows | Group-Object Error | ForEach-Object { [PSCustomObject]@{ Error = $_.Name; Count = $_.Count } })
    $stageRows = @(
        [PSCustomObject]@{ Stage = 'Tenant inspection'; Duration = ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'TenantInspectionDurationMs') }
        [PSCustomObject]@{ Stage = 'Snapshot collection'; Duration = ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'SnapshotCollectionDurationMs') }
        [PSCustomObject]@{ Stage = 'Offline processing'; Duration = ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'OfflineProcessingDurationMs') }
        [PSCustomObject]@{ Stage = 'Assessment intelligence'; Duration = ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'AssessmentIntelligenceDurationMs') }
        [PSCustomObject]@{ Stage = 'Export'; Duration = ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'ExportDurationMs') }
        [PSCustomObject]@{ Stage = 'Report generation'; Duration = ConvertTo-InspectorReportDuration (Get-InspectorReportProperty -InputObject $orchestration -Name 'ReportGenerationDurationMs') }
    )

    $artifactRows =
        @(
            Get-InspectorReportProperty -InputObject $manifest -Name 'Artifacts'
        ) |
        Where-Object { $null -ne $_ }

    $overviewRows = @(
        [PSCustomObject]@{ Field = 'Run ID'; Value = Get-InspectorReportProperty -InputObject $ReportModel -Name 'RunId' }
        [PSCustomObject]@{ Field = 'Report ID'; Value = Get-InspectorReportProperty -InputObject $ReportModel -Name 'ReportId' }
        [PSCustomObject]@{ Field = 'Assessment name'; Value = Get-InspectorReportProperty -InputObject $ReportModel -Name 'AssessmentName' }
        [PSCustomObject]@{ Field = 'Tenant ID'; Value = Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantId','TenantID') }
        [PSCustomObject]@{ Field = 'Tenant name'; Value = Get-InspectorReportMetricValue -InputObject $summary -Names @('TenantDisplayName','TenantName','DisplayName') }
        [PSCustomObject]@{ Field = 'Command status'; Value = $(if (Get-InspectorReportProperty -InputObject $orchestration -Name 'CommandStatus') { Get-InspectorReportProperty -InputObject $orchestration -Name 'CommandStatus' } else { Get-InspectorReportProperty -InputObject $manifest -Name 'SourceStatus' }) }
        [PSCustomObject]@{ Field = 'Tenant inspection status'; Value = $(if (Get-InspectorReportProperty -InputObject $orchestration -Name 'TenantInspectionStatus') { Get-InspectorReportProperty -InputObject $orchestration -Name 'TenantInspectionStatus' } else { Get-InspectorReportProperty -InputObject $summary -Name 'Status' }) }
        [PSCustomObject]@{ Field = 'Package validation status'; Value = Get-InspectorReportProperty -InputObject $ReportModel -Name 'PackageValidationStatus' }
        [PSCustomObject]@{ Field = 'Failed object count'; Value = @($failedRows).Count }
        [PSCustomObject]@{ Field = 'Diagnostics log path'; Value = Get-InspectorReportProperty -InputObject $outputSummary -Name 'DiagnosticsLogPath' }
    )

    $assessmentCoverage = Get-InspectorReportProperty -InputObject $ReportModel -Name 'AssessmentCoverage'
    if ($null -eq $assessmentCoverage) {
        $assessmentCoverage = Get-InspectorReportProperty -InputObject $summary -Name 'AssessmentCoverage'
    }
    if ($null -eq $assessmentCoverage) {
        $assessmentCoverage = Get-InspectorReportProperty -InputObject $manifest -Name 'AssessmentCoverage'
    }

    $coverageRows = @(
        [PSCustomObject]@{ Field = 'Coverage status'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'Status' }
        [PSCustomObject]@{ Field = 'Completeness'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'Completeness' }
        [PSCustomObject]@{ Field = 'Evidence plan matches'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'EvidencePlanMatches' }
        [PSCustomObject]@{ Field = 'Expected required evidence'; Value = Get-InspectorReportMetricValue -InputObject $assessmentCoverage -Names @('ExpectedEvidenceCount','RequiredEvidenceCount') }
        [PSCustomObject]@{ Field = 'Actual required evidence'; Value = Get-InspectorReportMetricValue -InputObject $assessmentCoverage -Names @('ActualRequiredEvidenceCount','RequiredEvidenceCount') }
        [PSCustomObject]@{ Field = 'Successful required evidence'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'SuccessfulRequiredEvidenceCount' }
        [PSCustomObject]@{ Field = 'Incomplete expected evidence'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'IncompleteRequiredEvidenceCount' }
        [PSCustomObject]@{ Field = 'Missing expected evidence'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'MissingExpectedEvidenceCount' }
        [PSCustomObject]@{ Field = 'Unexpected required evidence'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'UnexpectedRequiredEvidenceCount' }
        [PSCustomObject]@{ Field = 'Duplicate required evidence'; Value = Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'DuplicateRequiredEvidenceCount' }
    )

    $coverageIssueRows = @(
        @(Get-InspectorReportProperty -InputObject $assessmentCoverage -Name 'IncompleteQueryDetails') |
            Where-Object { $null -ne $_ } |
            ForEach-Object {
                [PSCustomObject]@{
                    Issue = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Issue')
                    QueryName = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'QueryName')
                    Status = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Status')
                    Completeness = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Completeness')
                }
            }
    )

    $coverageHtml =
        if ($null -eq $assessmentCoverage) {
            '<p class="empty-state">Assessment coverage metadata was not supplied for this report source.</p>'
        }
        else {
            "<p class=""muted"">Release eligibility requires the independently generated expected evidence plan to match the collected assessment-required evidence exactly, with every expected query succeeding completely.</p>$(New-InspectorHtmlTable -Rows $coverageRows -Columns @('Field','Value'))<h3>Coverage issues</h3>$(New-InspectorHtmlTable -Rows $coverageIssueRows -Columns @('Issue','QueryName','Status','Completeness') -EmptyMessage 'No missing, unexpected, duplicate, or incomplete required evidence queries.')"
        }

    $unexpectedExternalHosts = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $externalSummary -Name 'UnexpectedExternalHosts')
    if ([string]::IsNullOrWhiteSpace($unexpectedExternalHosts)) {
        $unexpectedExternalHosts = 'None detected'
    }

    $graphRows = @(
        [PSCustomObject]@{ Field = 'Graph request count'; Value = Get-InspectorReportMetricValue -InputObject $graphSummary -Names @('TotalRequests','GraphRequestCount') }
        [PSCustomObject]@{ Field = 'Throttled requests'; Value = Get-InspectorReportMetricValue -InputObject $throttlingSummary -Names @('ThrottledRequests') }
        [PSCustomObject]@{ Field = 'Retried requests'; Value = Get-InspectorReportMetricValue -InputObject $retrySummary -Names @('RetriedRequests') }
        [PSCustomObject]@{ Field = 'Unexpected external hosts'; Value = $unexpectedExternalHosts }
    )

    $validationRows = @(
        $ReportModel.PackageValidationErrors |
        ForEach-Object {
            [PSCustomObject]@{
                ErrorId = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'ErrorId')
                Message = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'Message')
                AffectedInvariant = ConvertTo-InspectorReportString (Get-InspectorReportProperty -InputObject $_ -Name 'AffectedInvariant')
            }
        }
    )

    $body = @"
<section class="section"><div class="section-header"><h2>Diagnostics Overview</h2></div>$(New-InspectorHtmlTable -Rows $overviewRows -Columns @('Field','Value'))</section>
<section class="section"><div class="section-header"><h2>Package Validation</h2></div>$(New-InspectorHtmlTable -Rows $validationRows -Columns @('ErrorId','Message','AffectedInvariant') -EmptyMessage 'Package validation passed.')</section>
<section class="section"><div class="section-header"><h2>Assessment Coverage</h2><span class="muted">Expected evidence plan vs collected evidence</span></div>$coverageHtml</section>
<section class="section"><div class="section-header"><h2>Failed Object Type Summary</h2></div>$(New-InspectorHtmlTable -Rows $failedTypeSummary -Columns @('ObjectType','Count') -EmptyMessage 'No failed objects.')</section>
<section class="section"><div class="section-header"><h2>Error Summary</h2></div>$(New-InspectorHtmlTable -Rows $errorSummary -Columns @('Error','Count') -EmptyMessage 'No failed object errors.')</section>
<section class="section"><div class="section-header"><h2>Failed Objects</h2></div>$(New-InspectorHtmlTable -Rows $failedRows -Columns @('ObjectKey','ObjectType','ObjectId','InspectionIdentity','Attempts','Error') -EmptyMessage 'No failed objects.')</section>
<section class="section"><div class="section-header"><h2>Stage Durations</h2></div>$(New-InspectorHtmlTable -Rows $stageRows -Columns @('Stage','Duration'))</section>
<section class="section"><div class="section-header"><h2>Graph Summary</h2></div>$(New-InspectorHtmlTable -Rows $graphRows -Columns @('Field','Value'))</section>
<section class="section"><div class="section-header"><h2>Artifacts</h2></div>$(New-InspectorHtmlTable -Rows $artifactRows -Columns @('Name','Kind','Path','RecordCount','SizeBytes') -EmptyMessage 'No artifact records were supplied.')</section>
"@

    return New-InspectorSidecarHtmlDocument -ReportModel $ReportModel -ActiveView 'Diagnostics' -Title "$($ReportModel.AssessmentName) Diagnostics" -Subtitle 'Static diagnostics sidecar. No raw tenant objects or secrets are embedded.' -Body $body
}
