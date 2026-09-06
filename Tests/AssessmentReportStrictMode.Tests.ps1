$modulePath =
    Join-Path $PSScriptRoot '..\EntraObjectInspector.psd1'

Import-Module $modulePath -Force

Describe 'HTML report UX scalar-shape regressions' {

    InModuleScope EntraObjectInspector {

        It 'renders a single scalar observation reference without Count failure' {
            $html =
                New-InspectorReportLinkList `
                    -Value 'OBS-SINGLE' `
                    -Prefix 'observation'

            $html | Should -Not -Match 'href="#observation-OBS-SINGLE"'
            $html | Should -Match '<span class="xref">OBS-SINGLE</span>'
            $html | Should -Match 'OBS-SINGLE'
        }

        It 'renders a single scalar evidence reference without Count failure' {
            $html =
                New-InspectorReportLinkList `
                    -Value 'ev-single' `
                    -Prefix 'evidence'

            $html | Should -Not -Match 'href="#evidence-ev-single"'
            $html | Should -Match '<span class="xref">ev-single</span>'
            $html | Should -Match 'ev-single'
        }

        It 'renders an empty table state without creating empty rows' {
            $html =
                New-InspectorHtmlTable `
                    -Rows @() `
                    -Columns @('Severity','Confidence','Title') `
                    -EmptyMessage 'No records were supplied.'

            $html | Should -Match 'No records were supplied.'
            $html | Should -Not -Match '<tr>'
        }
    }
}

