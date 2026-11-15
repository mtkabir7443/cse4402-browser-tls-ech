#Requires -Version 7.2
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$events=@(Get-Content -LiteralPath (Join-Path $root 'evidence/server-events.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
$rows=@()
foreach($caseName in @('valid','baseline','stale')){
    $runId='feasibility-firefox-'+$caseName+'-01'
    $meta=Get-Content -LiteralPath (Join-Path $root ('evidence/'+$runId+'-runner.json')) -Raw | ConvertFrom-Json
    $http=@($events | Where-Object { $_.event -eq 'http_result' -and $_.run_id -eq $runId })
    if($http.Count -ne 1){throw "Expected one HTTP result for $runId"}
    if($meta.certificate_verification_bypassed -or $http[0].tls_version -ne 'TLS 1.3' -or $http[0].user_agent -notlike '*Firefox/160.0*'){throw "Invalid browser evidence for $runId"}
    $expectedECH=$caseName -ne 'baseline'
    if($http[0].ech_accepted -ne $expectedECH){throw "Unexpected ECH result for $runId"}
    $outer=@($events | Where-Object { $_.event -eq 'handshake' -and $_.fixture -eq 'tls13-ech' -and $_.server_name -eq 'public.tlslab.test' -and -not $_.ech_accepted -and $_.timestamp -ge $meta.started_utc -and $_.timestamp -le $meta.finished_utc })
    if($caseName -eq 'stale' -and $outer.Count -lt 1){throw 'No stale-run outer handshake evidence'}
    $rows += [ordered]@{run_id=$runId;browser='Firefox 160.0';case=$caseName;tls_version=$http[0].tls_version;ech_accepted=$http[0].ech_accepted;client_ip=$http[0].client_ip;outer_connections_in_run=$outer.Count;certificate_bypass=$false;runner_file=('evidence/'+$runId+'-runner.json');screenshot=('evidence/'+$runId+'.png')}
}
$summary=Get-Content -LiteralPath (Join-Path $root 'evidence/fixture-probes/20261115T052622771Z/summary.json') -Raw | ConvertFrom-Json
if(-not $summary.all_passed -or $summary.passed_probe_count -ne 14){throw 'Fixture probes incomplete'}
$go=Get-Content -LiteralPath (Join-Path $root 'evidence/independent-ech-probe.json') -Raw | ConvertFrom-Json
if(@($go | Where-Object { -not $_.passed }).Count -gt 0 -or $go.Count -ne 3){throw 'Independent ECH controls incomplete'}
$result=[ordered]@{
    generated_utc=[DateTime]::UtcNow.ToString('o')
    validation_date='2026-11-15'
    fixture_controls_passed=14
    independent_ech_controls=$go
    actual_browser_results=$rows
    stale_interpretation='Observed recovery with final ECH acceptance; sequence is consistent with automatic authenticated retry. Browser retry extension/config ID and exact retry count were not decoded.'
    planned_full_matrix_runs=252
    completed_full_matrix=$false
    dashboard_end_to_end_verified=$false
    dashboard_limitation='The screenshot runner ended before completion; automatic approval review blocked the follow-up persistent browser launch with reason blocked by policy.'
}
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $root 'evidence/feasibility-summary.json') -Encoding utf8
Write-Output 'Verified 14 fixture controls, 3 Go ECH controls and 3 actual Firefox ECH cases.'
