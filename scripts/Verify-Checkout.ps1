#Requires -Version 7.2
<#
.SYNOPSIS
Build and check a clean checkout without installing trust or starting browsers.
.DESCRIPTION
Creates private fixture keys under .runtime if absent. Tests use ephemeral
loopback ports and explicit CA verification. No Windows trust or policy changes.
#>
[CmdletBinding()]
param(
    [string]$GoPath = (Join-Path $PSScriptRoot '../.tools/go/bin/go.exe'),
    [string]$OpenSslPath = 'openssl'
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$go = (Get-Command $GoPath -ErrorAction Stop).Source
$openssl = (Get-Command $OpenSslPath -ErrorAction Stop).Source
$previousOpenSsl = $env:SUITE_TEST_OPENSSL
$previousProxy = $env:GOPROXY
$previousSumDb = $env:GOSUMDB
Push-Location $root
try {
    $env:GOPROXY = 'off'
    $env:GOSUMDB = 'off'
    $env:SUITE_TEST_OPENSSL = $openssl
    New-Item -ItemType Directory -Path '.runtime','evidence' -Force | Out-Null
    & $go version
    node --version
    & $openssl version
    & $go build -buildvcs=false -o '.runtime/tlslab.exe' .
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    if (-not (Test-Path '.runtime/ca.pem')) {
        & './.runtime/tlslab.exe' -mode init
        if ($LASTEXITCODE -ne 0) { throw 'Fixture initialization failed' }
    }
    & $go test -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    & $go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
    node --test './scripts/run-matrix.test.cjs' './scripts/suite-fixtures.test.cjs'
    if ($LASTEXITCODE -ne 0) { throw 'Node controls failed' }
    if (Test-Path './results/comparison-data.json') {
        node './scripts/verify-public-results.cjs' './results'
        if ($LASTEXITCODE -ne 0) { throw 'Published result consistency checks failed' }
    }
    Write-Output 'PASS: clean-checkout build and controls; no browser study rerun or OS trust/policy changes.'
} finally {
    Pop-Location
    $env:SUITE_TEST_OPENSSL = $previousOpenSsl
    $env:GOPROXY = $previousProxy
    $env:GOSUMDB = $previousSumDb
}
