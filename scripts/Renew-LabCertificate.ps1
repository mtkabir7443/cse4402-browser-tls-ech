#Requires -Version 7.2
[CmdletBinding()]
param([string]$OpenSslPath='C:\msys64\mingw64\bin\openssl.exe')
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $root
try {
    if(-not(Test-Path -LiteralPath $OpenSslPath)){throw 'OpenSSL not found'}
    $ca=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText((Join-Path $root '.runtime/ca.pem')))
    $days=[Math]::Min(55,[Math]::Floor(($ca.NotAfter.ToUniversalTime()-[DateTime]::UtcNow).TotalDays)-1)
    if($days -lt 35){throw 'CA validity is too short for this measurement period; explicit new lab identity is needed.'}
    $stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    Copy-Item -LiteralPath '.runtime/server.pem' -Destination ('evidence/server-before-renewal-'+$stamp+'.pem')
    @'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:*.tlslab.test,DNS:tlslab.test,DNS:localhost,IP:127.0.0.1
'@ | Set-Content -LiteralPath '.runtime/leaf-extensions.cnf' -Encoding ascii
    & $OpenSslPath x509 -x509toreq -in '.runtime/server.pem' -signkey '.runtime/server-key.pem' -out '.runtime/leaf-renewal.csr'
    if($LASTEXITCODE -ne 0){throw 'CSR generation failed'}
    $serial='0x'+[guid]::NewGuid().ToString('N')
    & $OpenSslPath x509 -req -in '.runtime/leaf-renewal.csr' -CA '.runtime/ca.pem' -CAkey '.runtime/ca-key.pem' -set_serial $serial -days $days -sha256 -extfile '.runtime/leaf-extensions.cnf' -out '.runtime/server-next.pem'
    if($LASTEXITCODE -ne 0){throw 'Certificate renewal failed'}
    & $OpenSslPath verify -CAfile '.runtime/ca.pem' -verify_hostname 'valid.tlslab.test' '.runtime/server-next.pem'
    if($LASTEXITCODE -ne 0){throw 'Renewed certificate verification failed'}
    $leaf=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText((Join-Path $root '.runtime/server-next.pem')))
    if($leaf.NotAfter -le [DateTime]'2026-12-18T23:59:59'){throw 'New leaf does not cover final deadline'}
    Copy-Item -LiteralPath '.runtime/server-next.pem' -Destination '.runtime/server.pem' -Force
    [ordered]@{renewed_utc=[DateTime]::UtcNow.ToString('o');ca_thumbprint=$ca.Thumbprint;leaf_thumbprint=$leaf.Thumbprint;expires_utc=$leaf.NotAfter.ToUniversalTime().ToString('o');leaf_pem_sha256=(Get-FileHash -LiteralPath '.runtime/server.pem').Hash;private_key_reused=$true;windows_trust_modified=$false} | ConvertTo-Json | Set-Content -LiteralPath 'evidence/certificate-renewal.json' -Encoding utf8
    Get-Content -LiteralPath 'evidence/certificate-renewal.json'
} finally {Pop-Location}
