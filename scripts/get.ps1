# Установка готового моста Leash на Windows без сборки: скачивает
# leash-host.exe из GitHub Releases, сверяет SHA-256 с SHA256SUMS релиза,
# кладёт в %LOCALAPPDATA%\Leash\bin и регистрирует в Firefox (реестр HKCU).
#
#   irm https://raw.githubusercontent.com/Kirusshenkin/leash-firefox-extension/master/scripts/get.ps1 | iex
#
# $env:LEASH_VERSION = 'v0.3.0' — конкретный релиз (по умолчанию последний),
# $env:LEASH_BIN_DIR = '...' — другой каталог.
#
# Сборка x86_64; на Windows для ARM она работает через эмуляцию x64.

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'Kirusshenkin/leash-firefox-extension'
$version = if ($env:LEASH_VERSION) { $env:LEASH_VERSION } else { 'latest' }
$destDir = if ($env:LEASH_BIN_DIR) { $env:LEASH_BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'Leash\bin' }

if ($env:PROCESSOR_ARCHITECTURE -notin @('AMD64', 'ARM64')) {
    throw "готовой сборки для $($env:PROCESSOR_ARCHITECTURE) нет: соберите из исходников (cargo build -p leash-host)"
}
$file = 'leash-host-x86_64-pc-windows-msvc.exe'
$base = if ($version -eq 'latest') {
    "https://github.com/$repo/releases/latest/download"
} else {
    "https://github.com/$repo/releases/download/$version"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $bin = Join-Path $tmp $file
    $sums = Join-Path $tmp 'SHA256SUMS'
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$file" -OutFile $bin
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

    $want = Get-Content $sums |
        ForEach-Object { $p = $_ -split '\s+'; if ($p[1] -eq $file) { $p[0].ToLower() } } |
        Select-Object -First 1
    $got = (Get-FileHash -Algorithm SHA256 -Path $bin).Hash.ToLower()
    if (-not $want -or $want -ne $got) {
        throw "SHA-256 не совпал ($file): ожидался '$want', получен '$got'"
    }

    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    $exe = Join-Path $destDir 'leash-host.exe'
    Copy-Item -Force -Path $bin -Destination $exe
    & $exe install
    if ($LASTEXITCODE -ne 0) { throw "leash-host install завершился с кодом $LASTEXITCODE" }
} finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
