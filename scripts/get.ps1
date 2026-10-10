# Установка готового моста Leash на Windows (x86_64) без сборки:
# скачивает leash-host из GitHub Releases, сверяет SHA-256 с SHA256SUMS
# релиза, кладёт в %LOCALAPPDATA%\Leash и регистрирует в Firefox.
#
#   powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Kirusshenkin/leash-firefox-extension/master/scripts/get.ps1' -OutFile $env:TEMP\get.ps1; & $env:TEMP\get.ps1"
#
# LEASH_VERSION=v0.2.0 — конкретный релиз (по умолчанию последний),
# LEASH_BIN_DIR=… — другой каталог.

param(
    [string]$LEASH_VERSION = "latest",
    [string]$LEASH_BIN_DIR = "$env:LOCALAPPDATA\Leash"
)

$repo = "Kirusshenkin/leash-firefox-extension"
$target = "x86_64-pc-windows-msvc"

if ($LEASH_VERSION -eq "latest") {
    $base = "https://github.com/$repo/releases/latest/download"
} else {
    $base = "https://github.com/$repo/releases/download/$LEASH_VERSION"
}

$tmp = New-TemporaryDirectory
$file = "leash-host-$target.exe"

try {
    Write-Host "Скачивание $file..."
    Invoke-WebRequest -Uri "$base/$file" -OutFile "$tmp\$file" -UseBasicParsing
    Write-Host "Скачивание SHA256SUMS..."
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing

    Write-Host "Проверка SHA-256..."
    $sums = Get-Content "$tmp\SHA256SUMS" | ConvertFrom-String -PropertyNames Hash, File
    $want = ($sums | Where-Object { $_.File -eq $file }).Hash
    $got = (Get-FileHash "$tmp\$file" -Algorithm SHA256).Hash.ToLower()

    if ([string]::IsNullOrEmpty($want) -or $want.ToLower() -ne $got) {
        Write-Error "SHA-256 не совпал ($file): ожидался '$want', получен '$got'"
        exit 1
    }

    if (-not (Test-Path $LEASH_BIN_DIR)) {
        New-Item -ItemType Directory -Path $LEASH_BIN_DIR -Force | Out-Null
    }

    Write-Host "Установка в $LEASH_BIN_DIR..."
    Copy-Item "$tmp\$file" "$LEASH_BIN_DIR\leash-host.exe" -Force

    Write-Host "Регистрация в Firefox..."
    & "$LEASH_BIN_DIR\leash-host.exe" install
}
finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
