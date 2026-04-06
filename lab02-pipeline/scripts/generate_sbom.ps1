<#
.SYNOPSIS
    VulnCorp Lab 02 - Generacion de SBOM con Syft (PowerShell)
.DESCRIPTION
    Script nativo de PowerShell para Windows.
    Genera SBOMs en formato CycloneDX usando Syft.
    Usa cmd /c para redireccion, evitando problemas de codificacion.
.USAGE
    .\scripts\generate_sbom.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Lab02Dir = Split-Path -Parent $ScriptDir
$SbomDir = Join-Path $Lab02Dir "data" "sbom"

if (-not (Test-Path $SbomDir)) {
    New-Item -ItemType Directory -Path $SbomDir -Force | Out-Null
}

# --- Funciones ---
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "  [X] $msg" -ForegroundColor Red }
function Write-Info($msg)  { Write-Host "  [i] $msg" -ForegroundColor Cyan }

function Remove-BOM([string]$FilePath) {
    if (-not (Test-Path $FilePath)) { return }
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $clean = New-Object byte[] ($bytes.Length - 3)
        [System.Array]::Copy($bytes, 3, $clean, 0, $clean.Length)
        [System.IO.File]::WriteAllBytes($FilePath, $clean)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
        $utf8 = [System.Text.Encoding]::UTF8.GetBytes($text)
        [System.IO.File]::WriteAllBytes($FilePath, $utf8)
    }
}

# Detectar Python
$PythonExe = $null
foreach ($cmd in @("python3", "python", "py")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) {
        $testVer = & $found.Source --version 2>&1
        if ($testVer -match "Python 3") { $PythonExe = $found.Source; break }
    }
}
if (-not $PythonExe) {
    Write-Fail "Python 3 no encontrado."
    exit 1
}

# --- Header ---
Write-Host ""
Write-Host "+============================================================+" -ForegroundColor Cyan
Write-Host "|  VulnCorp Lab 02 -- Generacion de SBOM con Syft           |" -ForegroundColor Cyan
Write-Host "|  Formato: CycloneDX (OWASP Standard)                      |" -ForegroundColor Cyan
Write-Host "+============================================================+" -ForegroundColor Cyan
Write-Host ""

# Verificar Syft
$syftCmd = Get-Command syft -ErrorAction SilentlyContinue
if (-not $syftCmd) {
    Write-Fail "Syft no encontrado. Ejecute primero: .\scripts\setup_lab02.sh"
    exit 1
}
$syftVer = & syft version 2>&1 | Select-Object -First 1
Write-Ok "Syft: $syftVer"
Write-Host ""

# --- Imagenes ---
$Services = @(
    @{ Name="nginx-proxy";   Image="nginx:1.21.0" }
    @{ Name="prestashop";    Image="prestashop/prestashop:1.7.8.0" }
    @{ Name="mariadb-prod";  Image="mariadb:10.5.18" }
    @{ Name="redis-cache";   Image="redis:6.2.6" }
    @{ Name="phpmyadmin";    Image="phpmyadmin:5.1.1" }
    @{ Name="workstation";   Image="ubuntu:20.04" }
    @{ Name="ftp-server";    Image="delfer/alpine-ftp-server" }
)

$Total = $Services.Count
$Current = 0

foreach ($svc in $Services) {
    $Current++
    $name = $svc.Name
    $image = $svc.Image
    $jsonFile = Join-Path $SbomDir "${name}_sbom_cyclonedx.json"
    $xmlFile = Join-Path $SbomDir "${name}_sbom_cyclonedx.xml"
    $tableFile = Join-Path $SbomDir "${name}_sbom_table.txt"
    $errFile = Join-Path $SbomDir "${name}_sbom.err"

    Write-Host ""
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue
    Write-Host "  [$Current/$Total] Generando SBOM: $name" -ForegroundColor White
    Write-Host "  Imagen: $image" -ForegroundColor Gray
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue

    # --- CycloneDX JSON ---
    Write-Info "Generando CycloneDX JSON..."
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "syft `"$image`" -o cyclonedx-json > `"$jsonFile`" 2> `"$errFile`"" `
        -Wait -NoNewWindow -PassThru

    Remove-BOM -FilePath $jsonFile

    if ((Test-Path $jsonFile) -and (Get-Item $jsonFile).Length -gt 10) {
        # Contar componentes
        $pyScript = Join-Path $SbomDir "_count.py"
        @"
import json
with open(r'$jsonFile', encoding='utf-8-sig') as f:
    raw = f.read().lstrip('\ufeff').replace('\x00','')
data = json.loads(raw)
print(len(data.get('components', [])))
"@ | Set-Content -Path $pyScript -Encoding ASCII
        $compCount = & $PythonExe $pyScript 2>&1
        Remove-Item $pyScript -Force -ErrorAction SilentlyContinue
        Write-Ok "CycloneDX JSON: $jsonFile"
        Write-Info "Componentes encontrados: $compCount"
    } else {
        Write-Fail "Error generando SBOM JSON para $image"
        if (Test-Path $errFile) {
            Get-Content $errFile -Tail 3 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
        }
        continue
    }

    # --- CycloneDX XML ---
    Write-Info "Generando CycloneDX XML..."
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "syft `"$image`" -o cyclonedx-xml > `"$xmlFile`" 2> NUL" `
        -Wait -NoNewWindow -PassThru
    Remove-BOM -FilePath $xmlFile
    if ((Test-Path $xmlFile) -and (Get-Item $xmlFile).Length -gt 10) {
        Write-Ok "CycloneDX XML: $xmlFile"
    }

    # --- Tabla ---
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "syft `"$image`" -o table > `"$tableFile`" 2> NUL" `
        -Wait -NoNewWindow -PassThru
    Write-Ok "Tabla resumen: $tableFile"

    # Limpiar error file
    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
}

# --- Resumen ---
Write-Host ""
Write-Host "+============================================================+" -ForegroundColor Cyan
Write-Host "|              RESUMEN DE SBOMs GENERADOS                    |" -ForegroundColor Cyan
Write-Host "+============================================================+" -ForegroundColor Cyan
Write-Host ""

$pySummary = Join-Path $SbomDir "_summary.py"
@"
import json, os, glob
sbom_dir = r'$SbomDir'
json_files = sorted(glob.glob(os.path.join(sbom_dir, '*_cyclonedx.json')))
print(f"  {'Servicio':<18} {'Componentes':>12} {'Tipo BOM':<14} {'Spec Version':<14}")
print(f"  {'-'*18} {'-'*12} {'-'*14} {'-'*14}")
total = 0
for jf in json_files:
    try:
        with open(jf, encoding='utf-8-sig') as f:
            raw = f.read().lstrip('\ufeff').replace('\x00','')
        data = json.loads(raw)
        name = os.path.basename(jf).replace('_sbom_cyclonedx.json', '')
        cc = len(data.get('components', []))
        total += cc
        print(f"  {name:<18} {cc:>12} {data.get('bomFormat','N/A'):<14} {data.get('specVersion','N/A'):<14}")
    except Exception as e:
        print(f"  Error: {e}")
print(f"  {'-'*18} {'-'*12} {'-'*14} {'-'*14}")
print(f"  {'TOTAL':<18} {total:>12}")
print()
summary = {"total_images": len(json_files), "total_components": total, "sbom_files": [os.path.basename(f) for f in json_files]}
out = os.path.join(sbom_dir, 'sbom_summary.json')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)
print(f"  Resumen guardado en: {out}")
"@ | Set-Content -Path $pySummary -Encoding ASCII
& $PythonExe $pySummary
Remove-Item $pySummary -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Ok "Generacion de SBOMs completada"
Write-Info "Archivos en: $SbomDir"
Write-Host ""
Write-Info "Proximo paso:"
Write-Host "    Escanear vulnerabilidades: .\scripts\scan_grype.ps1" -ForegroundColor Cyan
Write-Host ""
