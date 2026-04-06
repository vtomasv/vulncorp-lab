<#
.SYNOPSIS
    VulnCorp Lab 02 - Escaneo de Vulnerabilidades con Grype (PowerShell)
.DESCRIPTION
    Script nativo de PowerShell para Windows.
    Escanea SBOMs CycloneDX con Grype para detectar vulnerabilidades.
    Usa cmd /c para redireccion, evitando problemas de codificacion.
.USAGE
    .\scripts\scan_grype.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Lab02Dir = Split-Path -Parent $ScriptDir
$SbomDir = Join-Path $Lab02Dir "data" "sbom"
$GrypeDir = Join-Path $Lab02Dir "data" "grype"

if (-not (Test-Path $GrypeDir)) {
    New-Item -ItemType Directory -Path $GrypeDir -Force | Out-Null
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
Write-Host "|  VulnCorp Lab 02 -- Escaneo de Vulnerabilidades con Grype  |" -ForegroundColor Cyan
Write-Host "|  Fuente: SBOMs CycloneDX generados por Syft               |" -ForegroundColor Cyan
Write-Host "+============================================================+" -ForegroundColor Cyan
Write-Host ""

# Verificar Grype
$grypeCmd = Get-Command grype -ErrorAction SilentlyContinue
if (-not $grypeCmd) {
    Write-Fail "Grype no encontrado. Ejecute primero: .\scripts\setup_lab02.sh"
    exit 1
}
$grypeVer = & grype version 2>&1 | Select-Object -First 1
Write-Ok "Grype: $grypeVer"

# Verificar SBOMs
$sbomFiles = Get-ChildItem -Path $SbomDir -Filter "*_sbom_cyclonedx.json" -ErrorAction SilentlyContinue
if (-not $sbomFiles -or $sbomFiles.Count -eq 0) {
    Write-Fail "No se encontraron SBOMs en $SbomDir"
    Write-Info "Ejecute primero: .\scripts\generate_sbom.ps1"
    exit 1
}
Write-Ok "SBOMs encontrados: $($sbomFiles.Count) archivos"
Write-Host ""

# Actualizar DB
Write-Info "Actualizando base de datos de Grype..."
& grype db update 2>&1 | Out-Null
Write-Host ""

# Limpiar resumen anterior
$summaryFile = Join-Path $GrypeDir "grype_summary.jsonl"
if (Test-Path $summaryFile) { Remove-Item $summaryFile -Force }

$Total = $sbomFiles.Count
$Current = 0

foreach ($sbomFile in $sbomFiles) {
    $Current++
    $basename = $sbomFile.Name -replace '_sbom_cyclonedx\.json$', ''
    $sbomPath = $sbomFile.FullName
    $cyclonedxOut = Join-Path $GrypeDir "${basename}_grype_cyclonedx.json"
    $jsonOut = Join-Path $GrypeDir "${basename}_grype_detail.json"
    $tableOut = Join-Path $GrypeDir "${basename}_grype_table.txt"
    $errFile = Join-Path $GrypeDir "${basename}_grype.err"

    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue
    Write-Host "  [$Current/$Total] Escaneando: $basename" -ForegroundColor White
    Write-Host "  SBOM: $sbomPath" -ForegroundColor Gray
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue

    # --- CycloneDX output ---
    Write-Info "Generando reporte CycloneDX..."
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "grype `"sbom:$sbomPath`" -o cyclonedx-json > `"$cyclonedxOut`" 2> `"$errFile`"" `
        -Wait -NoNewWindow -PassThru
    Remove-BOM -FilePath $cyclonedxOut

    if ((Test-Path $cyclonedxOut) -and (Get-Item $cyclonedxOut).Length -gt 10) {
        Write-Ok "CycloneDX: $cyclonedxOut"
    } else {
        Write-Warn "Error generando CycloneDX para $basename"
    }

    # --- JSON detallado ---
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "grype `"sbom:$sbomPath`" -o json > `"$jsonOut`" 2> NUL" `
        -Wait -NoNewWindow -PassThru
    Remove-BOM -FilePath $jsonOut

    # --- Contar vulnerabilidades ---
    $crit = 0; $high = 0; $med = 0; $low = 0; $neg = 0; $tot = 0
    if ((Test-Path $jsonOut) -and (Get-Item $jsonOut).Length -gt 10) {
        $pyCount = Join-Path $GrypeDir "_count.py"
        @"
import json, sys
try:
    with open(r'$jsonOut', encoding='utf-8-sig') as f:
        raw = f.read().lstrip('\ufeff').replace('\x00','')
    data = json.loads(raw)
    matches = data.get('matches', [])
    counts = {'Critical':0, 'High':0, 'Medium':0, 'Low':0, 'Negligible':0}
    for m in matches:
        sev = m.get('vulnerability',{}).get('severity','Unknown')
        if sev in counts: counts[sev] += 1
    total = sum(counts.values())
    print(f"{counts['Critical']} {counts['High']} {counts['Medium']} {counts['Low']} {counts['Negligible']} {total}")
except Exception as e:
    print('0 0 0 0 0 0')
"@ | Set-Content -Path $pyCount -Encoding ASCII
        $counts = & $PythonExe $pyCount 2>&1
        Remove-Item $pyCount -Force -ErrorAction SilentlyContinue
        $parts = ($counts | Out-String).Trim().Split(' ')
        if ($parts.Count -ge 6) {
            $crit = [int]$parts[0]; $high = [int]$parts[1]; $med = [int]$parts[2]
            $low = [int]$parts[3]; $neg = [int]$parts[4]; $tot = [int]$parts[5]
        }

        $critColor = if ($crit -gt 0) { "Red" } else { "Gray" }
        $highColor = if ($high -gt 0) { "Yellow" } else { "Gray" }
        Write-Host "  CRITICAL: " -NoNewline; Write-Host "$crit" -ForegroundColor $critColor -NoNewline
        Write-Host " | HIGH: " -NoNewline; Write-Host "$high" -ForegroundColor $highColor -NoNewline
        Write-Host " | MEDIUM: $med | LOW: $low | NEG: $neg | TOTAL: $tot"
    }

    # --- Tabla ---
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "grype `"sbom:$sbomPath`" -o table > `"$tableOut`" 2> NUL" `
        -Wait -NoNewWindow -PassThru
    Write-Ok "Tabla: $tableOut"

    # Guardar resumen (sin BOM)
    $jsonLine = "{`"service`":`"$basename`",`"critical`":$crit,`"high`":$high,`"medium`":$med,`"low`":$low,`"negligible`":$neg,`"total`":$tot}"
    [System.IO.File]::AppendAllText($summaryFile, "$jsonLine`n", (New-Object System.Text.UTF8Encoding $false))

    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
    Write-Host ""
}

# --- Resumen ---
Write-Host "+============================================================+" -ForegroundColor Cyan
Write-Host "|           RESUMEN DE VULNERABILIDADES (GRYPE)              |" -ForegroundColor Cyan
Write-Host "+============================================================+" -ForegroundColor Cyan
Write-Host ""

$pySummary = Join-Path $GrypeDir "_summary.py"
@"
import json, os
grype_dir = r'$GrypeDir'
summary_file = os.path.join(grype_dir, 'grype_summary.jsonl')
if not os.path.exists(summary_file):
    print("  No se encontraron resultados.")
    exit(0)
services = []
with open(summary_file, encoding='utf-8-sig') as f:
    for line in f:
        line = line.strip().lstrip('\ufeff').replace('\x00','')
        if not line: continue
        try: services.append(json.loads(line))
        except: continue
print(f"  {'Servicio':<18} {'CRIT':>6} {'HIGH':>6} {'MED':>6} {'LOW':>6} {'NEG':>6} {'TOTAL':>7}")
print(f"  {'-'*18} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*7}")
tc=th=tm=tl=tn=tt=0
for s in services:
    print(f"  {s['service']:<18} {s['critical']:>6} {s['high']:>6} {s['medium']:>6} {s['low']:>6} {s['negligible']:>6} {s['total']:>7}")
    tc+=s['critical'];th+=s['high'];tm+=s['medium'];tl+=s['low'];tn+=s['negligible'];tt+=s['total']
print(f"  {'-'*18} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*7}")
print(f"  {'TOTAL':<18} {tc:>6} {th:>6} {tm:>6} {tl:>6} {tn:>6} {tt:>7}")
print()
out = os.path.join(grype_dir, 'grype_consolidated.json')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    json.dump({"total_services":len(services),"total_vulnerabilities":tt,"by_severity":{"critical":tc,"high":th,"medium":tm,"low":tl,"negligible":tn},"services":services}, f, indent=2)
print(f"  Consolidado guardado en: {out}")
"@ | Set-Content -Path $pySummary -Encoding ASCII
& $PythonExe $pySummary
Remove-Item $pySummary -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Ok "Escaneo con Grype completado"
Write-Info "Reportes en: $GrypeDir"
Write-Host ""
Write-Info "Proximo paso:"
Write-Host "    Subir a plataformas: $PythonExe scripts\upload_reports.py" -ForegroundColor Cyan
Write-Host ""
