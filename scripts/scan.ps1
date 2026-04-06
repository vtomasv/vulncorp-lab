<#
.SYNOPSIS
    VulnCorp Lab - Escaneo de Vulnerabilidades con Trivy (PowerShell)
.DESCRIPTION
    Script nativo de PowerShell para Windows.
    Alternativa a scan.sh para usuarios que prefieren PowerShell.
    
    Curso: Gestion de Vulnerabilidades con Enfoque MITRE - 2026
.USAGE
    .\scripts\scan.ps1              # Modo normal
    .\scripts\scan.ps1 -Verbose     # Modo verbose
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

# --- Configuracion ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$DataDir = Join-Path $ProjectDir "data"
$LogFile = Join-Path $DataDir "scan.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Crear directorio de datos
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

# Iniciar log
"" | Set-Content -Path $LogFile -Encoding UTF8
"=== VulnCorp Scan Log ===" | Add-Content -Path $LogFile -Encoding UTF8
"Timestamp: $Timestamp" | Add-Content -Path $LogFile -Encoding UTF8
"Platform: Windows PowerShell $($PSVersionTable.PSVersion)" | Add-Content -Path $LogFile -Encoding UTF8
"DataDir: $DataDir" | Add-Content -Path $LogFile -Encoding UTF8

# --- Imagenes a escanear ---
$Services = @(
    @{ Name="nginx-proxy";   Image="nginx:1.21.0";                       Zone="produccion";              Exposure="internet";          Criticality="alta" }
    @{ Name="prestashop";    Image="prestashop/prestashop:1.7.8.0";      Zone="produccion";              Exposure="internet-via-proxy"; Criticality="critica" }
    @{ Name="mariadb-prod";  Image="mariadb:10.5.18";                    Zone="produccion+corporativa";  Exposure="interna";           Criticality="critica" }
    @{ Name="redis-cache";   Image="redis:6.2.6";                        Zone="produccion";              Exposure="interna";           Criticality="media" }
    @{ Name="phpmyadmin";    Image="phpmyadmin:5.1.1";                   Zone="corporativa";             Exposure="red-interna";       Criticality="alta" }
    @{ Name="workstation";   Image="ubuntu:20.04";                       Zone="corporativa";             Exposure="red-interna";       Criticality="baja" }
    @{ Name="ftp-server";    Image="delfer/alpine-ftp-server";           Zone="corporativa";             Exposure="red-interna";       Criticality="media" }
)

# --- Funciones de utilidad ---
function Write-Header {
    Write-Host ""
    Write-Host "+============================================================+" -ForegroundColor Cyan
    Write-Host "|     VulnCorp -- Escaner de Vulnerabilidades (Trivy)        |" -ForegroundColor Cyan
    Write-Host "|     Unidad 1: Gestion de Vulnerabilidades (MITRE)          |" -ForegroundColor Cyan
    Write-Host "+============================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Plataforma: Windows PowerShell" -ForegroundColor Gray
    Write-Host "  Directorio: $DataDir" -ForegroundColor Gray
    Write-Host ""
}

function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "  [X] $msg" -ForegroundColor Red }
function Write-Info($msg)  { Write-Host "  [i] $msg" -ForegroundColor Cyan }

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 1: Verificar herramientas
# ═══════════════════════════════════════════════════════════════════════════════

Write-Header

Write-Host "[1/4] Verificando herramientas..." -ForegroundColor Yellow

# Docker
try {
    $dockerVer = docker --version 2>&1
    Write-Ok "Docker: $dockerVer"
} catch {
    Write-Fail "Docker no encontrado. Instale Docker Desktop."
    exit 1
}

# Trivy
$trivyCmd = Get-Command trivy -ErrorAction SilentlyContinue
if (-not $trivyCmd) {
    Write-Fail "Trivy no encontrado. Instale con:"
    Write-Host "      choco install trivy" -ForegroundColor Gray
    Write-Host "      scoop install trivy" -ForegroundColor Gray
    Write-Host "      winget install AquaSecurity.Trivy" -ForegroundColor Gray
    exit 1
}
$trivyVer = trivy --version 2>&1 | Select-Object -First 1
Write-Ok "Trivy: $trivyVer"
"Trivy: $trivyVer" | Add-Content -Path $LogFile -Encoding UTF8

# Python
$pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $pythonCmd) {
    Write-Fail "Python 3 no encontrado."
    exit 1
}
$PythonExe = $pythonCmd.Source
$pythonVer = & $PythonExe --version 2>&1
Write-Ok "Python: $pythonVer"

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 2: Actualizar base de datos
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "[2/4] Actualizando base de datos de vulnerabilidades..." -ForegroundColor Yellow
Write-Info "Esto puede tomar unos minutos la primera vez."

# Limpiar cache
trivy clean --scan-cache 2>&1 | Out-Null

$dbOk = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    "DB download attempt $attempt/3" | Add-Content -Path $LogFile -Encoding UTF8
    
    $dbOutput = trivy image --download-db-only 2>&1
    if ($LASTEXITCODE -eq 0) {
        $dbOk = $true
        Write-Ok "Base de datos actualizada"
        break
    }
    
    Write-Warn "Intento $attempt/3 fallido. Limpiando DB..."
    trivy clean --vuln-db 2>&1 | Out-Null
    Start-Sleep -Seconds 2
}

if (-not $dbOk) {
    Write-Fail "No se pudo descargar la base de datos."
    Write-Fail "Verifique su conexion a Internet."
    exit 1
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 3: Escanear imagenes
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "[3/4] Escaneando imagenes del laboratorio VulnCorp..." -ForegroundColor Yellow

# Limpiar resumen anterior
$summaryFile = Join-Path $DataDir "scan_summary.jsonl"
if (Test-Path $summaryFile) { Remove-Item $summaryFile -Force }

foreach ($svc in $Services) {
    $name = $svc.Name
    $image = $svc.Image
    $zone = $svc.Zone
    $exposure = $svc.Exposure
    $criticality = $svc.Criticality
    $reportFile = Join-Path $DataDir "${name}_trivy.json"

    Write-Host ""
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue
    Write-Host "  Escaneando: $name" -ForegroundColor White
    Write-Host "  Imagen:     $image" -ForegroundColor Gray
    Write-Host "  Zona:       $zone | Exposicion: $exposure | Criticidad: $criticality" -ForegroundColor Gray
    Write-Host "  Reporte:    $reportFile" -ForegroundColor Gray
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue

    "=== Scan: $name ($image) ===" | Add-Content -Path $LogFile -Encoding UTF8

    $scanOk = $false
    $crit = 0; $high = 0; $med = 0; $low = 0; $total = 0

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        if ($attempt -gt 1) {
            Write-Warn "Reintento $attempt/2 - Limpiando cache..."
            trivy clean --scan-cache 2>&1 | Out-Null
            Start-Sleep -Seconds 1
        }

        # Eliminar reporte anterior
        if (Test-Path $reportFile) { Remove-Item $reportFile -Force }

        # ─── ESCANEO ─────────────────────────────────────────────────
        # Usamos redireccion nativa de PowerShell (>) para escribir
        # el archivo. Esto evita problemas con el flag --output de
        # Trivy en Windows.
        $errFile = Join-Path $DataDir "${name}_scan.err"

        # Ejecutar Trivy y capturar stdout a archivo
        $trivyArgs = @("image", "--format", "json", "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--skip-db-update", $image)
        
        try {
            & trivy $trivyArgs 2>$errFile | Set-Content -Path $reportFile -Encoding UTF8 -NoNewline
        } catch {
            "Trivy exception: $_" | Add-Content -Path $LogFile -Encoding UTF8
        }

        $exitCode = $LASTEXITCODE
        "Exit code: $exitCode" | Add-Content -Path $LogFile -Encoding UTF8

        if ($VerbosePreference -eq "Continue" -and (Test-Path $errFile)) {
            Write-Host "  --- Salida de Trivy (stderr) ---" -ForegroundColor Cyan
            Get-Content $errFile
            Write-Host "  --- Fin ---" -ForegroundColor Cyan
        }

        if ($exitCode -ne 0) {
            Write-Fail "Trivy fallo (exit code: $exitCode)"
            if (Test-Path $errFile) {
                Get-Content $errFile | Select-Object -Last 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
            }
            continue
        }

        # Verificar archivo
        if (-not (Test-Path $reportFile)) {
            Write-Fail "Archivo de reporte no se genero"
            continue
        }

        $fileSize = (Get-Item $reportFile).Length
        if ($fileSize -lt 10) {
            Write-Warn "Reporte muy pequeno ($fileSize bytes)"
            continue
        }

        Write-Info "Archivo generado: $fileSize bytes"
        "Report size: $fileSize bytes" | Add-Content -Path $LogFile -Encoding UTF8

        # ─── CONTAR VULNERABILIDADES ─────────────────────────────────
        $pyScript = @"
import json, sys
try:
    with open(r'$reportFile', encoding='utf-8-sig') as f:
        raw = f.read()
    raw = raw.lstrip('\ufeff').replace('\x00', '').strip()
    data = json.loads(raw)
    c = h = m = l = 0
    for r in data.get('Results', []):
        for v in (r.get('Vulnerabilities') or []):
            s = v.get('Severity', '')
            if s == 'CRITICAL': c += 1
            elif s == 'HIGH': h += 1
            elif s == 'MEDIUM': m += 1
            elif s == 'LOW': l += 1
    print(f'{c} {h} {m} {l} {c+h+m+l}')
except Exception as e:
    print('0 0 0 0 0')
    print(f'ERROR: {e}', file=sys.stderr)
"@
        $counts = & $PythonExe -c $pyScript 2>>$LogFile
        $parts = $counts.Trim().Split(' ')

        if ($parts.Count -ge 5) {
            $crit  = [int]$parts[0]
            $high  = [int]$parts[1]
            $med   = [int]$parts[2]
            $low   = [int]$parts[3]
            $total = [int]$parts[4]
        }

        "Counts: C=$crit H=$high M=$med L=$low T=$total" | Add-Content -Path $LogFile -Encoding UTF8

        # Limpiar archivo de error
        if (Test-Path $errFile) { Remove-Item $errFile -Force }
        $scanOk = $true
        break
    }

    if (-not $scanOk) {
        Write-Fail "No se pudo escanear $name despues de 2 intentos."
        '{"Results":[]}' | Set-Content -Path $reportFile -Encoding UTF8
        $crit = 0; $high = 0; $med = 0; $low = 0; $total = 0
    }

    # Mostrar resumen
    Write-Host ""
    Write-Host "  CRITICAL: $crit  |  HIGH: $high  |  MEDIUM: $med  |  LOW: $low  |  TOTAL: $total"
    Write-Ok "Reporte: $reportFile"

    # Guardar en JSONL
    $jsonLine = "{`"service`":`"$name`",`"image`":`"$image`",`"zone`":`"$zone`",`"exposure`":`"$exposure`",`"criticality`":`"$criticality`",`"critical`":$crit,`"high`":$high,`"medium`":$med,`"low`":$low,`"total`":$total,`"timestamp`":`"$Timestamp`"}"
    $jsonLine | Add-Content -Path $summaryFile -Encoding UTF8
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 4: Reporte consolidado
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "[4/4] Generando reporte consolidado..." -ForegroundColor Yellow

$pyConsolidate = @"
import json, os, sys

data_dir = r'$DataDir'
summary_file = os.path.join(data_dir, 'scan_summary.jsonl')

if not os.path.exists(summary_file):
    print("  No se encontraron resultados de escaneo.")
    sys.exit(0)

services = []
with open(summary_file, 'r', encoding='utf-8-sig') as f:
    for line in f:
        line = line.strip().lstrip('\ufeff').replace('\x00', '')
        if not line: continue
        try: services.append(json.loads(line))
        except: continue

if not services:
    print("  No se encontraron resultados validos.")
    sys.exit(0)

header = f"  {'Servicio':<16} {'Zona':<22} {'Exposicion':<18} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'TOTAL':>6}"
sep    = f"  {'-'*16} {'-'*22} {'-'*18} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*6}"

print()
print(header)
print(sep)

tc = th = tm = tl = tt = 0
for s in services:
    print(f"  {s['service']:<16} {s['zone']:<22} {s['exposure']:<18} {s['critical']:>5} {s['high']:>5} {s['medium']:>5} {s['low']:>5} {s['total']:>6}")
    tc += s['critical']; th += s['high']; tm += s['medium']; tl += s['low']; tt += s['total']

print(sep)
print(f"  {'TOTAL':<16} {'':<22} {'':<18} {tc:>5} {th:>5} {tm:>5} {tl:>5} {tt:>6}")
print()

consolidated = {
    "scan_timestamp": services[0].get('timestamp', ''),
    "total_services": len(services),
    "total_vulnerabilities": tt,
    "by_severity": {"critical": tc, "high": th, "medium": tm, "low": tl},
    "services": services
}

out = os.path.join(data_dir, 'consolidated_report.json')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(consolidated, f, indent=2, ensure_ascii=False)

print(f"  Reporte consolidado: {out}")
"@

& $PythonExe -c $pyConsolidate

Write-Host ""
Write-Host "+============================================================+" -ForegroundColor Green
Write-Host "|  Escaneo completado                                        |" -ForegroundColor Green
Write-Host "+============================================================+" -ForegroundColor Green
Write-Host ""
Write-Info "Reportes en: $DataDir"
Write-Info "Dashboard:   http://localhost:3000"
Write-Info "Log:         $LogFile"
Write-Host ""
