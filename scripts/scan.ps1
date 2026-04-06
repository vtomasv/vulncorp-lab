<#
.SYNOPSIS
    VulnCorp Lab - Escaneo de Vulnerabilidades con Trivy (PowerShell)
.DESCRIPTION
    Script nativo de PowerShell para Windows.
    Usa cmd /c para redirigir la salida de Trivy, evitando problemas
    de codificacion (BOM, UTF-16) que PowerShell introduce al redirigir
    la salida de binarios externos.

    Curso: Gestion de Vulnerabilidades con Enfoque MITRE - 2026
.USAGE
    .\scripts\scan.ps1
    .\scripts\scan.ps1 -Verbose
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

# --- Funcion para escribir log ---
function Write-Log($msg) {
    $msg | Add-Content -Path $LogFile -Encoding ASCII
}

# Iniciar log
"=== VulnCorp Scan Log ===" | Set-Content -Path $LogFile -Encoding ASCII
Write-Log "Timestamp: $Timestamp"
Write-Log "Platform: PowerShell $($PSVersionTable.PSVersion) on $([System.Environment]::OSVersion.VersionString)"
Write-Log "DataDir: $DataDir"

# --- Funcion para ejecutar Trivy con cmd /c ---
# Esto evita que PowerShell modifique la codificacion de la salida.
# cmd /c pasa la salida binaria directamente al archivo sin BOM ni conversion.
function Invoke-TrivyToFile {
    param(
        [string]$Arguments,
        [string]$OutputFile,
        [string]$ErrorFile
    )

    # Construir comando cmd /c con rutas escapadas
    # Usamos comillas dobles alrededor de las rutas para manejar espacios
    $cmdLine = "trivy $Arguments > `"$OutputFile`" 2> `"$ErrorFile`""
    Write-Log "CMD: cmd /c $cmdLine"

    $process = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", $cmdLine `
        -Wait -NoNewWindow -PassThru

    return $process.ExitCode
}

# --- Funcion para limpiar BOM de un archivo (por si acaso) ---
function Remove-BOM {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) { return }

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Log "BOM detectado y eliminado en: $FilePath"
        $clean = New-Object byte[] ($bytes.Length - 3)
        [System.Array]::Copy($bytes, 3, $clean, 0, $clean.Length)
        [System.IO.File]::WriteAllBytes($FilePath, $clean)
    }
    # BOM UTF-16 LE
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        Write-Log "BOM UTF-16LE detectado en: $FilePath - Convirtiendo a UTF-8"
        $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
        $utf8 = [System.Text.Encoding]::UTF8.GetBytes($text)
        [System.IO.File]::WriteAllBytes($FilePath, $utf8)
    }
}

# --- Funcion para leer JSON limpio ---
function Read-CleanJson {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) { return $null }

    Remove-BOM -FilePath $FilePath

    try {
        $raw = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::UTF8)
        $raw = $raw.TrimStart([char]0xFEFF).Replace("`0", "").Trim()
        return $raw | ConvertFrom-Json
    } catch {
        Write-Log "Error parseando JSON $FilePath : $_"
        return $null
    }
}

# --- Imagenes a escanear ---
$Services = @(
    @{ Name="nginx-proxy";   Image="nginx:1.21.0";                       Zone="produccion";              Exposure="internet";           Criticality="alta" }
    @{ Name="prestashop";    Image="prestashop/prestashop:1.7.8.0";      Zone="produccion";              Exposure="internet-via-proxy";  Criticality="critica" }
    @{ Name="mariadb-prod";  Image="mariadb:10.5.18";                    Zone="produccion+corporativa";  Exposure="interna";            Criticality="critica" }
    @{ Name="redis-cache";   Image="redis:6.2.6";                        Zone="produccion";              Exposure="interna";            Criticality="media" }
    @{ Name="phpmyadmin";    Image="phpmyadmin:5.1.1";                   Zone="corporativa";             Exposure="red-interna";        Criticality="alta" }
    @{ Name="workstation";   Image="ubuntu:20.04";                       Zone="corporativa";             Exposure="red-interna";        Criticality="baja" }
    @{ Name="ftp-server";    Image="delfer/alpine-ftp-server";           Zone="corporativa";             Exposure="red-interna";        Criticality="media" }
)

# --- Funciones de utilidad ---
function Write-Header {
    Write-Host ""
    Write-Host "+============================================================+" -ForegroundColor Cyan
    Write-Host "|     VulnCorp -- Escaner de Vulnerabilidades (Trivy)        |" -ForegroundColor Cyan
    Write-Host "|     Unidad 1: Gestion de Vulnerabilidades (MITRE)          |" -ForegroundColor Cyan
    Write-Host "+============================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Plataforma: PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "  Directorio: $DataDir" -ForegroundColor Gray
    Write-Host ""
}

function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "  [X] $msg" -ForegroundColor Red }
function Write-Info($msg)  { Write-Host "  [i] $msg" -ForegroundColor Cyan }

# =====================================================================
#  PASO 1: Verificar herramientas
# =====================================================================

Write-Header

Write-Host "[1/4] Verificando herramientas..." -ForegroundColor Yellow

# Docker
try {
    $dockerVer = & docker --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Docker: $dockerVer"
    } else {
        Write-Fail "Docker no responde correctamente."
        exit 1
    }
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
$trivyVer = & trivy version 2>&1 | Select-Object -First 1
Write-Ok "Trivy: $trivyVer"
Write-Log "Trivy: $trivyVer"

# Python
$PythonExe = $null
foreach ($cmd in @("python3", "python", "py")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) {
        $testVer = & $found.Source --version 2>&1
        if ($testVer -match "Python 3") {
            $PythonExe = $found.Source
            break
        }
    }
}
if (-not $PythonExe) {
    Write-Fail "Python 3 no encontrado."
    exit 1
}
$pythonVer = & $PythonExe --version 2>&1
Write-Ok "Python: $pythonVer ($PythonExe)"

# =====================================================================
#  PASO 2: Actualizar base de datos
# =====================================================================

Write-Host ""
Write-Host "[2/4] Actualizando base de datos de vulnerabilidades..." -ForegroundColor Yellow
Write-Info "Esto puede tomar unos minutos la primera vez."

# Limpiar scan cache
& trivy clean --scan-cache 2>&1 | Out-Null

$dbOk = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Log "DB download attempt $attempt/3"

    # Usar cmd /c para evitar problemas de PowerShell con la salida de Trivy
    $dbErrFile = Join-Path $DataDir "db_download.err"
    $exitCode = Invoke-TrivyToFile -Arguments "image --download-db-only" -OutputFile "NUL" -ErrorFile $dbErrFile

    if ($exitCode -eq 0) {
        $dbOk = $true
        Write-Ok "Base de datos actualizada"
        if (Test-Path $dbErrFile) { Remove-Item $dbErrFile -Force -ErrorAction SilentlyContinue }
        break
    }

    Write-Warn "Intento $attempt/3 fallido."
    if (Test-Path $dbErrFile) {
        $errContent = Get-Content $dbErrFile -Tail 3 -ErrorAction SilentlyContinue
        if ($errContent) {
            $errContent | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
        }
    }

    Write-Info "Limpiando DB y reintentando..."
    & trivy clean --vuln-db 2>&1 | Out-Null
    Start-Sleep -Seconds 3
}

if (-not $dbOk) {
    Write-Fail "No se pudo descargar la base de datos despues de 3 intentos."
    Write-Fail "Verifique su conexion a Internet."
    exit 1
}

# =====================================================================
#  PASO 3: Escanear imagenes
# =====================================================================

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
    $errFile = Join-Path $DataDir "${name}_scan.err"

    Write-Host ""
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue
    Write-Host "  Escaneando: $name" -ForegroundColor White
    Write-Host "  Imagen:     $image" -ForegroundColor Gray
    Write-Host "  Zona:       $zone | Exposicion: $exposure" -ForegroundColor Gray
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue

    Write-Log "=== Scan: $name ($image) ==="

    $scanOk = $false
    $crit = 0; $high = 0; $med = 0; $low = 0; $total = 0

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        if ($attempt -gt 1) {
            Write-Warn "Reintento $attempt/2 - Limpiando cache..."
            & trivy clean --scan-cache 2>&1 | Out-Null
            Start-Sleep -Seconds 2
        }

        # Eliminar reporte anterior
        if (Test-Path $reportFile) { Remove-Item $reportFile -Force }
        if (Test-Path $errFile) { Remove-Item $errFile -Force }

        # ---- ESCANEO ----
        # Usamos cmd /c para redirigir la salida de Trivy.
        # Esto evita que PowerShell agregue BOM o convierta la codificacion.
        $trivyArgs = "image --format json --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --skip-db-update `"$image`""
        $exitCode = Invoke-TrivyToFile -Arguments $trivyArgs -OutputFile $reportFile -ErrorFile $errFile

        Write-Log "Exit code: $exitCode"

        if ($VerbosePreference -eq "Continue" -and (Test-Path $errFile)) {
            Write-Host "  --- Salida de Trivy (stderr) ---" -ForegroundColor DarkGray
            Get-Content $errFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            Write-Host "  --- Fin ---" -ForegroundColor DarkGray
        }

        if ($exitCode -ne 0) {
            Write-Fail "Trivy fallo (exit code: $exitCode)"
            if (Test-Path $errFile) {
                Get-Content $errFile -Tail 5 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
            }
            continue
        }

        # Verificar que el archivo existe y tiene contenido
        if (-not (Test-Path $reportFile)) {
            Write-Fail "Archivo de reporte no se genero"
            continue
        }

        $fileSize = (Get-Item $reportFile).Length
        if ($fileSize -lt 10) {
            Write-Warn "Reporte muy pequeno ($fileSize bytes). Posible archivo vacio."
            continue
        }

        # Limpiar BOM si existe
        Remove-BOM -FilePath $reportFile

        Write-Info "Archivo generado: $fileSize bytes"
        Write-Log "Report size: $fileSize bytes"

        # ---- CONTAR VULNERABILIDADES ----
        # Usamos Python para parsear el JSON de forma robusta
        $pyCountScript = Join-Path $DataDir "_count_vulns.py"
        @"
import json, sys
try:
    with open(r'$($reportFile.Replace("'","''"))', encoding='utf-8-sig') as f:
        raw = f.read()
    raw = raw.lstrip('\ufeff').replace('\x00', '').strip()
    if not raw:
        print('0 0 0 0 0')
        sys.exit(0)
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
"@ | Set-Content -Path $pyCountScript -Encoding ASCII

        $counts = & $PythonExe $pyCountScript 2>>$LogFile
        $parts = ($counts | Out-String).Trim().Split(' ')

        if ($parts.Count -ge 5) {
            $crit  = [int]$parts[0]
            $high  = [int]$parts[1]
            $med   = [int]$parts[2]
            $low   = [int]$parts[3]
            $total = [int]$parts[4]
        }

        Write-Log "Counts: C=$crit H=$high M=$med L=$low T=$total"

        # Si 0 vulnerabilidades en primer intento, verificar si es legitimo
        if ($total -eq 0 -and $attempt -eq 1) {
            $jsonData = Read-CleanJson -FilePath $reportFile
            if ($jsonData -and $jsonData.Results) {
                $pkgCount = 0
                foreach ($r in $jsonData.Results) {
                    if ($r.Packages) { $pkgCount += $r.Packages.Count }
                }
                Write-Info "Diagnostico: Results=$($jsonData.Results.Count), Packages=$pkgCount"
                Write-Log "JSON check: Results=$($jsonData.Results.Count), Packages=$pkgCount"

                if ($pkgCount -eq 0) {
                    Write-Warn "0 paquetes detectados. Cache posiblemente corrupto. Reintentando..."
                    continue
                }
            } else {
                Write-Warn "No se pudo parsear el JSON. Reintentando..."
                continue
            }
        }

        # Limpiar archivos temporales
        if (Test-Path $errFile) { Remove-Item $errFile -Force -ErrorAction SilentlyContinue }
        if (Test-Path $pyCountScript) { Remove-Item $pyCountScript -Force -ErrorAction SilentlyContinue }
        $scanOk = $true
        break
    }

    if (-not $scanOk) {
        Write-Fail "No se pudo escanear $name despues de 2 intentos."
        '{"Results":[]}' | Set-Content -Path $reportFile -Encoding ASCII
        $crit = 0; $high = 0; $med = 0; $low = 0; $total = 0
    }

    # Mostrar resumen
    Write-Host ""
    $critColor = if ($crit -gt 0) { "Red" } else { "Gray" }
    $highColor = if ($high -gt 0) { "Yellow" } else { "Gray" }
    $medColor  = if ($med -gt 0) { "Cyan" } else { "Gray" }
    Write-Host "  CRITICAL: " -NoNewline; Write-Host "$crit" -ForegroundColor $critColor -NoNewline
    Write-Host "  |  HIGH: " -NoNewline; Write-Host "$high" -ForegroundColor $highColor -NoNewline
    Write-Host "  |  MEDIUM: " -NoNewline; Write-Host "$med" -ForegroundColor $medColor -NoNewline
    Write-Host "  |  LOW: $low  |  TOTAL: $total"
    Write-Ok "Reporte: $reportFile"

    # Guardar en JSONL (usando ASCII para evitar BOM)
    $jsonLine = "{`"service`":`"$name`",`"image`":`"$image`",`"zone`":`"$zone`",`"exposure`":`"$exposure`",`"criticality`":`"$criticality`",`"critical`":$crit,`"high`":$high,`"medium`":$med,`"low`":$low,`"total`":$total,`"timestamp`":`"$Timestamp`"}"
    # Usar .NET para escribir sin BOM
    [System.IO.File]::AppendAllText($summaryFile, "$jsonLine`n", (New-Object System.Text.UTF8Encoding $false))
}

# =====================================================================
#  PASO 4: Reporte consolidado
# =====================================================================

Write-Host ""
Write-Host "[4/4] Generando reporte consolidado..." -ForegroundColor Yellow

$pyConsolidateScript = Join-Path $DataDir "_consolidate.py"
@"
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
"@ | Set-Content -Path $pyConsolidateScript -Encoding ASCII

& $PythonExe $pyConsolidateScript

# Limpiar scripts temporales
Remove-Item -Path (Join-Path $DataDir "_count_vulns.py") -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $DataDir "_consolidate.py") -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "+============================================================+" -ForegroundColor Green
Write-Host "|  Escaneo completado                                        |" -ForegroundColor Green
Write-Host "+============================================================+" -ForegroundColor Green
Write-Host ""
Write-Info "Reportes en: $DataDir"
Write-Info "Dashboard:   http://localhost:3000"
Write-Info "Log:         $LogFile"
Write-Host ""
