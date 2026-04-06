<#
.SYNOPSIS
    VulnCorp Lab - Escaneo de Vulnerabilidades con Trivy (PowerShell)
.DESCRIPTION
    Script nativo de PowerShell para Windows.
    Usa [System.Diagnostics.Process] para ejecutar Trivy y capturar stdout
    directamente como bytes, evitando que PowerShell modifique la codificacion.

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
    $entry = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    [System.IO.File]::AppendAllText($LogFile, "$entry`r`n", (New-Object System.Text.UTF8Encoding $false))
}

# Iniciar log
$logHeader = "=== VulnCorp Scan Log ===`r`nTimestamp: $Timestamp`r`nPlatform: PowerShell $($PSVersionTable.PSVersion) on $([System.Environment]::OSVersion.VersionString)`r`nDataDir: $DataDir`r`n"
[System.IO.File]::WriteAllText($LogFile, $logHeader, (New-Object System.Text.UTF8Encoding $false))

# --- Funcion para ejecutar Trivy y guardar stdout a archivo ---
# Usa System.Diagnostics.Process para capturar stdout como bytes puros
# sin que PowerShell modifique la codificacion.
function Invoke-TrivyScan {
    param(
        [string]$Arguments,
        [string]$OutputFile,
        [switch]$ShowStderr
    )

    Write-Log "CMD: trivy $Arguments"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "trivy"
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    # Forzar UTF-8 sin BOM en la salida
    $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding $false
    $psi.StandardErrorEncoding = New-Object System.Text.UTF8Encoding $false

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)

        # Leer stdout y stderr de forma asincrona para evitar deadlocks
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        $proc.WaitForExit()

        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result

        # Guardar stdout al archivo usando .NET (sin BOM)
        if ($OutputFile -and $stdout) {
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($OutputFile, $stdout, $utf8NoBom)
        }

        # Mostrar stderr si se solicita
        if ($ShowStderr -and $stderr) {
            Write-Host "  --- Salida de Trivy (stderr) ---" -ForegroundColor DarkGray
            $stderr -split "`n" | ForEach-Object {
                $line = $_.TrimEnd("`r")
                if ($line) { Write-Host "    $line" -ForegroundColor DarkGray }
            }
            Write-Host "  --- Fin ---" -ForegroundColor DarkGray
        }

        # Guardar stderr en log
        if ($stderr) {
            Write-Log "STDERR: $($stderr.Substring(0, [Math]::Min(500, $stderr.Length)))"
        }

        return @{
            ExitCode = $proc.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    }
    catch {
        Write-Log "ERROR ejecutando Trivy: $_"
        return @{
            ExitCode = -1
            Stdout = ""
            Stderr = $_.ToString()
        }
    }
}

# --- Funcion para ejecutar Trivy sin captura (para DB download) ---
function Invoke-TrivyCommand {
    param([string]$Arguments)

    Write-Log "CMD: trivy $Arguments"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "trivy"
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()
        $stderr = $stderrTask.Result
        if ($stderr) { Write-Log "STDERR: $($stderr.Substring(0, [Math]::Min(300, $stderr.Length)))" }
        return $proc.ExitCode
    }
    catch {
        Write-Log "ERROR: $_"
        return -1
    }
}

# --- Funcion para limpiar BOM de un archivo ---
function Remove-BOM {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) { return }

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -lt 2) { return }

    $changed = $false

    # BOM UTF-8 (EF BB BF)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Log "BOM UTF-8 detectado y eliminado en: $FilePath"
        $clean = New-Object byte[] ($bytes.Length - 3)
        [System.Array]::Copy($bytes, 3, $clean, 0, $clean.Length)
        [System.IO.File]::WriteAllBytes($FilePath, $clean)
        $changed = $true
    }
    # BOM UTF-16 LE (FF FE)
    elseif ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        Write-Log "BOM UTF-16LE detectado en: $FilePath - Convirtiendo a UTF-8"
        $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
        $utf8 = (New-Object System.Text.UTF8Encoding $false).GetBytes($text)
        [System.IO.File]::WriteAllBytes($FilePath, $utf8)
        $changed = $true
    }

    return $changed
}

# --- Funcion para leer JSON limpio ---
function Read-CleanJson {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) { return $null }

    Remove-BOM -FilePath $FilePath | Out-Null

    try {
        $raw = [System.IO.File]::ReadAllText($FilePath, (New-Object System.Text.UTF8Encoding $false))
        $raw = $raw.TrimStart([char]0xFEFF).Replace("`0", "").Trim()
        if (-not $raw) { return $null }
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
Invoke-TrivyCommand -Arguments "clean --scan-cache" | Out-Null

$dbOk = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Log "DB download attempt $attempt/3"

    $exitCode = Invoke-TrivyCommand -Arguments "image --download-db-only"

    if ($exitCode -eq 0) {
        $dbOk = $true
        Write-Ok "Base de datos actualizada"
        break
    }

    Write-Warn "Intento $attempt/3 fallido."
    Write-Info "Limpiando DB y reintentando..."
    Invoke-TrivyCommand -Arguments "clean --vuln-db" | Out-Null
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

$utf8NoBom = New-Object System.Text.UTF8Encoding $false

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
    Write-Host "  Zona:       $zone | Exposicion: $exposure" -ForegroundColor Gray
    Write-Host "  ------------------------------------------------------------" -ForegroundColor Blue

    Write-Log "=== Scan: $name ($image) ==="

    $scanOk = $false
    $crit = 0; $high = 0; $med = 0; $low = 0; $total = 0

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        if ($attempt -gt 1) {
            Write-Warn "Reintento $attempt/2 - Limpiando cache..."
            Invoke-TrivyCommand -Arguments "clean --scan-cache" | Out-Null
            Start-Sleep -Seconds 2
        }

        # Eliminar reporte anterior
        if (Test-Path $reportFile) { Remove-Item $reportFile -Force }

        # ---- ESCANEO ----
        # Usamos System.Diagnostics.Process para capturar stdout como bytes puros
        # y escribirlo directamente al archivo sin BOM ni conversion de encoding.
        $showStderr = ($VerbosePreference -eq "Continue")
        $trivyArgs = "image --format json --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --skip-db-update `"$image`""
        $result = Invoke-TrivyScan -Arguments $trivyArgs -OutputFile $reportFile -ShowStderr:$showStderr

        Write-Log "Exit code: $($result.ExitCode)"

        if ($result.ExitCode -ne 0) {
            Write-Fail "Trivy fallo (exit code: $($result.ExitCode))"
            if ($result.Stderr) {
                $result.Stderr -split "`n" | Select-Object -Last 5 | ForEach-Object {
                    $line = $_.TrimEnd("`r")
                    if ($line) { Write-Host "    $line" -ForegroundColor Yellow }
                }
            }
            continue
        }

        # Verificar que el archivo existe y tiene contenido
        if (-not (Test-Path $reportFile)) {
            Write-Fail "Archivo de reporte no se genero"
            Write-Log "FAIL: Report file not created"
            continue
        }

        $fileSize = (Get-Item $reportFile).Length
        if ($fileSize -lt 10) {
            Write-Warn "Reporte muy pequeno ($fileSize bytes). Posible archivo vacio."
            continue
        }

        # Limpiar BOM si existe (por si acaso)
        Remove-BOM -FilePath $reportFile | Out-Null

        Write-Info "Archivo generado: $fileSize bytes"
        Write-Log "Report size: $fileSize bytes"

        # ---- CONTAR VULNERABILIDADES ----
        # Usamos Python para parsear el JSON de forma robusta
        $pyCountScript = Join-Path $DataDir "_count_vulns.py"
        # Escribir script Python con .NET para evitar BOM
        $pyCode = @"
import json, sys
try:
    with open(sys.argv[1], 'rb') as f:
        raw = f.read()
    if raw[:3] == b'\xef\xbb\xbf':
        raw = raw[3:]
    if raw[:2] == b'\xff\xfe':
        raw = raw.decode('utf-16-le').encode('utf-8')
    text = raw.decode('utf-8', errors='ignore').strip()
    if not text:
        print('0 0 0 0 0')
        sys.exit(0)
    data = json.loads(text)
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
        [System.IO.File]::WriteAllText($pyCountScript, $pyCode, $utf8NoBom)

        $counts = & $PythonExe $pyCountScript $reportFile 2>>$LogFile
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
        Remove-Item -Path $pyCountScript -Force -ErrorAction SilentlyContinue
        $scanOk = $true
        break
    }

    if (-not $scanOk) {
        Write-Fail "No se pudo escanear $name despues de 2 intentos."
        [System.IO.File]::WriteAllText($reportFile, '{"Results":[]}', $utf8NoBom)
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

    # Guardar en JSONL usando .NET para evitar BOM
    $jsonLine = "{`"service`":`"$name`",`"image`":`"$image`",`"zone`":`"$zone`",`"exposure`":`"$exposure`",`"criticality`":`"$criticality`",`"critical`":$crit,`"high`":$high,`"medium`":$med,`"low`":$low,`"total`":$total,`"timestamp`":`"$Timestamp`"}"
    [System.IO.File]::AppendAllText($summaryFile, "$jsonLine`n", $utf8NoBom)
}

# =====================================================================
#  PASO 4: Reporte consolidado
# =====================================================================

Write-Host ""
Write-Host "[4/4] Generando reporte consolidado..." -ForegroundColor Yellow

$pyConsolidateScript = Join-Path $DataDir "_consolidate.py"
$pyConsolidateCode = @"
import json, os, sys

data_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
summary_file = os.path.join(data_dir, 'scan_summary.jsonl')

if not os.path.exists(summary_file):
    print("  No se encontraron resultados de escaneo.")
    sys.exit(0)

services = []
with open(summary_file, 'rb') as f:
    raw = f.read()
if raw[:3] == b'\xef\xbb\xbf':
    raw = raw[3:]
text = raw.decode('utf-8', errors='ignore')

for line in text.splitlines():
    line = line.strip()
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
[System.IO.File]::WriteAllText($pyConsolidateScript, $pyConsolidateCode, $utf8NoBom)

& $PythonExe $pyConsolidateScript $DataDir

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
