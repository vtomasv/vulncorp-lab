#!/usr/bin/env bash
###############################################################################
#  VulnCorp Lab -- Escaneo de Vulnerabilidades con Trivy
#  Curso: Gestion de Vulnerabilidades con Enfoque MITRE -- 2026
#
#  Compatible con: Linux, macOS, Windows (Git Bash MINGW64 / WSL2)
#
#  IMPORTANTE: Este script NUNCA usa el flag --output de Trivy porque tiene
#  bugs conocidos en Windows (Issue #1698, #8884). En su lugar, usa
#  redireccion de stdout del shell (>) que funciona en todos los OS.
#
#  Para Windows se recomienda usar scan.ps1 (PowerShell nativo).
#  Este script funciona en Git Bash pero PowerShell es mas confiable.
#
#  Uso:
#    ./scripts/scan.sh              # Modo normal
#    ./scripts/scan.sh --verbose    # Modo verbose
###############################################################################

set -uo pipefail

# --- Detectar plataforma ---
PLATFORM="linux"
IS_WINDOWS=false
IS_GITBASH=false

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*)
        PLATFORM="windows-gitbash"
        IS_WINDOWS=true
        IS_GITBASH=true
        # Desactivar conversion de rutas de MSYS para este script
        export MSYS_NO_PATHCONV=1
        export MSYS2_ARG_CONV_EXCL="*"
        ;;
    CYGWIN*)
        PLATFORM="windows-cygwin"
        IS_WINDOWS=true
        ;;
    Darwin*)
        PLATFORM="macos"
        ;;
    Linux*)
        if [ -f /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
            PLATFORM="wsl2"
        fi
        ;;
esac

# --- Directorios (usar rutas relativas al script) ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="${PROJECT_DIR}/data"
LOG_FILE="${DATA_DIR}/scan.log"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S" 2>/dev/null || echo "unknown")

mkdir -p "$DATA_DIR"

# --- Verbose mode ---
VERBOSE=false
if [ "${1:-}" = "--verbose" ] || [ "${1:-}" = "-v" ]; then
    VERBOSE=true
fi

# --- Colores ---
R=''; G=''; Y=''; B=''; C=''; BOLD=''; N=''
if [ -t 1 ]; then
    # Git Bash soporta ANSI, pero tput puede fallar
    if command -v tput >/dev/null 2>&1; then
        nc=$(tput colors 2>/dev/null) || nc=0
        if [ "${nc:-0}" -ge 8 ]; then
            R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
            C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
        fi
    fi
    # Fallback: si TERM esta definido
    if [ -z "$N" ] && [ -n "${TERM:-}" ] && [ "${TERM:-}" != "dumb" ]; then
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
        C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
    fi
fi

# --- Funciones de logging ---
log()  { printf "%b\n" "$*"; }
ok()   { log "  ${G}[OK]${N} $*"; }
warn() { log "  ${Y}[!]${N} $*"; }
fail() { log "  ${R}[X]${N} $*"; }
info() { log "  ${C}[i]${N} $*"; }

log_to_file() {
    printf "[%s] %s\n" "$(date +%H:%M:%S 2>/dev/null || echo '??:??:??')" "$*" >> "$LOG_FILE"
}

# --- Iniciar log ---
printf "=== VulnCorp Scan Log ===\n" > "$LOG_FILE"
log_to_file "Timestamp: $TIMESTAMP"
log_to_file "Platform: $PLATFORM"
log_to_file "Shell: ${BASH_VERSION:-unknown}"
log_to_file "DataDir: $DATA_DIR"

# --- Detectar Python ---
PYTHON_CMD=""
for cmd in python3 python py; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ver=$("$cmd" --version 2>&1 || true)
        if echo "$ver" | grep -q "Python 3"; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    fail "Python 3 no encontrado. Instale Python 3.8+."
    exit 1
fi

# --- Funcion para limpiar BOM de un archivo (usa Python, funciona en todos los OS) ---
clean_bom() {
    local filepath="$1"
    [ ! -f "$filepath" ] && return 0

    "$PYTHON_CMD" -c "
import sys
fp = sys.argv[1]
with open(fp, 'rb') as f:
    raw = f.read()
if raw[:3] == b'\xef\xbb\xbf':
    with open(fp, 'wb') as f: f.write(raw[3:])
elif raw[:2] == b'\xff\xfe':
    t = raw[2:].decode('utf-16-le')
    with open(fp, 'wb') as f: f.write(t.encode('utf-8'))
elif b'\x00' in raw[:100]:
    try:
        t = raw.decode('utf-16')
        with open(fp, 'wb') as f: f.write(t.encode('utf-8'))
    except: pass
" "$filepath" 2>/dev/null || true
}

# --- Funcion para contar vulnerabilidades ---
count_vulns() {
    local report_file="$1"
    local py_script="${DATA_DIR}/_count_vulns_tmp.py"

    # Escribir script Python a archivo (evita heredoc inline con problemas CRLF)
    cat > "$py_script" << 'PYSCRIPT'
import json, sys
try:
    with open(sys.argv[1], 'rb') as f:
        raw = f.read()
    if raw[:3] == b'\xef\xbb\xbf': raw = raw[3:]
    if raw[:2] == b'\xff\xfe': raw = raw.decode('utf-16-le').encode('utf-8')
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
PYSCRIPT

    "$PYTHON_CMD" "$py_script" "$report_file" 2>>"$LOG_FILE"
    rm -f "$py_script" 2>/dev/null || true
}

# --- Funcion para diagnosticar JSON ---
diagnose_json() {
    local report_file="$1"
    local py_script="${DATA_DIR}/_diag_tmp.py"

    cat > "$py_script" << 'PYSCRIPT'
import json, sys
try:
    with open(sys.argv[1], 'rb') as f:
        raw = f.read()
    if raw[:3] == b'\xef\xbb\xbf': raw = raw[3:]
    text = raw.decode('utf-8', errors='ignore').strip()
    data = json.loads(text)
    results = data.get('Results', [])
    pkgs = sum(len(r.get('Packages', [])) for r in results)
    has_v = any('Vulnerabilities' in r for r in results)
    print(f'{len(results)} {pkgs} {has_v}')
except Exception as e:
    print('0 0 False')
    print(f'ERROR: {e}', file=sys.stderr)
PYSCRIPT

    "$PYTHON_CMD" "$py_script" "$report_file" 2>/dev/null
    rm -f "$py_script" 2>/dev/null || true
}

# --- Imagenes a escanear ---
SERVICES=(
    "nginx-proxy|nginx:1.21.0|produccion|internet|alta"
    "prestashop|prestashop/prestashop:1.7.8.0|produccion|internet-via-proxy|critica"
    "mariadb-prod|mariadb:10.5.18|produccion+corporativa|interna|critica"
    "redis-cache|redis:6.2.6|produccion|interna|media"
    "phpmyadmin|phpmyadmin:5.1.1|corporativa|red-interna|alta"
    "workstation|ubuntu:20.04|corporativa|red-interna|baja"
    "ftp-server|delfer/alpine-ftp-server|corporativa|red-interna|media"
)

# =====================================================================
#  PASO 1: Verificar herramientas
# =====================================================================

log ""
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|     VulnCorp -- Escaner de Vulnerabilidades (Trivy)        |${N}"
log "${BOLD}${C}|     Unidad 1: Gestion de Vulnerabilidades (MITRE)          |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""
info "Plataforma: ${PLATFORM}"
info "Python:     ${PYTHON_CMD}"
info "Directorio: ${DATA_DIR}"
if [ "$IS_GITBASH" = true ]; then
    info "Git Bash detectado. Recomendacion: use scan.ps1 en PowerShell para mejor compatibilidad."
fi
log ""

log "${Y}[1/4] Verificando herramientas...${N}"

# Docker
if command -v docker >/dev/null 2>&1; then
    docker_ver=$(docker --version 2>&1 || echo "desconocida")
    ok "Docker: ${docker_ver}"
else
    fail "Docker no encontrado."
    exit 1
fi

# Trivy
if ! command -v trivy >/dev/null 2>&1; then
    fail "Trivy no encontrado."
    info "Instale con:"
    log "    Linux:   sudo apt install trivy  /  brew install trivy"
    log "    macOS:   brew install trivy"
    log "    Windows: choco install trivy  /  scoop install trivy"
    exit 1
fi
trivy_ver=$(trivy version 2>&1 | head -1)
ok "Trivy: ${trivy_ver}"
log_to_file "Trivy: ${trivy_ver}"

# Python
python_ver=$("$PYTHON_CMD" --version 2>&1)
ok "Python: ${python_ver}"

# =====================================================================
#  PASO 2: Actualizar base de datos de vulnerabilidades
# =====================================================================

log ""
log "${Y}[2/4] Actualizando base de datos de vulnerabilidades...${N}"
info "Esto puede tomar unos minutos la primera vez."

# Limpiar scan cache
trivy clean --scan-cache >> "$LOG_FILE" 2>&1 || true

db_ok=false
for attempt in 1 2 3; do
    log_to_file "DB download attempt $attempt/3"

    if trivy image --download-db-only > /dev/null 2>"${DATA_DIR}/db_download.err"; then
        db_ok=true
        ok "Base de datos actualizada"
        rm -f "${DATA_DIR}/db_download.err"
        break
    fi

    warn "Intento $attempt/3 fallido."
    if [ -f "${DATA_DIR}/db_download.err" ]; then
        tail -3 "${DATA_DIR}/db_download.err" 2>/dev/null | while IFS= read -r errline; do
            log "    $errline"
        done
    fi
    info "Limpiando DB y reintentando..."
    trivy clean --vuln-db >> "$LOG_FILE" 2>&1 || true
    sleep 3
done

if [ "$db_ok" = false ]; then
    fail "No se pudo descargar la base de datos despues de 3 intentos."
    fail "Verifique su conexion a Internet."
    exit 1
fi

# =====================================================================
#  PASO 3: Escanear imagenes
# =====================================================================

log ""
log "${Y}[3/4] Escaneando imagenes del laboratorio VulnCorp...${N}"

# Limpiar resumen anterior
rm -f "${DATA_DIR}/scan_summary.jsonl"

scan_image() {
    local entry="$1"
    local name image zone exposure criticality
    IFS='|' read -r name image zone exposure criticality <<< "$entry"

    local report_file="${DATA_DIR}/${name}_trivy.json"
    local trivy_stderr="${DATA_DIR}/${name}_scan.err"

    log ""
    log "  ${B}------------------------------------------------------------${N}"
    log "  Escaneando: ${BOLD}${name}${N}"
    log "  Imagen:     ${image}"
    log "  Zona:       ${zone} | Exposicion: ${exposure} | Criticidad: ${criticality}"
    log "  ${B}------------------------------------------------------------${N}"

    log_to_file "=== Scan: $name ($image) ==="

    local scan_ok=false
    local crit=0 high=0 med=0 low=0 total=0

    for attempt in 1 2; do
        if [ $attempt -gt 1 ]; then
            warn "Reintento $attempt/2 - Limpiando cache..."
            trivy clean --scan-cache >> "$LOG_FILE" 2>&1 || true
            sleep 2
        fi

        # Eliminar reporte anterior
        rm -f "$report_file" "$trivy_stderr"

        # ---- ESCANEO ----
        # CLAVE: Usamos redireccion de stdout (>) en lugar de --output.
        log_to_file "Running: trivy image --format json --skip-db-update $image > $report_file"

        local exit_code=0
        trivy image --format json \
            --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
            --skip-db-update \
            "$image" > "$report_file" 2>"$trivy_stderr"
        exit_code=$?

        # Mostrar stderr si verbose
        if [ "$VERBOSE" = true ] && [ -f "$trivy_stderr" ] && [ -s "$trivy_stderr" ]; then
            log "  --- Salida de Trivy (stderr) ---"
            while IFS= read -r errline; do
                log "    $errline"
            done < "$trivy_stderr"
            log "  --- Fin ---"
        fi

        log_to_file "Exit code: $exit_code"

        if [ $exit_code -ne 0 ]; then
            fail "Trivy fallo (exit code: $exit_code)"
            if [ -f "$trivy_stderr" ]; then
                tail -5 "$trivy_stderr" 2>/dev/null | while IFS= read -r errline; do
                    log "    $errline"
                done
            fi
            continue
        fi

        # Verificar que el archivo existe y tiene contenido
        if [ ! -f "$report_file" ]; then
            fail "Archivo de reporte no se genero"
            continue
        fi

        local file_size
        file_size=$(wc -c < "$report_file" 2>/dev/null | tr -d ' \r\n')
        if [ "${file_size:-0}" -lt 10 ]; then
            warn "Reporte muy pequeno (${file_size:-0} bytes)"
            continue
        fi

        # Limpiar BOM si existe
        clean_bom "$report_file"

        info "Archivo generado: ${file_size} bytes"
        log_to_file "Report size: $file_size bytes"

        # ---- CONTAR VULNERABILIDADES ----
        local counts
        counts=$(count_vulns "$report_file")

        read -r crit high med low total <<< "$counts"
        crit=${crit:-0}; high=${high:-0}; med=${med:-0}; low=${low:-0}; total=${total:-0}

        log_to_file "Counts: C=${crit} H=${high} M=${med} L=${low} T=${total}"

        # Si 0 vulnerabilidades en primer intento, verificar si es legitimo
        if [ "$total" = "0" ] && [ $attempt -eq 1 ]; then
            local pkg_check
            pkg_check=$(diagnose_json "$report_file")

            local num_results num_pkgs has_vulns_key
            read -r num_results num_pkgs has_vulns_key <<< "${pkg_check:-0 0 False}"

            info "Diagnostico: Results=${num_results:-0}, Packages=${num_pkgs:-0}, HasVulns=${has_vulns_key:-False}"
            log_to_file "JSON check: Results=${num_results:-0}, Packages=${num_pkgs:-0}, HasVulns=${has_vulns_key:-False}"

            if [ "${num_pkgs:-0}" = "0" ]; then
                warn "0 paquetes detectados. Posible cache corrupto. Reintentando..."
                continue
            fi
        fi

        # Limpiar archivo de error
        rm -f "$trivy_stderr" 2>/dev/null || true
        scan_ok=true
        break
    done

    if [ "$scan_ok" = false ]; then
        fail "No se pudo escanear ${name} despues de 2 intentos."
        warn "Revise: ${LOG_FILE}"
        printf '{"Results":[]}\n' > "$report_file"
        crit=0; high=0; med=0; low=0; total=0
    fi

    # Mostrar resumen
    log ""
    log "  ${R}CRITICAL: ${crit}${N}  |  ${Y}HIGH: ${high}${N}  |  ${B}MEDIUM: ${med}${N}  |  ${G}LOW: ${low}${N}  |  TOTAL: ${total}"
    ok "Reporte: ${report_file}"

    # Guardar en resumen JSONL
    printf '{"service":"%s","image":"%s","zone":"%s","exposure":"%s","criticality":"%s","critical":%d,"high":%d,"medium":%d,"low":%d,"total":%d,"timestamp":"%s"}\n' \
        "$name" "$image" "$zone" "$exposure" "$criticality" \
        "$crit" "$high" "$med" "$low" "$total" "$TIMESTAMP" \
        >> "${DATA_DIR}/scan_summary.jsonl"
}

# Escanear cada imagen
for entry in "${SERVICES[@]}"; do
    scan_image "$entry"
done

# =====================================================================
#  PASO 4: Reporte consolidado
# =====================================================================

log ""
log "${Y}[4/4] Generando reporte consolidado...${N}"

PY_CONSOLIDATE="${DATA_DIR}/_consolidate_tmp.py"
cat > "$PY_CONSOLIDATE" << 'PYSCRIPT'
import json, os, sys

data_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('DATA_DIR', './data')

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
PYSCRIPT

"$PYTHON_CMD" "$PY_CONSOLIDATE" "$DATA_DIR"
rm -f "$PY_CONSOLIDATE" 2>/dev/null || true

log ""
log "${G}${BOLD}+============================================================+${N}"
log "${G}${BOLD}|  Escaneo completado                                        |${N}"
log "${G}${BOLD}+============================================================+${N}"
log ""
info "Reportes en: ${DATA_DIR}/"
info "Dashboard:   http://localhost:3000"
info "Log:         ${LOG_FILE}"
log ""
