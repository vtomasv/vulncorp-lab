#!/bin/bash
###############################################################################
#  VulnCorp Lab — Escaneo de Vulnerabilidades con Trivy
#  Curso: Gestión de Vulnerabilidades con Enfoque MITRE — 2026
#
#  Compatible con: Linux, macOS (Intel/ARM), Windows (Git Bash, MINGW, WSL2)
#
#  Uso:
#    ./scripts/scan.sh              # Modo normal
#    ./scripts/scan.sh --verbose    # Modo verbose
#
#  NOTA TECNICA: Este script usa redireccion stdout (>) en lugar del flag
#  --output de Trivy para escribir archivos. Esto evita el bug conocido
#  de Trivy en Windows donde --output no genera archivos (Issue #1698).
#  La redireccion es manejada por el shell, no por Trivy, y funciona
#  en todos los sistemas operativos.
###############################################################################

# --- Argumentos ---
VERBOSE=false
for arg in "$@"; do
    case "$arg" in
        --verbose|-v) VERBOSE=true ;;
    esac
done

# --- Deteccion de plataforma ---
OS_TYPE="linux"
case "$(uname -s 2>/dev/null || echo Windows_NT)" in
    MINGW*|MSYS*|CYGWIN*) OS_TYPE="windows-bash" ;;
    Darwin*)               OS_TYPE="macos" ;;
    Linux*)
        grep -qi microsoft /proc/version 2>/dev/null && OS_TYPE="wsl" || OS_TYPE="linux"
        ;;
esac

# --- Colores (solo si la terminal los soporta) ---
USE_COLOR=false
if [ -t 1 ]; then
    case "$TERM" in
        xterm*|screen*|tmux*|vt100*) USE_COLOR=true ;;
    esac
    [ -n "$WT_SESSION" ] && USE_COLOR=true
    [ -n "$TERM_PROGRAM" ] && USE_COLOR=true
fi

if [ "$USE_COLOR" = true ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
    C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
else
    R=''; G=''; Y=''; B=''; C=''; N=''; BOLD=''
fi

# --- Funciones de utilidad ---
log()  { echo -e "$1"; }
info() { echo -e "  ${C}[i]${N} $1"; }
ok()   { echo -e "  ${G}[OK]${N} $1"; }
warn() { echo -e "  ${Y}[!]${N} $1"; }
fail() { echo -e "  ${R}[X]${N} $1"; }

# --- Directorio de trabajo ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="${PROJECT_DIR}/data"
mkdir -p "$DATA_DIR"

# Archivo de log
LOG_FILE="${DATA_DIR}/scan.log"
: > "$LOG_FILE"

log_to_file() {
    echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE"
}

log_to_file "=== VulnCorp Scan Log ==="
log_to_file "Plataforma: ${OS_TYPE}"
log_to_file "uname: $(uname -a 2>/dev/null || echo 'N/A')"
log_to_file "DATA_DIR: ${DATA_DIR}"
log_to_file "pwd: $(pwd)"

# --- Timestamp ---
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# --- Imagenes a escanear ---
# Formato: nombre|imagen|zona|exposicion|criticidad
SERVICES=(
    "nginx-proxy|nginx:1.21.0|produccion|internet|alta"
    "prestashop|prestashop/prestashop:1.7.8.0|produccion|internet-via-proxy|critica"
    "mariadb-prod|mariadb:10.5.18|produccion+corporativa|interna|critica"
    "redis-cache|redis:6.2.6|produccion|interna|media"
    "phpmyadmin|phpmyadmin:5.1.1|corporativa|red-interna|alta"
    "workstation|ubuntu:20.04|corporativa|red-interna|baja"
    "ftp-server|delfer/alpine-ftp-server|corporativa|red-interna|media"
)

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 1: Verificar herramientas
# ═══════════════════════════════════════════════════════════════════════════════

log ""
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|     VulnCorp -- Escaner de Vulnerabilidades (Trivy)        |${N}"
log "${BOLD}${C}|     Unidad 1: Gestion de Vulnerabilidades (MITRE)          |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""
info "Plataforma: ${BOLD}${OS_TYPE}${N}"
info "Directorio: ${BOLD}${DATA_DIR}${N}"
[ "$VERBOSE" = true ] && info "Modo: ${Y}VERBOSE${N}"
log ""

log "${Y}[1/4] Verificando herramientas...${N}"

# Verificar Docker
if ! command -v docker &>/dev/null; then
    fail "Docker no encontrado. Instale Docker Desktop."
    exit 1
fi
ok "Docker: $(docker --version 2>&1 | head -1)"

# Verificar Trivy
if ! command -v trivy &>/dev/null; then
    warn "Trivy no encontrado. Intentando instalar..."
    case "$OS_TYPE" in
        macos)
            if command -v brew &>/dev/null; then
                brew install trivy
            else
                fail "Instale Trivy: brew install trivy"
                exit 1
            fi
            ;;
        windows-bash)
            fail "Instale Trivy manualmente:"
            log "      choco install trivy"
            log "      scoop install trivy"
            log "      https://github.com/aquasecurity/trivy/releases"
            exit 1
            ;;
        *)
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
            ;;
    esac
fi

TRIVY_VER=$(trivy --version 2>&1 | head -1)
ok "Trivy: ${TRIVY_VER}"
log_to_file "Trivy: ${TRIVY_VER}"
log_to_file "Trivy path: $(command -v trivy)"

# Verificar Python
if ! command -v python3 &>/dev/null; then
    if command -v python &>/dev/null; then
        alias python3=python
    else
        fail "Python 3 no encontrado."
        exit 1
    fi
fi
ok "Python: $(python3 --version 2>&1)"

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 2: Actualizar base de datos de vulnerabilidades
# ═══════════════════════════════════════════════════════════════════════════════

log ""
log "${Y}[2/4] Actualizando base de datos de vulnerabilidades...${N}"
info "Esto puede tomar unos minutos la primera vez."

# Limpiar cache de escaneo previo
trivy clean --scan-cache >> "$LOG_FILE" 2>&1 || true

DB_OK=false
for attempt in 1 2 3; do
    log_to_file "DB download attempt ${attempt}/3"

    DB_OUTPUT=$(trivy image --download-db-only 2>&1)
    DB_EXIT=$?
    log_to_file "DB exit code: ${DB_EXIT}"
    log_to_file "DB output: ${DB_OUTPUT}"

    if [ $DB_EXIT -eq 0 ]; then
        DB_OK=true
        ok "Base de datos actualizada"
        break
    fi

    warn "Intento ${attempt}/3 fallido. Limpiando DB..."
    trivy clean --vuln-db >> "$LOG_FILE" 2>&1 || true
    sleep 2
done

if [ "$DB_OK" = false ]; then
    fail "No se pudo descargar la base de datos."
    fail "Verifique su conexion a Internet."
    log "  Revise el log: ${LOG_FILE}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 3: Escanear imagenes
# ═══════════════════════════════════════════════════════════════════════════════

log ""
log "${Y}[3/4] Escaneando imagenes del laboratorio VulnCorp...${N}"

# Limpiar reportes anteriores
rm -f "${DATA_DIR}/scan_summary.jsonl" 2>/dev/null || true

scan_image() {
    local entry="$1"

    # Parsear campos separados por |
    local name image zone exposure criticality
    IFS='|' read -r name image zone exposure criticality <<< "$entry"

    local report_file="${DATA_DIR}/${name}_trivy.json"

    log ""
    log "${B}------------------------------------------------------------${N}"
    log "${BOLD}  Escaneando: ${C}${name}${N}"
    log "  Imagen:     ${image}"
    log "  Zona:       ${zone} | Exposicion: ${exposure} | Criticidad: ${criticality}"
    log "  Reporte:    ${report_file}"
    log "${B}------------------------------------------------------------${N}"

    log_to_file "=== Scan: ${name} (${image}) ==="

    local scan_ok=false
    local crit=0 high=0 med=0 low=0 total=0

    for attempt in 1 2; do
        [ $attempt -gt 1 ] && {
            warn "Reintento ${attempt}/2 - Limpiando cache..."
            trivy clean --scan-cache >> "$LOG_FILE" 2>&1 || true
            sleep 1
        }

        # ─── ESCANEO ─────────────────────────────────────────────────
        # CLAVE: Usamos redireccion stdout (>) en lugar de --output.
        # Esto evita el bug de Trivy en Windows donde --output no
        # genera archivos (Issue #1698 de aquasecurity/trivy).
        # La redireccion > es manejada por el shell (bash/MINGW),
        # que si sabe escribir en rutas POSIX, a diferencia de Trivy
        # que es un binario nativo de Windows.
        local trivy_stderr="${DATA_DIR}/${name}_scan.err"

        trivy image \
            --format json \
            --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
            --skip-db-update \
            "$image" \
            > "$report_file" \
            2> "$trivy_stderr"

        local exit_code=$?

        # Guardar stderr en log
        if [ -f "$trivy_stderr" ]; then
            cat "$trivy_stderr" >> "$LOG_FILE"
            if [ "$VERBOSE" = true ]; then
                log "${C}  --- Salida de Trivy (stderr) ---${N}"
                cat "$trivy_stderr"
                log "${C}  --- Fin ---${N}"
            fi
        fi

        log_to_file "Exit code: ${exit_code}"

        # Verificar exit code
        if [ $exit_code -ne 0 ]; then
            fail "Trivy fallo (exit code: ${exit_code})"
            if [ -f "$trivy_stderr" ]; then
                log "${Y}$(tail -5 "$trivy_stderr")${N}"
            fi
            continue
        fi

        # Verificar que el archivo existe
        if [ ! -f "$report_file" ]; then
            fail "Archivo de reporte no se genero: ${report_file}"
            log_to_file "Report file missing after scan"
            continue
        fi

        # Verificar que no esta vacio
        local fsize
        fsize=$(wc -c < "$report_file" 2>/dev/null | tr -d ' ')
        fsize=${fsize:-0}

        if [ "$fsize" -lt 10 ] 2>/dev/null; then
            warn "Reporte muy pequeno (${fsize} bytes). Posible error."
            if [ "$VERBOSE" = true ]; then
                log "  Contenido: $(cat "$report_file")"
            fi
            log_to_file "Report too small: ${fsize} bytes"
            continue
        fi

        info "Archivo generado: ${fsize} bytes"
        log_to_file "Report size: ${fsize} bytes"

        # ─── CONTAR VULNERABILIDADES ─────────────────────────────────
        local counts
        counts=$(python3 -c "
import json, sys
try:
    with open('''${report_file}''', encoding='utf-8-sig') as f:
        raw = f.read()
    # Limpiar BOM y caracteres nulos
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
    print(f'0 0 0 0 0', file=sys.stdout)
    print(f'ERROR: {e}', file=sys.stderr)
" 2>>"$LOG_FILE")

        # Parsear resultado
        read -r crit high med low total <<< "$counts"
        crit=${crit:-0}; high=${high:-0}; med=${med:-0}; low=${low:-0}; total=${total:-0}

        log_to_file "Counts: C=${crit} H=${high} M=${med} L=${low} T=${total}"

        # Validar: si 0 vulns y primer intento, reintentar
        if [ "$total" = "0" ] && [ $attempt -lt 2 ]; then
            # Verificar si hay paquetes (si hay paquetes pero 0 vulns, puede ser legitimo)
            local pkg_check
            pkg_check=$(python3 -c "
import json
with open('''${report_file}''', encoding='utf-8-sig') as f:
    raw = f.read().lstrip('\ufeff').replace('\x00', '').strip()
data = json.loads(raw)
results = data.get('Results', [])
pkgs = sum(len(r.get('Packages', [])) for r in results)
has_v = any('Vulnerabilities' in r for r in results)
print(f'{len(results)} {pkgs} {has_v}')
" 2>/dev/null)

            local num_results num_pkgs has_vulns_key
            read -r num_results num_pkgs has_vulns_key <<< "$pkg_check"

            info "Diagnostico: Results=${num_results}, Packages=${num_pkgs}, HasVulns=${has_vulns_key}"
            log_to_file "JSON check: Results=${num_results}, Packages=${num_pkgs}, HasVulns=${has_vulns_key}"

            if [ "${num_pkgs:-0}" = "0" ]; then
                warn "0 paquetes detectados. Posible cache corrupto. Reintentando..."
                continue
            fi
        fi

        # Limpiar archivo de error si todo salio bien
        rm -f "$trivy_stderr" 2>/dev/null || true
        scan_ok=true
        break
    done

    if [ "$scan_ok" = false ]; then
        fail "No se pudo escanear ${name} despues de 2 intentos."
        warn "Revise: ${LOG_FILE}"
        echo '{"Results":[]}' > "$report_file"
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

# ═══════════════════════════════════════════════════════════════════════════════
#  PASO 4: Reporte consolidado
# ═══════════════════════════════════════════════════════════════════════════════

log ""
log "${Y}[4/4] Generando reporte consolidado...${N}"

python3 << 'PYEOF'
import json, os, sys

data_dir = os.environ.get('DATA_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))
# Fallback: usar variable de entorno o buscar el directorio
for candidate in [data_dir, './data', '../data']:
    summary = os.path.join(candidate, 'scan_summary.jsonl')
    if os.path.exists(summary):
        data_dir = candidate
        break

summary_file = os.path.join(data_dir, 'scan_summary.jsonl')
if not os.path.exists(summary_file):
    print("  No se encontraron resultados de escaneo.")
    sys.exit(0)

services = []
with open(summary_file, 'r', encoding='utf-8-sig') as f:
    for line in f:
        line = line.strip().lstrip('\ufeff').replace('\x00', '')
        if not line:
            continue
        try:
            services.append(json.loads(line))
        except json.JSONDecodeError:
            continue

if not services:
    print("  No se encontraron resultados validos.")
    sys.exit(0)

# Tabla
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

# JSON consolidado para el dashboard
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
PYEOF

# Pasar DATA_DIR como variable de entorno para Python
export DATA_DIR

log ""
log "${G}${BOLD}+============================================================+${N}"
log "${G}${BOLD}|  Escaneo completado                                        |${N}"
log "${G}${BOLD}+============================================================+${N}"
log ""
info "Reportes en: ${DATA_DIR}/"
info "Dashboard:   http://localhost:3000"
info "Log:         ${LOG_FILE}"
log ""
