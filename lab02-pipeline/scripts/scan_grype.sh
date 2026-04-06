#!/usr/bin/env bash
###############################################################################
#  VulnCorp Lab 02 — Escaneo de Vulnerabilidades con Grype
#  Curso: Gestion de Vulnerabilidades con Enfoque MITRE — 2026
#
#  Compatible con: Linux, macOS, Windows (Git Bash / WSL2)
#
#  Toma los SBOMs generados por Syft (CycloneDX JSON) y los pasa por Grype
#  para detectar vulnerabilidades conocidas.
#
#  Usa redireccion de stdout (>) para evitar problemas de rutas en Windows.
###############################################################################

set -euo pipefail

# --- Detectar plataforma ---
IS_WINDOWS=false
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=true ;; esac

# --- Colores condicionales ---
if [ -t 1 ] && command -v tput &>/dev/null && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
    C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; B=''; C=''; BOLD=''; N=''
fi

log()  { printf "%b\n" "$*"; }
ok()   { log "  ${G}[OK]${N} $*"; }
warn() { log "  ${Y}[!]${N} $*"; }
fail() { log "  ${R}[X]${N} $*"; }
info() { log "  ${C}[i]${N} $*"; }

# --- Directorios ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB02_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SBOM_DIR="${LAB02_DIR}/data/sbom"
GRYPE_DIR="${LAB02_DIR}/data/grype"
mkdir -p "$GRYPE_DIR"

# --- Detectar Python ---
PYTHON_CMD=""
for cmd in python3 python py; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1 || true)
        if echo "$ver" | grep -q "Python 3"; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done
if [ -z "$PYTHON_CMD" ]; then
    fail "Python 3 no encontrado."
    exit 1
fi

log ""
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|  VulnCorp Lab 02 -- Escaneo de Vulnerabilidades con Grype  |${N}"
log "${BOLD}${C}|  Fuente: SBOMs CycloneDX generados por Syft               |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

# Verificar Grype
if ! command -v grype &>/dev/null; then
    fail "Grype no encontrado. Ejecute primero: ./scripts/setup_lab02.sh"
    exit 1
fi
grype_ver=$(grype version 2>/dev/null | grep '^Application' || grype version 2>/dev/null | head -1)
ok "Grype: ${grype_ver}"

# Verificar SBOMs
shopt -s nullglob
SBOM_FILES=("$SBOM_DIR"/*_sbom_cyclonedx.json)
shopt -u nullglob

if [ ${#SBOM_FILES[@]} -eq 0 ]; then
    fail "No se encontraron SBOMs en ${SBOM_DIR}/"
    info "Ejecute primero: ./scripts/generate_sbom.sh"
    exit 1
fi
ok "SBOMs encontrados: ${#SBOM_FILES[@]} archivos"
log ""

# Actualizar DB de Grype
info "Actualizando base de datos de vulnerabilidades de Grype..."
grype db update 2>/dev/null || warn "Usando base de datos existente"
log ""

# Limpiar resumen anterior
rm -f "${GRYPE_DIR}/grype_summary.jsonl"

TOTAL=${#SBOM_FILES[@]}
CURRENT=0

for SBOM_FILE in "${SBOM_FILES[@]}"; do
    CURRENT=$((CURRENT + 1))
    BASENAME=$(basename "$SBOM_FILE" | sed 's/_sbom_cyclonedx\.json//')

    log "  ${B}------------------------------------------------------------${N}"
    log "  ${BOLD}[${CURRENT}/${TOTAL}] Escaneando: ${C}${BASENAME}${N}"
    log "  SBOM: ${SBOM_FILE}"
    log "  ${B}------------------------------------------------------------${N}"

    # --- CycloneDX output (para DefectDojo) ---
    CYCLONEDX_OUT="${GRYPE_DIR}/${BASENAME}_grype_cyclonedx.json"
    info "Generando reporte CycloneDX..."

    if grype "sbom:${SBOM_FILE}" -o cyclonedx-json > "$CYCLONEDX_OUT" 2>/dev/null; then
        ok "CycloneDX: ${CYCLONEDX_OUT}"
    else
        warn "Error generando CycloneDX para ${BASENAME}"
    fi

    # Limpiar BOM
    if command -v xxd &>/dev/null && [ -f "$CYCLONEDX_OUT" ]; then
        first_bytes=$(xxd -l 3 -p "$CYCLONEDX_OUT" 2>/dev/null || true)
        if [ "$first_bytes" = "efbbbf" ]; then
            tail -c +4 "$CYCLONEDX_OUT" > "${CYCLONEDX_OUT}.tmp" && mv "${CYCLONEDX_OUT}.tmp" "$CYCLONEDX_OUT"
        fi
    fi

    # --- JSON detallado ---
    JSON_OUT="${GRYPE_DIR}/${BASENAME}_grype_detail.json"
    grype "sbom:${SBOM_FILE}" -o json > "$JSON_OUT" 2>/dev/null || true

    # Limpiar BOM
    if command -v xxd &>/dev/null && [ -f "$JSON_OUT" ]; then
        first_bytes=$(xxd -l 3 -p "$JSON_OUT" 2>/dev/null || true)
        if [ "$first_bytes" = "efbbbf" ]; then
            tail -c +4 "$JSON_OUT" > "${JSON_OUT}.tmp" && mv "${JSON_OUT}.tmp" "$JSON_OUT"
        fi
    fi

    # --- Contar vulnerabilidades ---
    CRIT=0; HIGH=0; MED=0; LOW=0; NEG=0; TOT=0
    if [ -f "$JSON_OUT" ] && [ -s "$JSON_OUT" ]; then
        COUNTS=$("$PYTHON_CMD" -c "
import json, sys
try:
    with open('''${JSON_OUT}''', encoding='utf-8-sig') as f:
        raw = f.read().lstrip('\ufeff').replace('\x00','')
    data = json.loads(raw)
    matches = data.get('matches', [])
    counts = {'Critical':0, 'High':0, 'Medium':0, 'Low':0, 'Negligible':0}
    for m in matches:
        sev = m.get('vulnerability',{}).get('severity','Unknown')
        if sev in counts: counts[sev] += 1
    total = sum(counts.values())
    print(f\"{counts['Critical']} {counts['High']} {counts['Medium']} {counts['Low']} {counts['Negligible']} {total}\")
except Exception as e:
    print('0 0 0 0 0 0', file=sys.stdout)
    print(f'ERROR: {e}', file=sys.stderr)
" 2>/dev/null || echo "0 0 0 0 0 0")

        read -r CRIT HIGH MED LOW NEG TOT <<< "$COUNTS"
        CRIT=${CRIT:-0}; HIGH=${HIGH:-0}; MED=${MED:-0}; LOW=${LOW:-0}; NEG=${NEG:-0}; TOT=${TOT:-0}

        log "  ${R}CRITICAL: ${CRIT}${N} | ${Y}HIGH: ${HIGH}${N} | ${B}MEDIUM: ${MED}${N} | ${G}LOW: ${LOW}${N} | NEG: ${NEG} | TOTAL: ${TOT}"
    fi

    # --- Tabla resumen ---
    TABLE_OUT="${GRYPE_DIR}/${BASENAME}_grype_table.txt"
    grype "sbom:${SBOM_FILE}" -o table > "$TABLE_OUT" 2>/dev/null || true
    ok "Tabla: ${TABLE_OUT}"

    # Guardar linea de resumen (sin BOM, con newline Unix)
    printf '{"service":"%s","critical":%d,"high":%d,"medium":%d,"low":%d,"negligible":%d,"total":%d}\n' \
        "$BASENAME" "$CRIT" "$HIGH" "$MED" "$LOW" "$NEG" "$TOT" \
        >> "${GRYPE_DIR}/grype_summary.jsonl"

    log ""
done

# =====================================================================
#  Resumen consolidado
# =====================================================================
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|           RESUMEN DE VULNERABILIDADES (GRYPE)              |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

export GRYPE_DIR

"$PYTHON_CMD" << 'PYEOF'
import json, os

grype_dir = os.environ.get('GRYPE_DIR', './data/grype')
summary_file = os.path.join(grype_dir, 'grype_summary.jsonl')

if not os.path.exists(summary_file):
    print("  No se encontraron resultados.")
    exit(0)

services = []
with open(summary_file, encoding='utf-8-sig') as f:
    for line in f:
        line = line.strip().lstrip('\ufeff').replace('\x00', '')
        if not line: continue
        try: services.append(json.loads(line))
        except: continue

print(f"  {'Servicio':<18} {'CRIT':>6} {'HIGH':>6} {'MED':>6} {'LOW':>6} {'NEG':>6} {'TOTAL':>7}")
print(f"  {'-'*18} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*7}")

tc = th = tm = tl = tn = tt = 0
for s in services:
    print(f"  {s['service']:<18} {s['critical']:>6} {s['high']:>6} {s['medium']:>6} {s['low']:>6} {s['negligible']:>6} {s['total']:>7}")
    tc += s['critical']; th += s['high']; tm += s['medium']
    tl += s['low']; tn += s['negligible']; tt += s['total']

print(f"  {'-'*18} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*7}")
print(f"  {'TOTAL':<18} {tc:>6} {th:>6} {tm:>6} {tl:>6} {tn:>6} {tt:>7}")
print()

consolidated = {
    "total_services": len(services),
    "total_vulnerabilities": tt,
    "by_severity": {"critical": tc, "high": th, "medium": tm, "low": tl, "negligible": tn},
    "services": services
}
out = os.path.join(grype_dir, 'grype_consolidated.json')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(consolidated, f, indent=2, ensure_ascii=False)
print(f"  Consolidado guardado en: {out}")
PYEOF

log ""
ok "Escaneo con Grype completado"
info "Reportes en: ${GRYPE_DIR}/"
log ""
info "Proximo paso:"
log "    Subir a plataformas: ${C}${PYTHON_CMD} scripts/upload_reports.py${N}"
log ""
