#!/usr/bin/env bash
###############################################################################
#  VulnCorp Lab 02 — Generacion de SBOM con Syft (CycloneDX)
#  Curso: Gestion de Vulnerabilidades con Enfoque MITRE — 2026
#
#  Compatible con: Linux, macOS, Windows (Git Bash / WSL2)
#
#  Este script genera el Software Bill of Materials (SBOM) de cada imagen
#  del Lab 01 usando Syft en formato CycloneDX JSON.
#
#  NOTA: Usa redireccion de stdout (>) en lugar del flag -o file=path
#  para evitar problemas de rutas en Windows (mismo patron que scan.sh).
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

# --- Directorios (rutas relativas al script) ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB02_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SBOM_DIR="${LAB02_DIR}/data/sbom"
mkdir -p "$SBOM_DIR"

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
log "${BOLD}${C}|  VulnCorp Lab 02 -- Generacion de SBOM con Syft           |${N}"
log "${BOLD}${C}|  Formato: CycloneDX (OWASP Standard)                      |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

# Verificar Syft
if ! command -v syft &>/dev/null; then
    fail "Syft no encontrado. Ejecute primero: ./scripts/setup_lab02.sh"
    exit 1
fi
syft_ver=$(syft version 2>/dev/null | grep '^Application' || syft version 2>/dev/null | head -1)
ok "Syft: ${syft_ver}"
log ""

# =====================================================================
#  Imagenes del Lab 01 (VulnCorp PetaShop)
# =====================================================================
IMAGE_NAMES=("nginx-proxy" "prestashop" "mariadb-prod" "redis-cache" "phpmyadmin" "workstation" "ftp-server")
IMAGE_TAGS=("nginx:1.21.0" "prestashop/prestashop:1.7.8.0" "mariadb:10.5.18" "redis:6.2.6" "phpmyadmin:5.1.1" "ubuntu:20.04" "delfer/alpine-ftp-server")

TOTAL=${#IMAGE_NAMES[@]}
CURRENT=0

for i in "${!IMAGE_NAMES[@]}"; do
    CURRENT=$((CURRENT + 1))
    NAME="${IMAGE_NAMES[$i]}"
    IMAGE="${IMAGE_TAGS[$i]}"

    log ""
    log "  ${B}------------------------------------------------------------${N}"
    log "  ${BOLD}[${CURRENT}/${TOTAL}] Generando SBOM: ${C}${NAME}${N}"
    log "  Imagen: ${IMAGE}"
    log "  ${B}------------------------------------------------------------${N}"

    # --- CycloneDX JSON (formato principal) ---
    JSON_FILE="${SBOM_DIR}/${NAME}_sbom_cyclonedx.json"
    info "Generando CycloneDX JSON..."

    # Intentar con -o formato (sin =path) y redireccion stdout
    if syft "$IMAGE" -o cyclonedx-json --quiet > "$JSON_FILE" 2>/dev/null; then
        : # OK
    elif syft "$IMAGE" -o cyclonedx-json > "$JSON_FILE" 2>/dev/null; then
        : # OK sin --quiet
    else
        fail "Error generando SBOM JSON para ${IMAGE}"
        continue
    fi

    # Limpiar BOM si existe
    if command -v xxd &>/dev/null; then
        first_bytes=$(xxd -l 3 -p "$JSON_FILE" 2>/dev/null || true)
        if [ "$first_bytes" = "efbbbf" ]; then
            tail -c +4 "$JSON_FILE" > "${JSON_FILE}.tmp" && mv "${JSON_FILE}.tmp" "$JSON_FILE"
        fi
    fi

    if [ -f "$JSON_FILE" ] && [ -s "$JSON_FILE" ]; then
        COMP_COUNT=$("$PYTHON_CMD" -c "
import json
with open('''${JSON_FILE}''', encoding='utf-8-sig') as f:
    raw = f.read().lstrip('\ufeff').replace('\x00','')
data = json.loads(raw)
print(len(data.get('components', [])))
" 2>/dev/null || echo "?")
        ok "CycloneDX JSON: ${JSON_FILE}"
        info "Componentes encontrados: ${BOLD}${COMP_COUNT}${N}"
    else
        fail "Error generando SBOM para ${IMAGE}"
        continue
    fi

    # --- CycloneDX XML (formato alternativo) ---
    XML_FILE="${SBOM_DIR}/${NAME}_sbom_cyclonedx.xml"
    info "Generando CycloneDX XML..."
    if syft "$IMAGE" -o cyclonedx-xml --quiet > "$XML_FILE" 2>/dev/null || \
       syft "$IMAGE" -o cyclonedx-xml > "$XML_FILE" 2>/dev/null; then
        ok "CycloneDX XML:  ${XML_FILE}"
    else
        warn "No se pudo generar XML (no critico)"
    fi

    # --- Tabla resumen ---
    TABLE_FILE="${SBOM_DIR}/${NAME}_sbom_table.txt"
    syft "$IMAGE" -o table > "$TABLE_FILE" 2>/dev/null || true
    ok "Tabla resumen:  ${TABLE_FILE}"
done

# =====================================================================
#  Resumen consolidado
# =====================================================================
log ""
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|              RESUMEN DE SBOMs GENERADOS                    |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

export SBOM_DIR

"$PYTHON_CMD" << 'PYEOF'
import json, os, glob

sbom_dir = os.environ.get('SBOM_DIR', './data/sbom')
json_files = sorted(glob.glob(os.path.join(sbom_dir, '*_cyclonedx.json')))

print(f"  {'Servicio':<18} {'Componentes':>12} {'Tipo BOM':<14} {'Spec Version':<14}")
print(f"  {'-'*18} {'-'*12} {'-'*14} {'-'*14}")

total_components = 0
for jf in json_files:
    try:
        with open(jf, encoding='utf-8-sig') as f:
            raw = f.read().lstrip('\ufeff').replace('\x00', '')
        data = json.loads(raw)
        name = os.path.basename(jf).replace('_sbom_cyclonedx.json', '')
        comp_count = len(data.get('components', []))
        bom_format = data.get('bomFormat', 'N/A')
        spec_ver = data.get('specVersion', 'N/A')
        total_components += comp_count
        print(f"  {name:<18} {comp_count:>12} {bom_format:<14} {spec_ver:<14}")
    except Exception as e:
        print(f"  Error leyendo {os.path.basename(jf)}: {e}")

print(f"  {'-'*18} {'-'*12} {'-'*14} {'-'*14}")
print(f"  {'TOTAL':<18} {total_components:>12}")
print()

summary = {
    "total_images": len(json_files),
    "total_components": total_components,
    "sbom_files": [os.path.basename(f) for f in json_files]
}
summary_file = os.path.join(sbom_dir, 'sbom_summary.json')
with open(summary_file, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)
print(f"  Resumen guardado en: {summary_file}")
PYEOF

log ""
ok "Generacion de SBOMs completada"
info "Archivos en: ${SBOM_DIR}/"
log ""
info "Proximo paso:"
log "    Escanear vulnerabilidades: ${C}./scripts/scan_grype.sh${N}"
log ""
