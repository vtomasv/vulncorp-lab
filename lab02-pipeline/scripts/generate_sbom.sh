#!/usr/bin/env bash
###############################################################################
#  VulnCorp Lab 02 -- Generacion de SBOM con Syft (CycloneDX)
#  Curso: Gestion de Vulnerabilidades con Enfoque MITRE -- 2026
#
#  Compatible con: Linux, macOS, Windows (Git Bash MINGW64 / WSL2)
#
#  Este script genera el Software Bill of Materials (SBOM) de cada imagen
#  del Lab 01 usando Syft en formato CycloneDX JSON.
#
#  SOLUCION WINDOWS: Syft es un binario nativo de Windows (.exe).
#  Cuando se ejecuta desde Git Bash, la redireccion stdout (>) es
#  manejada por bash (funciona), pero los argumentos de Syft que
#  contienen rutas deben ser convertidos a formato Windows nativo.
#  Este script usa redireccion stdout para la salida y no pasa
#  rutas como argumentos a Syft (solo nombres de imagenes Docker).
###############################################################################

set -uo pipefail

# --- Detectar plataforma ---
IS_WINDOWS=false
IS_GITBASH=false
case "$(uname -s)" in
    MINGW*|MSYS*)
        IS_WINDOWS=true
        IS_GITBASH=true
        ;;
    CYGWIN*)
        IS_WINDOWS=true
        ;;
esac

# --- Colores (compatibles con Git Bash) ---
R=''; G=''; Y=''; B=''; C=''; BOLD=''; N=''
if [ -t 1 ]; then
    if [ -n "${TERM:-}" ] && [ "${TERM:-}" != "dumb" ]; then
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
        C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
    fi
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

# --- Detectar Python (compatible Git Bash: python3 no existe en Windows) ---
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
    fail "Python 3 no encontrado."
    exit 1
fi

# --- Funcion para limpiar BOM (usando Python, compatible Git Bash) ---
clean_bom() {
    local filepath="$1"
    if [ ! -f "$filepath" ]; then return; fi
    "$PYTHON_CMD" -c "
import sys
fp = sys.argv[1]
with open(fp, 'rb') as f:
    raw = f.read()
if raw[:3] == b'\xef\xbb\xbf':
    with open(fp, 'wb') as f: f.write(raw[3:])
elif raw[:2] == b'\xff\xfe':
    with open(fp, 'wb') as f: f.write(raw.decode('utf-16-le').encode('utf-8'))
" "$filepath" 2>/dev/null || true
}

# --- Funcion para contar componentes ---
count_components() {
    local json_file="$1"
    "$PYTHON_CMD" -c "
import json, sys
fpath = sys.argv[1]
try:
    with open(fpath, 'rb') as f:
        raw = f.read()
    if raw[:3] == b'\xef\xbb\xbf': raw = raw[3:]
    text = raw.decode('utf-8', errors='ignore')
    data = json.loads(text)
    print(len(data.get('components', [])))
except:
    print('?')
" "$json_file" 2>/dev/null
}

log ""
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|  VulnCorp Lab 02 -- Generacion de SBOM con Syft           |${N}"
log "${BOLD}${C}|  Formato: CycloneDX (OWASP Standard)                      |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

# Verificar Syft
if ! command -v syft >/dev/null 2>&1; then
    fail "Syft no encontrado."
    if [ "$IS_WINDOWS" = true ]; then
        info "Instale con: choco install syft  o  scoop install syft"
    else
        info "Ejecute primero: ./scripts/setup_lab02.sh"
    fi
    exit 1
fi
syft_ver=$(syft version 2>/dev/null | grep -i 'version' | head -1 || syft version 2>/dev/null | head -1 || echo "desconocida")
ok "Syft: ${syft_ver}"

# Mostrar plataforma detectada
if [ "$IS_GITBASH" = true ]; then
    info "Plataforma: Windows (Git Bash / MINGW)"
elif [ "$IS_WINDOWS" = true ]; then
    info "Plataforma: Windows (Cygwin)"
else
    info "Plataforma: $(uname -s)"
fi

info "Directorio SBOM: ${SBOM_DIR}/"
log ""

# =====================================================================
#  Imagenes del Lab 01 (VulnCorp PetaShop)
#  NOTA: Syft recibe nombres de imagenes Docker (no rutas de archivos),
#  por lo que NO hay problema de conversion de rutas aqui.
#  La redireccion stdout (>) es manejada por bash, no por Syft.
# =====================================================================
IMAGE_NAMES=("nginx-proxy" "prestashop" "mariadb-prod" "redis-cache" "phpmyadmin" "workstation" "ftp-server")
IMAGE_TAGS=("nginx:1.21.0" "prestashop/prestashop:1.7.8.0" "mariadb:10.5.18" "redis:6.2.6" "phpmyadmin:5.1.1" "ubuntu:20.04" "delfer/alpine-ftp-server")

TOTAL=${#IMAGE_NAMES[@]}
CURRENT=0
GENERATED_OK=0

for i in "${!IMAGE_NAMES[@]}"; do
    CURRENT=$((CURRENT + 1))
    NAME="${IMAGE_NAMES[$i]}"
    IMAGE="${IMAGE_TAGS[$i]}"

    log ""
    log "  ${B}------------------------------------------------------------${N}"
    log "  ${BOLD}[${CURRENT}/${TOTAL}] Generando SBOM: ${C}${NAME}${N}"
    log "  Imagen: ${IMAGE}"
    log "  ${B}------------------------------------------------------------${N}"

    # Verificar que la imagen existe localmente
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        warn "Imagen no encontrada localmente: ${IMAGE}"
        info "Descargando imagen..."
        if ! docker pull "$IMAGE" 2>/dev/null; then
            fail "No se pudo descargar ${IMAGE}"
            continue
        fi
    fi

    # --- CycloneDX JSON (formato principal) ---
    JSON_FILE="${SBOM_DIR}/${NAME}_sbom_cyclonedx.json"
    ERR_FILE="${SBOM_DIR}/${NAME}_syft_error.log"
    info "Generando CycloneDX JSON..."

    # Syft recibe el nombre de imagen Docker (no una ruta de archivo)
    # La redireccion > es manejada por bash, funciona en todas las plataformas
    if syft "$IMAGE" -o cyclonedx-json > "$JSON_FILE" 2>"$ERR_FILE"; then
        : # OK
    else
        fail "Error generando SBOM JSON para ${IMAGE}"
        if [ -f "$ERR_FILE" ] && [ -s "$ERR_FILE" ]; then
            warn "Detalle del error:"
            head -5 "$ERR_FILE" | while IFS= read -r line; do warn "  $line"; done
        fi
        continue
    fi

    # Limpiar BOM
    clean_bom "$JSON_FILE"

    if [ -f "$JSON_FILE" ] && [ -s "$JSON_FILE" ]; then
        COMP_COUNT=$(count_components "$JSON_FILE")
        ok "CycloneDX JSON: $(basename "$JSON_FILE")"
        info "Componentes encontrados: ${BOLD}${COMP_COUNT}${N}"
        GENERATED_OK=$((GENERATED_OK + 1))
        rm -f "$ERR_FILE" 2>/dev/null || true
    else
        fail "Archivo SBOM vacio para ${IMAGE}"
        continue
    fi

    # --- CycloneDX XML (formato alternativo) ---
    XML_FILE="${SBOM_DIR}/${NAME}_sbom_cyclonedx.xml"
    info "Generando CycloneDX XML..."
    if syft "$IMAGE" -o cyclonedx-xml > "$XML_FILE" 2>/dev/null; then
        clean_bom "$XML_FILE"
        ok "CycloneDX XML:  $(basename "$XML_FILE")"
    else
        warn "No se pudo generar XML (no critico)"
    fi

    # --- Tabla resumen ---
    TABLE_FILE="${SBOM_DIR}/${NAME}_sbom_table.txt"
    syft "$IMAGE" -o table > "$TABLE_FILE" 2>/dev/null || true
    ok "Tabla resumen:  $(basename "$TABLE_FILE")"
done

# =====================================================================
#  Resumen consolidado
# =====================================================================
log ""
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|              RESUMEN DE SBOMs GENERADOS                    |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

# Crear script Python temporal para el resumen
PY_SUMMARY="${SBOM_DIR}/_summary_tmp.py"
cat > "$PY_SUMMARY" << 'PYSCRIPT'
import json, os, glob, sys

sbom_dir = sys.argv[1] if len(sys.argv) > 1 else './data/sbom'
json_files = sorted(glob.glob(os.path.join(sbom_dir, '*_sbom_cyclonedx.json')))

if not json_files:
    print("  No se encontraron SBOMs.")
    sys.exit(0)

print(f"  {'Servicio':<18} {'Componentes':>12} {'Tipo BOM':<14} {'Spec Version':<14}")
print(f"  {'-'*18} {'-'*12} {'-'*14} {'-'*14}")

total_components = 0
for jf in json_files:
    try:
        with open(jf, 'rb') as f:
            raw = f.read()
        if raw[:3] == b'\xef\xbb\xbf': raw = raw[3:]
        data = json.loads(raw.decode('utf-8', errors='ignore'))
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
PYSCRIPT

"$PYTHON_CMD" "$PY_SUMMARY" "$SBOM_DIR"
rm -f "$PY_SUMMARY" 2>/dev/null || true

log ""
ok "Generacion de SBOMs completada (${GENERATED_OK}/${TOTAL} exitosos)"
info "Archivos en: ${SBOM_DIR}/"
log ""
info "Proximo paso:"
if [ "$IS_WINDOWS" = true ]; then
    log "    Escanear vulnerabilidades: ${C}.\\scripts\\scan_grype.ps1${N}  (PowerShell)"
    log "    o bien:                    ${C}bash scripts/scan_grype.sh${N}  (Git Bash)"
else
    log "    Escanear vulnerabilidades: ${C}./scripts/scan_grype.sh${N}"
fi
log ""
