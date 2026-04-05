#!/bin/bash
###############################################################################
#  VulnCorp Lab 02 — Generación de SBOM con Syft (CycloneDX)
#  Curso MAR303 — Universidad Mayor — 2026
#
#  Este script genera el Software Bill of Materials (SBOM) de cada imagen
#  del Lab 01 usando Syft en formato CycloneDX JSON.
#
#  CycloneDX es un estándar OWASP para describir la composición de software.
#  Cada SBOM contiene: componentes, versiones, licencias, hashes y relaciones.
#
#  Formatos generados:
#    - CycloneDX JSON  (principal, para Dependency-Track y DefectDojo)
#    - CycloneDX XML   (alternativo, para compatibilidad)
#    - Tabla resumen    (para análisis visual rápido)
###############################################################################

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB02_DIR="$(dirname "$SCRIPT_DIR")"
SBOM_DIR="${LAB02_DIR}/data/sbom"
mkdir -p "$SBOM_DIR"

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║  VulnCorp Lab 02 — Generación de SBOM con Syft             ║${NC}"
echo -e "${BOLD}${CYAN}║  Formato: CycloneDX (OWASP Standard)                       ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Verificar Syft
if ! command -v syft &> /dev/null; then
    echo -e "${RED}[✗] Syft no encontrado. Ejecute primero: ./scripts/setup_lab02.sh${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Syft: $(syft version 2>/dev/null | grep '^Application' || syft version 2>/dev/null | head -1)${NC}"
echo ""

# =====================================================================
#  Imágenes del Lab 01 (VulnCorp PetaShop)
# =====================================================================
# Usamos arrays indexados para compatibilidad con bash 3.x (macOS)
IMAGE_NAMES=("nginx-proxy" "prestashop" "mariadb-prod" "redis-cache" "phpmyadmin" "workstation" "ftp-server")
IMAGE_TAGS=("nginx:1.21.0" "prestashop/prestashop:1.7.8.0" "mariadb:10.5.18" "redis:6.2.6" "phpmyadmin:5.1.1" "ubuntu:20.04" "delfer/alpine-ftp-server")

TOTAL=${#IMAGE_NAMES[@]}
CURRENT=0

for i in "${!IMAGE_NAMES[@]}"; do
    CURRENT=$((CURRENT + 1))
    NAME="${IMAGE_NAMES[$i]}"
    IMAGE="${IMAGE_TAGS[$i]}"

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  [${CURRENT}/${TOTAL}] Generando SBOM: ${CYAN}${NAME}${NC}"
    echo -e "  Imagen: ${IMAGE}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # --- CycloneDX JSON (formato principal) ---
    JSON_FILE="${SBOM_DIR}/${NAME}_sbom_cyclonedx.json"
    echo -e "  Generando CycloneDX JSON..."
    syft "$IMAGE" -o cyclonedx-json="$JSON_FILE" --quiet 2>/dev/null || \
    syft "$IMAGE" -o cyclonedx-json > "$JSON_FILE" 2>/dev/null

    if [ -f "$JSON_FILE" ] && [ -s "$JSON_FILE" ]; then
        # Contar componentes
        COMP_COUNT=$(python3 -c "
import json
with open('$JSON_FILE') as f:
    data = json.load(f)
components = data.get('components', [])
print(len(components))
" 2>/dev/null || echo "?")
        echo -e "${GREEN}  [✓] CycloneDX JSON: ${JSON_FILE}${NC}"
        echo -e "      Componentes encontrados: ${BOLD}${COMP_COUNT}${NC}"
    else
        echo -e "${RED}  [✗] Error generando SBOM para ${IMAGE}${NC}"
        continue
    fi

    # --- CycloneDX XML (formato alternativo) ---
    XML_FILE="${SBOM_DIR}/${NAME}_sbom_cyclonedx.xml"
    echo -e "  Generando CycloneDX XML..."
    syft "$IMAGE" -o cyclonedx-xml="$XML_FILE" --quiet 2>/dev/null || \
    syft "$IMAGE" -o cyclonedx-xml > "$XML_FILE" 2>/dev/null

    if [ -f "$XML_FILE" ] && [ -s "$XML_FILE" ]; then
        echo -e "${GREEN}  [✓] CycloneDX XML:  ${XML_FILE}${NC}"
    fi

    # --- Tabla resumen (para análisis visual) ---
    TABLE_FILE="${SBOM_DIR}/${NAME}_sbom_table.txt"
    syft "$IMAGE" -o table > "$TABLE_FILE" 2>/dev/null
    echo -e "${GREEN}  [✓] Tabla resumen:  ${TABLE_FILE}${NC}"
    echo ""
done

# =====================================================================
#  Resumen consolidado
# =====================================================================
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║              RESUMEN DE SBOMs GENERADOS                     ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Generar resumen con Python
python3 << 'PYEOF'
import json, os, glob

sbom_dir = os.environ.get('SBOM_DIR', './data/sbom')
json_files = sorted(glob.glob(os.path.join(sbom_dir, '*_cyclonedx.json')))

print(f"  {'Servicio':<18} {'Componentes':>12} {'Tipo BOM':<14} {'Spec Version':<14} {'Serial Number'}")
print(f"  {'─'*18} {'─'*12} {'─'*14} {'─'*14} {'─'*40}")

total_components = 0
for jf in json_files:
    try:
        with open(jf) as f:
            data = json.load(f)
        name = os.path.basename(jf).replace('_sbom_cyclonedx.json', '')
        comp_count = len(data.get('components', []))
        bom_format = data.get('bomFormat', 'N/A')
        spec_ver = data.get('specVersion', 'N/A')
        serial = data.get('serialNumber', 'N/A')[:38]
        total_components += comp_count
        print(f"  {name:<18} {comp_count:>12} {bom_format:<14} {spec_ver:<14} {serial}")
    except Exception as e:
        print(f"  Error leyendo {jf}: {e}")

print(f"  {'─'*18} {'─'*12} {'─'*14} {'─'*14} {'─'*40}")
print(f"  {'TOTAL':<18} {total_components:>12}")
print()

# Guardar resumen JSON
summary = {
    "timestamp": os.popen("date -u +%Y-%m-%dT%H:%M:%SZ").read().strip(),
    "total_images": len(json_files),
    "total_components": total_components,
    "sbom_files": [os.path.basename(f) for f in json_files]
}
summary_file = os.path.join(sbom_dir, 'sbom_summary.json')
with open(summary_file, 'w') as f:
    json.dump(summary, f, indent=2)
print(f"  Resumen guardado en: {summary_file}")
PYEOF

export SBOM_DIR

echo ""
echo -e "${GREEN}${BOLD}[✓] Generación de SBOMs completada${NC}"
echo -e "    Archivos en: ${SBOM_DIR}/"
echo ""
echo -e "  ${BOLD}Próximo paso:${NC}"
echo -e "    Escanear vulnerabilidades: ${CYAN}./scripts/scan_grype.sh${NC}"
echo ""
