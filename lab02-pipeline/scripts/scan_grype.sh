#!/bin/bash
###############################################################################
#  VulnCorp Lab 02 — Escaneo de Vulnerabilidades con Grype
#  Curso MAR303 — Universidad Mayor — 2026
#
#  Este script toma los SBOMs generados por Syft (CycloneDX JSON) y los
#  pasa por Grype para detectar vulnerabilidades conocidas.
#
#  Grype cruza cada componente del SBOM contra múltiples fuentes:
#    - NVD (National Vulnerability Database)
#    - GitHub Security Advisories
#    - Alpine SecDB, Debian Security Tracker, etc.
#
#  Formatos de salida:
#    - CycloneDX JSON  (para importar en DefectDojo)
#    - Tabla resumen    (para análisis visual)
#    - JSON detallado   (para procesamiento programático)
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
GRYPE_DIR="${LAB02_DIR}/data/grype"
mkdir -p "$GRYPE_DIR"

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║  VulnCorp Lab 02 — Escaneo de Vulnerabilidades con Grype    ║${NC}"
echo -e "${BOLD}${CYAN}║  Fuente: SBOMs CycloneDX generados por Syft                ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Verificar Grype
if ! command -v grype &> /dev/null; then
    echo -e "${RED}[✗] Grype no encontrado. Ejecute primero: ./scripts/setup_lab02.sh${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Grype: $(grype version 2>/dev/null | grep '^Application' || grype version 2>/dev/null | head -1)${NC}"

# Verificar que existan SBOMs
SBOM_FILES=("$SBOM_DIR"/*_sbom_cyclonedx.json)
if [ ! -f "${SBOM_FILES[0]}" ]; then
    echo -e "${RED}[✗] No se encontraron SBOMs en ${SBOM_DIR}/${NC}"
    echo -e "${YELLOW}    Ejecute primero: ./scripts/generate_sbom.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] SBOMs encontrados: ${#SBOM_FILES[@]} archivos${NC}"
echo ""

# Actualizar base de datos de Grype
echo -e "${YELLOW}[i] Actualizando base de datos de vulnerabilidades de Grype...${NC}"
grype db update 2>/dev/null || echo -e "${YELLOW}    (usando base de datos existente)${NC}"
echo ""

TOTAL=${#SBOM_FILES[@]}
CURRENT=0

for SBOM_FILE in "${SBOM_FILES[@]}"; do
    CURRENT=$((CURRENT + 1))
    BASENAME=$(basename "$SBOM_FILE" | sed 's/_sbom_cyclonedx\.json//')

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  [${CURRENT}/${TOTAL}] Escaneando: ${CYAN}${BASENAME}${NC}"
    echo -e "  SBOM: ${SBOM_FILE}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # --- Escaneo con salida CycloneDX (para DefectDojo) ---
    CYCLONEDX_OUT="${GRYPE_DIR}/${BASENAME}_grype_cyclonedx.json"
    echo -e "  Generando reporte CycloneDX..."
    grype "sbom:${SBOM_FILE}" -o cyclonedx-json > "$CYCLONEDX_OUT" 2>/dev/null || \
    grype "sbom:${SBOM_FILE}" -o cyclonedx-json > "$CYCLONEDX_OUT"

    if [ -f "$CYCLONEDX_OUT" ] && [ -s "$CYCLONEDX_OUT" ]; then
        echo -e "${GREEN}  [✓] CycloneDX: ${CYCLONEDX_OUT}${NC}"
    fi

    # --- Escaneo con salida JSON detallada ---
    JSON_OUT="${GRYPE_DIR}/${BASENAME}_grype_detail.json"
    grype "sbom:${SBOM_FILE}" -o json > "$JSON_OUT" 2>/dev/null

    # --- Contar vulnerabilidades por severidad ---
    if [ -f "$JSON_OUT" ] && [ -s "$JSON_OUT" ]; then
        COUNTS=$(python3 -c "
import json
with open('$JSON_OUT') as f:
    data = json.load(f)
matches = data.get('matches', [])
counts = {'Critical':0, 'High':0, 'Medium':0, 'Low':0, 'Negligible':0}
for m in matches:
    sev = m.get('vulnerability',{}).get('severity','Unknown')
    if sev in counts:
        counts[sev] += 1
total = sum(counts.values())
print(f\"{counts['Critical']} {counts['High']} {counts['Medium']} {counts['Low']} {counts['Negligible']} {total}\")
" 2>/dev/null || echo "0 0 0 0 0 0")

        CRIT=$(echo "$COUNTS" | awk '{print $1}')
        HIGH=$(echo "$COUNTS" | awk '{print $2}')
        MED=$(echo "$COUNTS" | awk '{print $3}')
        LOW=$(echo "$COUNTS" | awk '{print $4}')
        NEG=$(echo "$COUNTS" | awk '{print $5}')
        TOT=$(echo "$COUNTS" | awk '{print $6}')

        echo -e "  ${RED}CRITICAL: ${CRIT}${NC} | ${YELLOW}HIGH: ${HIGH}${NC} | ${BLUE}MEDIUM: ${MED}${NC} | ${GREEN}LOW: ${LOW}${NC} | NEGLIGIBLE: ${NEG} | TOTAL: ${TOT}"
    fi

    # --- Tabla resumen legible ---
    TABLE_OUT="${GRYPE_DIR}/${BASENAME}_grype_table.txt"
    grype "sbom:${SBOM_FILE}" -o table > "$TABLE_OUT" 2>/dev/null
    echo -e "${GREEN}  [✓] Tabla:     ${TABLE_OUT}${NC}"

    # Guardar línea de resumen
    echo "{\"service\":\"${BASENAME}\",\"critical\":${CRIT:-0},\"high\":${HIGH:-0},\"medium\":${MED:-0},\"low\":${LOW:-0},\"negligible\":${NEG:-0},\"total\":${TOT:-0}}" >> "${GRYPE_DIR}/grype_summary.jsonl"

    echo ""
done

# =====================================================================
#  Resumen consolidado
# =====================================================================
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║           RESUMEN DE VULNERABILIDADES (GRYPE)               ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

python3 << 'PYEOF'
import json, os

grype_dir = os.environ.get('GRYPE_DIR', './data/grype')
summary_file = os.path.join(grype_dir, 'grype_summary.jsonl')

if not os.path.exists(summary_file):
    print("  No se encontraron resultados.")
    exit(0)

services = []
with open(summary_file) as f:
    for line in f:
        if line.strip():
            services.append(json.loads(line.strip()))

print(f"  {'Servicio':<18} {'CRIT':>6} {'HIGH':>6} {'MED':>6} {'LOW':>6} {'NEG':>6} {'TOTAL':>7}")
print(f"  {'─'*18} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*7}")

tc = th = tm = tl = tn = tt = 0
for s in services:
    print(f"  {s['service']:<18} {s['critical']:>6} {s['high']:>6} {s['medium']:>6} {s['low']:>6} {s['negligible']:>6} {s['total']:>7}")
    tc += s['critical']; th += s['high']; tm += s['medium']
    tl += s['low']; tn += s['negligible']; tt += s['total']

print(f"  {'─'*18} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*7}")
print(f"  {'TOTAL':<18} {tc:>6} {th:>6} {tm:>6} {tl:>6} {tn:>6} {tt:>7}")
print()

# Guardar consolidado
consolidated = {
    "total_services": len(services),
    "total_vulnerabilities": tt,
    "by_severity": {"critical": tc, "high": th, "medium": tm, "low": tl, "negligible": tn},
    "services": services
}
out = os.path.join(grype_dir, 'grype_consolidated.json')
with open(out, 'w') as f:
    json.dump(consolidated, f, indent=2)
print(f"  Consolidado guardado en: {out}")
PYEOF

export GRYPE_DIR

echo ""
echo -e "${GREEN}${BOLD}[✓] Escaneo con Grype completado${NC}"
echo -e "    Reportes en: ${GRYPE_DIR}/"
echo ""
echo -e "  ${BOLD}Próximo paso:${NC}"
echo -e "    Subir a plataformas: ${CYAN}python3 scripts/upload_reports.py${NC}"
echo ""
