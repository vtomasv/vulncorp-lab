#!/bin/bash
###############################################################################
#  VulnCorp Lab — Script de Escaneo de Vulnerabilidades con Trivy
#  Curso MAR303 — Universidad Mayor — 2026
#
#  Este script escanea todas las imágenes del laboratorio y genera reportes
#  en formato JSON que alimentan el dashboard de vulnerabilidades.
#
#  Compatible con: AMD64 (Intel/AMD) y ARM64 (Apple Silicon M1/M2/M3/M4)
###############################################################################

set -e

# Colores para la terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # Sin color
BOLD='\033[1m'

# Directorio de reportes (relativo al script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/../data"
mkdir -p "$REPORT_DIR"

# Timestamp para el reporte
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║     VulnCorp — Escáner de Vulnerabilidades (Trivy)          ║${NC}"
echo -e "${BOLD}${CYAN}║     Unidad 1: Gestión de Vulnerabilidades (MITRE)           ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Lista de imágenes a escanear (las mismas del docker-compose.yml)
# Usamos arrays indexados para mantener compatibilidad con bash 3.x (macOS)
SERVICE_NAMES=("nginx-proxy" "prestashop" "mariadb-prod" "redis-cache" "phpmyadmin" "workstation" "ftp-server")
SERVICE_IMAGES=("nginx:1.21.0" "prestashop/prestashop:1.7.8.0" "mariadb:10.5.18" "redis:6.2.6" "phpmyadmin:5.1.1" "ubuntu:20.04" "delfer/alpine-ftp-server")
SERVICE_ZONES=("produccion" "produccion" "produccion+corporativa" "produccion" "corporativa" "corporativa" "corporativa")
SERVICE_EXPOSURE=("internet" "internet-via-proxy" "interna" "interna" "red-interna" "red-interna" "red-interna")
SERVICE_CRITICALITY=("alta" "critica" "critica" "media" "alta" "baja" "media")

# Verificar que Trivy esté instalado
check_trivy() {
    if ! command -v trivy &> /dev/null; then
        echo -e "${YELLOW}[!] Trivy no encontrado. Instalando...${NC}"
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
        echo -e "${GREEN}[✓] Trivy instalado correctamente${NC}"
    else
        echo -e "${GREEN}[✓] Trivy encontrado: $(trivy --version 2>/dev/null | head -1)${NC}"
    fi
}

# Escanear una imagen individual
scan_image() {
    local idx=$1
    local service_name="${SERVICE_NAMES[$idx]}"
    local image="${SERVICE_IMAGES[$idx]}"
    local zone="${SERVICE_ZONES[$idx]}"
    local exposure="${SERVICE_EXPOSURE[$idx]}"
    local criticality="${SERVICE_CRITICALITY[$idx]}"
    local report_file="${REPORT_DIR}/${service_name}_trivy.json"

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Escaneando: ${CYAN}${service_name}${NC}"
    echo -e "  Imagen:     ${image}"
    echo -e "  Zona:       ${zone}"
    echo -e "  Exposición: ${exposure}"
    echo -e "  Criticidad: ${criticality}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Escanear con Trivy en formato JSON
    trivy image \
        --format json \
        --output "$report_file" \
        --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
        --quiet \
        "$image" 2>/dev/null || {
            echo -e "${RED}[✗] Error escaneando ${image}${NC}"
            return 1
        }

    # Contar vulnerabilidades por severidad usando python3
    if [ -f "$report_file" ]; then
        local counts
        counts=$(python3 -c "
import json, sys
with open('$report_file') as f:
    data = json.load(f)
counts = {'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0}
for result in data.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        sev = vuln.get('Severity','UNKNOWN')
        if sev in counts:
            counts[sev] += 1
print(f\"{counts['CRITICAL']} {counts['HIGH']} {counts['MEDIUM']} {counts['LOW']}\")
" 2>/dev/null || echo "0 0 0 0")

        local critical high medium low total
        critical=$(echo "$counts" | awk '{print $1}')
        high=$(echo "$counts" | awk '{print $2}')
        medium=$(echo "$counts" | awk '{print $3}')
        low=$(echo "$counts" | awk '{print $4}')
        total=$((critical + high + medium + low))

        echo -e "  ${RED}CRITICAL: ${critical}${NC}  |  ${YELLOW}HIGH: ${high}${NC}  |  ${BLUE}MEDIUM: ${medium}${NC}  |  ${GREEN}LOW: ${low}${NC}  |  TOTAL: ${total}"
        echo -e "${GREEN}  [✓] Reporte guardado: ${report_file}${NC}"

        # Guardar resumen
        echo "{\"service\":\"${service_name}\",\"image\":\"${image}\",\"zone\":\"${zone}\",\"exposure\":\"${exposure}\",\"criticality\":\"${criticality}\",\"critical\":${critical},\"high\":${high},\"medium\":${medium},\"low\":${low},\"total\":${total},\"timestamp\":\"${TIMESTAMP}\"}" >> "${REPORT_DIR}/scan_summary.jsonl"
    fi
}

# Generar reporte consolidado
generate_consolidated_report() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║              REPORTE CONSOLIDADO DE VULNERABILIDADES         ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    python3 << 'PYEOF'
import json
import os

script_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
report_dir = os.environ.get('REPORT_DIR', './data')
summary_file = os.path.join(report_dir, 'scan_summary.jsonl')

if not os.path.exists(summary_file):
    print("  No se encontraron resultados de escaneo.")
    exit(0)

services = []
with open(summary_file, 'r') as f:
    for line in f:
        if line.strip():
            services.append(json.loads(line.strip()))

# Tabla de resumen
print(f"  {'Servicio':<16} {'Zona':<22} {'Exposición':<18} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'TOTAL':>6}")
print(f"  {'─'*16} {'─'*22} {'─'*18} {'─'*5} {'─'*5} {'─'*5} {'─'*5} {'─'*6}")

total_c = total_h = total_m = total_l = total_t = 0
for s in services:
    print(f"  {s['service']:<16} {s['zone']:<22} {s['exposure']:<18} {s['critical']:>5} {s['high']:>5} {s['medium']:>5} {s['low']:>5} {s['total']:>6}")
    total_c += s['critical']
    total_h += s['high']
    total_m += s['medium']
    total_l += s['low']
    total_t += s['total']

print(f"  {'─'*16} {'─'*22} {'─'*18} {'─'*5} {'─'*5} {'─'*5} {'─'*5} {'─'*6}")
print(f"  {'TOTAL':<16} {'':<22} {'':<18} {total_c:>5} {total_h:>5} {total_m:>5} {total_l:>5} {total_t:>6}")
print()

# Generar JSON consolidado para el dashboard
consolidated = {
    "scan_timestamp": services[0]['timestamp'] if services else "",
    "total_services": len(services),
    "total_vulnerabilities": total_t,
    "by_severity": {
        "critical": total_c,
        "high": total_h,
        "medium": total_m,
        "low": total_l
    },
    "services": services
}

output_file = os.path.join(report_dir, 'consolidated_report.json')
with open(output_file, 'w') as f:
    json.dump(consolidated, f, indent=2)

print(f"  Reporte consolidado guardado en: {output_file}")
PYEOF
}

# ===================== EJECUCIÓN PRINCIPAL =====================
echo -e "${YELLOW}[1/3] Verificando herramientas...${NC}"
check_trivy

echo ""
echo -e "${YELLOW}[2/3] Escaneando imágenes del laboratorio VulnCorp...${NC}"

# Limpiar resumen anterior
rm -f "${REPORT_DIR}/scan_summary.jsonl"

# Escanear cada imagen
for i in "${!SERVICE_NAMES[@]}"; do
    scan_image "$i"
done

echo ""
echo -e "${YELLOW}[3/3] Generando reporte consolidado...${NC}"
export REPORT_DIR
generate_consolidated_report

echo ""
echo -e "${GREEN}${BOLD}[✓] Escaneo completado. Los reportes están en: ${REPORT_DIR}/${NC}"
echo -e "${CYAN}    Abra el dashboard en: http://localhost:3000${NC}"
echo ""
