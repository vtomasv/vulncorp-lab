#!/bin/bash
###############################################################################
#  VulnCorp Lab — Script de Escaneo de Vulnerabilidades con Trivy
#  Curso: Gestión de Vulnerabilidades con Enfoque MITRE — 2026
#
#  Este script escanea todas las imágenes del laboratorio y genera reportes
#  en formato JSON que alimentan el dashboard de vulnerabilidades.
#
#  Compatible con:
#    - Linux (AMD64 / ARM64)
#    - macOS (Intel / Apple Silicon M1/M2/M3/M4)
#    - Windows (Git Bash, MINGW, WSL2, PowerShell via bash)
#
#  Problemas conocidos resueltos:
#    - MINGW path mangling en Windows (MSYS_NO_PATHCONV)
#    - Trivy DB corruption al re-descargar (separar DB download del scan)
#    - BOM UTF-8 en archivos generados en Windows
#    - Trivy scan cache corrupto (limpieza automática)
###############################################################################

# ─── Configuración de entorno para Windows ───────────────────────────────────
# MINGW/Git Bash en Windows convierte automáticamente rutas Unix a Windows,
# lo que rompe argumentos como --output /ruta/archivo.json.
# MSYS_NO_PATHCONV=1 desactiva esta conversión.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

set -e

# ─── Detección de plataforma ─────────────────────────────────────────────────
OS_TYPE="linux"
WINDOWS_MODE=false

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        OS_TYPE="windows"
        WINDOWS_MODE=true
        ;;
    Darwin*)
        OS_TYPE="macos"
        ;;
    Linux*)
        if grep -qi microsoft /proc/version 2>/dev/null; then
            OS_TYPE="wsl"
        fi
        ;;
esac

# ─── Colores según plataforma ────────────────────────────────────────────────
supports_color() {
    if [ "$WINDOWS_MODE" = true ]; then
        if [ -n "$WT_SESSION" ] || [ -n "$TERM_PROGRAM" ] || [ "$TERM" = "xterm-256color" ]; then
            return 0
        fi
        return 1
    fi
    return 0
}

if supports_color; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
    BOLD='\033[1m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    NC=''
    BOLD=''
fi

# ─── Directorio de reportes ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/../data"
mkdir -p "$REPORT_DIR"
REPORT_DIR="$(cd "$REPORT_DIR" && pwd)"

# Timestamp para el reporte
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# Número máximo de reintentos por imagen
MAX_RETRIES=2

echo ""
echo -e "${BOLD}${CYAN}+============================================================+${NC}"
echo -e "${BOLD}${CYAN}|     VulnCorp -- Escaner de Vulnerabilidades (Trivy)        |${NC}"
echo -e "${BOLD}${CYAN}|     Unidad 1: Gestion de Vulnerabilidades (MITRE)          |${NC}"
echo -e "${BOLD}${CYAN}+============================================================+${NC}"
echo ""
echo -e "  Plataforma detectada: ${CYAN}${OS_TYPE}${NC}"
echo -e "  Directorio de reportes: ${CYAN}${REPORT_DIR}${NC}"
echo ""

# Lista de imágenes a escanear
SERVICE_NAMES=("nginx-proxy" "prestashop" "mariadb-prod" "redis-cache" "phpmyadmin" "workstation" "ftp-server")
SERVICE_IMAGES=("nginx:1.21.0" "prestashop/prestashop:1.7.8.0" "mariadb:10.5.18" "redis:6.2.6" "phpmyadmin:5.1.1" "ubuntu:20.04" "delfer/alpine-ftp-server")
SERVICE_ZONES=("produccion" "produccion" "produccion+corporativa" "produccion" "corporativa" "corporativa" "corporativa")
SERVICE_EXPOSURE=("internet" "internet-via-proxy" "interna" "interna" "red-interna" "red-interna" "red-interna")
SERVICE_CRITICALITY=("alta" "critica" "critica" "media" "alta" "baja" "media")

# ─── Verificar Trivy ─────────────────────────────────────────────────────────
check_trivy() {
    if ! command -v trivy &> /dev/null; then
        echo -e "${YELLOW}[!] Trivy no encontrado. Instalando...${NC}"
        if [ "$OS_TYPE" = "macos" ]; then
            if command -v brew &> /dev/null; then
                brew install trivy
            else
                echo -e "${RED}[!] Homebrew no encontrado. Instale Trivy manualmente: https://trivy.dev${NC}"
                exit 1
            fi
        elif [ "$WINDOWS_MODE" = true ]; then
            echo -e "${YELLOW}[!] En Windows, instale Trivy con:${NC}"
            echo "      choco install trivy"
            echo "      scoop install trivy"
            echo "      o descargue de: https://github.com/aquasecurity/trivy/releases"
            exit 1
        else
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
        fi
        echo -e "${GREEN}[OK] Trivy instalado correctamente${NC}"
    else
        echo -e "${GREEN}[OK] Trivy encontrado: $(trivy --version 2>/dev/null | head -1)${NC}"
    fi
}

# ─── Descargar/Actualizar la base de datos de Trivy ──────────────────────────
# IMPORTANTE: Separamos la descarga de la DB del escaneo.
# En Windows, si Trivy descarga la DB durante el escaneo y la descarga se
# interrumpe o corrompe, el escaneo reporta 0 vulnerabilidades silenciosamente.
# Ref: https://github.com/aquasecurity/trivy/discussions/7758
update_trivy_db() {
    echo -e "${YELLOW}[i] Descargando/actualizando base de datos de vulnerabilidades...${NC}"
    echo -e "    (Esto puede tomar unos minutos la primera vez)"

    # Limpiar scan cache para evitar resultados obsoletos
    trivy clean --scan-cache 2>/dev/null || true

    # Descargar la DB de vulnerabilidades
    local db_retries=3
    local db_ok=false
    for attempt in $(seq 1 $db_retries); do
        if trivy image --download-db-only 2>/dev/null; then
            db_ok=true
            break
        fi
        echo -e "${YELLOW}    [!] Intento ${attempt}/${db_retries} de descarga de DB fallido. Reintentando...${NC}"
        # Limpiar DB corrupta antes de reintentar
        trivy clean --vuln-db 2>/dev/null || true
        sleep 2
    done

    if [ "$db_ok" = false ]; then
        echo -e "${RED}[X] No se pudo descargar la base de datos de Trivy.${NC}"
        echo -e "${RED}    Verifique su conexion a Internet e intente de nuevo.${NC}"
        exit 1
    fi

    echo -e "${GREEN}[OK] Base de datos de vulnerabilidades actualizada${NC}"
}

# ─── Contar vulnerabilidades en un archivo JSON ──────────────────────────────
count_vulns() {
    local report_file="$1"
    python3 << PYEOF
import json, sys, os

report_file = os.path.normpath(r'''$report_file''')

try:
    with open(report_file, encoding='utf-8-sig') as f:
        content = f.read()

    # Eliminar BOM si existe
    if content and ord(content[0]) == 0xFEFF:
        content = content[1:]

    # Eliminar caracteres nulos
    content = content.replace('\x00', '')

    data = json.loads(content)

    counts = {'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0}
    results = data.get('Results', [])

    for result in results:
        vulns = result.get('Vulnerabilities', [])
        if vulns is None:
            continue
        for vuln in vulns:
            sev = vuln.get('Severity','UNKNOWN')
            if sev in counts:
                counts[sev] += 1

    total = sum(counts.values())
    print(f"{counts['CRITICAL']} {counts['HIGH']} {counts['MEDIUM']} {counts['LOW']} {total}")

except Exception as e:
    print(f"0 0 0 0 0", file=sys.stderr)
    print(f"0 0 0 0 0")
PYEOF
}

# ─── Escanear una imagen ─────────────────────────────────────────────────────
scan_image() {
    local idx=$1
    local service_name="${SERVICE_NAMES[$idx]}"
    local image="${SERVICE_IMAGES[$idx]}"
    local zone="${SERVICE_ZONES[$idx]}"
    local exposure="${SERVICE_EXPOSURE[$idx]}"
    local criticality="${SERVICE_CRITICALITY[$idx]}"
    local report_file="${REPORT_DIR}/${service_name}_trivy.json"

    echo ""
    echo -e "${BLUE}------------------------------------------------------------${NC}"
    echo -e "${BOLD}  Escaneando: ${CYAN}${service_name}${NC}"
    echo -e "  Imagen:     ${image}"
    echo -e "  Zona:       ${zone}"
    echo -e "  Exposicion: ${exposure}"
    echo -e "  Criticidad: ${criticality}"
    echo -e "${BLUE}------------------------------------------------------------${NC}"

    local scan_ok=false
    local attempt=0

    while [ $attempt -lt $MAX_RETRIES ] && [ "$scan_ok" = false ]; do
        attempt=$((attempt + 1))

        if [ $attempt -gt 1 ]; then
            echo -e "${YELLOW}    [!] Reintento ${attempt}/${MAX_RETRIES} - Limpiando cache de escaneo...${NC}"
            trivy clean --scan-cache 2>/dev/null || true
            sleep 1
        fi

        # Escanear con --skip-db-update (ya descargamos la DB antes)
        trivy image \
            --format json \
            --output "$report_file" \
            --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
            --skip-db-update \
            --quiet \
            "$image" 2>/dev/null || {
                echo -e "${RED}[X] Error escaneando ${image}${NC}"
                continue
            }

        # Verificar que el archivo existe y no está vacío
        if [ ! -s "$report_file" ]; then
            echo -e "${YELLOW}    [!] Reporte vacio para ${service_name}${NC}"
            continue
        fi

        # Contar vulnerabilidades
        local counts
        counts=$(count_vulns "$report_file")

        local critical high medium low total
        critical=$(echo "$counts" | awk '{print $1}')
        high=$(echo "$counts" | awk '{print $2}')
        medium=$(echo "$counts" | awk '{print $3}')
        low=$(echo "$counts" | awk '{print $4}')
        total=$(echo "$counts" | awk '{print $5}')

        # Validar: si total es 0 y no es la primera vez, reintentar
        # (algunas imágenes como alpine-ftp pueden tener legítimamente 0)
        if [ "$total" = "0" ] && [ $attempt -lt $MAX_RETRIES ]; then
            echo -e "${YELLOW}    [!] Se detectaron 0 vulnerabilidades. Verificando...${NC}"

            # Verificar si el JSON tiene la estructura correcta
            local has_results
            has_results=$(python3 -c "
import json
try:
    with open(r'''$report_file''', encoding='utf-8-sig') as f:
        data = json.loads(f.read().lstrip('\ufeff'))
    results = data.get('Results', [])
    has_vulns_key = any('Vulnerabilities' in r for r in results)
    print('yes' if has_vulns_key else 'no')
except:
    print('error')
" 2>/dev/null || echo "error")

            if [ "$has_results" = "no" ] || [ "$has_results" = "error" ]; then
                echo -e "${YELLOW}    [!] El JSON no contiene datos de vulnerabilidades. Reintentando...${NC}"
                continue
            fi
        fi

        scan_ok=true
    done

    if [ "$scan_ok" = false ]; then
        echo -e "${RED}[X] No se pudo obtener resultados para ${service_name} despues de ${MAX_RETRIES} intentos${NC}"
        # Crear un reporte vacío para no romper el flujo
        echo '{"Results":[]}' > "$report_file"
        local critical=0 high=0 medium=0 low=0 total=0
    fi

    echo ""
    echo -e "  ${RED}CRITICAL: ${critical}${NC}  |  ${YELLOW}HIGH: ${high}${NC}  |  ${BLUE}MEDIUM: ${medium}${NC}  |  ${GREEN}LOW: ${low}${NC}  |  TOTAL: ${total}"
    echo -e "${GREEN}  [OK] Reporte guardado: ${report_file}${NC}"

    # Guardar resumen en JSONL
    echo "{\"service\":\"${service_name}\",\"image\":\"${image}\",\"zone\":\"${zone}\",\"exposure\":\"${exposure}\",\"criticality\":\"${criticality}\",\"critical\":${critical},\"high\":${high},\"medium\":${medium},\"low\":${low},\"total\":${total},\"timestamp\":\"${TIMESTAMP}\"}" >> "${REPORT_DIR}/scan_summary.jsonl"
}

# ─── Generar reporte consolidado ──────────────────────────────────────────────
generate_consolidated_report() {
    echo ""
    echo -e "${BOLD}${CYAN}+============================================================+${NC}"
    echo -e "${BOLD}${CYAN}|          REPORTE CONSOLIDADO DE VULNERABILIDADES           |${NC}"
    echo -e "${BOLD}${CYAN}+============================================================+${NC}"
    echo ""

    python3 << 'PYEOF'
import json
import os
import sys

report_dir = os.environ.get('REPORT_DIR', './data')
summary_file = os.path.join(report_dir, 'scan_summary.jsonl')

if not os.path.exists(summary_file):
    print("  No se encontraron resultados de escaneo.")
    sys.exit(0)

services = []
with open(summary_file, 'r', encoding='utf-8-sig') as f:
    for line in f:
        line = line.strip()
        if line:
            # Eliminar BOM si existe en la línea
            if line and ord(line[0]) == 0xFEFF:
                line = line[1:]
            try:
                services.append(json.loads(line))
            except json.JSONDecodeError:
                continue

if not services:
    print("  No se encontraron resultados validos.")
    sys.exit(0)

# Tabla de resumen
header = f"  {'Servicio':<16} {'Zona':<22} {'Exposicion':<18} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'TOTAL':>6}"
separator = f"  {'-'*16} {'-'*22} {'-'*18} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*6}"

print(header)
print(separator)

total_c = total_h = total_m = total_l = total_t = 0
for s in services:
    print(f"  {s['service']:<16} {s['zone']:<22} {s['exposure']:<18} {s['critical']:>5} {s['high']:>5} {s['medium']:>5} {s['low']:>5} {s['total']:>6}")
    total_c += s['critical']
    total_h += s['high']
    total_m += s['medium']
    total_l += s['low']
    total_t += s['total']

print(separator)
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
with open(output_file, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(consolidated, f, indent=2, ensure_ascii=False)

print(f"  Reporte consolidado guardado en: {output_file}")
PYEOF
}

# ═══════════════════════════════════════════════════════════════════════════════
#  EJECUCION PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[1/4] Verificando herramientas...${NC}"
check_trivy

echo ""
echo -e "${YELLOW}[2/4] Actualizando base de datos de vulnerabilidades...${NC}"
update_trivy_db

echo ""
echo -e "${YELLOW}[3/4] Escaneando imagenes del laboratorio VulnCorp...${NC}"

# Limpiar resumen anterior
rm -f "${REPORT_DIR}/scan_summary.jsonl"

# Escanear cada imagen
for i in "${!SERVICE_NAMES[@]}"; do
    scan_image "$i"
done

echo ""
echo -e "${YELLOW}[4/4] Generando reporte consolidado...${NC}"
export REPORT_DIR
generate_consolidated_report

echo ""
echo -e "${GREEN}${BOLD}[OK] Escaneo completado. Los reportes estan en: ${REPORT_DIR}/${NC}"
echo -e "${CYAN}     Abra el dashboard en: http://localhost:3000${NC}"
echo ""
