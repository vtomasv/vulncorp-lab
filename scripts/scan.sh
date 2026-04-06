#!/bin/bash
###############################################################################
#  VulnCorp Lab — Script de Escaneo de Vulnerabilidades con Trivy
#  Curso: Gestión de Vulnerabilidades con Enfoque MITRE — 2026
#
#  Compatible con: Linux, macOS (Intel/ARM), Windows (Git Bash, MINGW, WSL2)
#
#  Uso:
#    ./scripts/scan.sh            # Modo normal
#    ./scripts/scan.sh --verbose  # Modo verbose (muestra salida completa de Trivy)
###############################################################################

# ─── Configuración de entorno para Windows ───────────────────────────────────
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

# ─── Modo verbose ────────────────────────────────────────────────────────────
VERBOSE=false
if [ "$1" = "--verbose" ] || [ "$1" = "-v" ]; then
    VERBOSE=true
fi

# No usar set -e para poder capturar errores sin que el script aborte
# set -e

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

# Archivo de log para diagnóstico
LOG_FILE="${REPORT_DIR}/scan.log"
echo "=== VulnCorp Scan Log - $(date) ===" > "$LOG_FILE"
echo "Plataforma: ${OS_TYPE}" >> "$LOG_FILE"
echo "REPORT_DIR: ${REPORT_DIR}" >> "$LOG_FILE"
echo "Trivy: $(trivy --version 2>&1 | head -1)" >> "$LOG_FILE"
echo "Python: $(python3 --version 2>&1)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

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
echo -e "  Archivo de log: ${CYAN}${LOG_FILE}${NC}"
if [ "$VERBOSE" = true ]; then
    echo -e "  Modo: ${YELLOW}VERBOSE (mostrando salida completa de Trivy)${NC}"
fi
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
        local trivy_ver
        trivy_ver=$(trivy --version 2>&1 | head -1)
        echo -e "${GREEN}[OK] Trivy encontrado: ${trivy_ver}${NC}"
    fi

    # Mostrar ubicación de Trivy y su cache
    local trivy_path
    trivy_path=$(command -v trivy 2>/dev/null || echo "no encontrado")
    echo -e "  Ruta de Trivy: ${trivy_path}"
    echo "Trivy path: ${trivy_path}" >> "$LOG_FILE"
}

# ─── Descargar/Actualizar la base de datos de Trivy ──────────────────────────
update_trivy_db() {
    echo -e "${YELLOW}[i] Descargando/actualizando base de datos de vulnerabilidades...${NC}"
    echo -e "    (Esto puede tomar unos minutos la primera vez)"

    # Limpiar scan cache para evitar resultados obsoletos
    echo -e "  Limpiando scan cache..."
    trivy clean --scan-cache 2>&1 | tee -a "$LOG_FILE" || true

    # Descargar la DB de vulnerabilidades
    local db_retries=3
    local db_ok=false
    for attempt in $(seq 1 $db_retries); do
        echo "" >> "$LOG_FILE"
        echo "=== DB Download attempt ${attempt}/${db_retries} ===" >> "$LOG_FILE"

        local db_output
        db_output=$(trivy image --download-db-only 2>&1)
        local db_exit_code=$?

        echo "$db_output" >> "$LOG_FILE"

        if [ $db_exit_code -eq 0 ]; then
            db_ok=true
            echo -e "${GREEN}  [OK] Base de datos descargada correctamente${NC}"
            break
        fi

        echo -e "${YELLOW}    [!] Intento ${attempt}/${db_retries} fallido (exit code: ${db_exit_code})${NC}"
        echo -e "${YELLOW}    Error: ${db_output}${NC}"

        # Limpiar DB corrupta antes de reintentar
        echo -e "    Limpiando DB corrupta..."
        trivy clean --vuln-db 2>&1 | tee -a "$LOG_FILE" || true
        sleep 2
    done

    if [ "$db_ok" = false ]; then
        echo -e "${RED}[X] No se pudo descargar la base de datos de Trivy despues de ${db_retries} intentos.${NC}"
        echo -e "${RED}    Verifique su conexion a Internet.${NC}"
        echo -e "${RED}    Revise el log: ${LOG_FILE}${NC}"
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
    # Imprimir el error real para diagnóstico
    print(f"ERROR: {e}", file=sys.stderr)
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
    local error_file="${REPORT_DIR}/${service_name}_error.log"

    echo ""
    echo -e "${BLUE}------------------------------------------------------------${NC}"
    echo -e "${BOLD}  Escaneando: ${CYAN}${service_name}${NC}"
    echo -e "  Imagen:     ${image}"
    echo -e "  Zona:       ${zone}"
    echo -e "  Exposicion: ${exposure}"
    echo -e "  Criticidad: ${criticality}"
    echo -e "  Reporte:    ${report_file}"
    echo -e "${BLUE}------------------------------------------------------------${NC}"

    echo "" >> "$LOG_FILE"
    echo "=== Scanning: ${service_name} (${image}) ===" >> "$LOG_FILE"

    local scan_ok=false
    local attempt=0
    local critical=0 high=0 medium=0 low=0 total=0

    while [ $attempt -lt $MAX_RETRIES ] && [ "$scan_ok" = false ]; do
        attempt=$((attempt + 1))

        if [ $attempt -gt 1 ]; then
            echo -e "${YELLOW}    [!] Reintento ${attempt}/${MAX_RETRIES} - Limpiando cache de escaneo...${NC}"
            trivy clean --scan-cache 2>&1 | tee -a "$LOG_FILE" || true
            sleep 1
        fi

        echo "  Attempt ${attempt}/${MAX_RETRIES}..." >> "$LOG_FILE"

        # Escanear con --skip-db-update (ya descargamos la DB antes)
        # Capturar TANTO stdout como stderr para diagnóstico
        local trivy_output
        trivy_output=$(trivy image \
            --format json \
            --output "$report_file" \
            --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
            --skip-db-update \
            "$image" 2>&1)
        local trivy_exit_code=$?

        # Guardar la salida de Trivy en el log
        echo "$trivy_output" >> "$LOG_FILE"
        echo "$trivy_output" > "$error_file"

        # Mostrar la salida de Trivy si estamos en modo verbose o si hubo error
        if [ "$VERBOSE" = true ]; then
            echo -e "${CYAN}  --- Salida de Trivy ---${NC}"
            echo "$trivy_output"
            echo -e "${CYAN}  --- Fin salida Trivy ---${NC}"
        fi

        if [ $trivy_exit_code -ne 0 ]; then
            echo -e "${RED}  [X] Trivy fallo con codigo de salida: ${trivy_exit_code}${NC}"
            echo -e "${RED}  Error de Trivy:${NC}"
            echo -e "${YELLOW}$(echo "$trivy_output" | tail -10)${NC}"
            echo -e ""
            echo -e "  Para ver el error completo:"
            echo -e "    cat ${error_file}"
            continue
        fi

        # Verificar que el archivo existe
        if [ ! -f "$report_file" ]; then
            echo -e "${RED}  [X] El archivo de reporte no se genero: ${report_file}${NC}"
            echo -e "${YELLOW}  Esto puede ser un problema de rutas en Windows.${NC}"
            echo -e "  Verificando directorio..."
            ls -la "$REPORT_DIR/" 2>&1 | head -5
            echo "  Report file not found: ${report_file}" >> "$LOG_FILE"
            continue
        fi

        # Verificar que no está vacío
        local file_size
        file_size=$(wc -c < "$report_file" 2>/dev/null || echo "0")
        file_size=$(echo "$file_size" | tr -d ' ')

        if [ "$file_size" = "0" ] || [ -z "$file_size" ]; then
            echo -e "${YELLOW}  [!] Reporte vacio (0 bytes) para ${service_name}${NC}"
            echo "  Report file empty: ${report_file}" >> "$LOG_FILE"
            continue
        fi

        echo -e "  Archivo generado: ${file_size} bytes"
        echo "  Report file size: ${file_size} bytes" >> "$LOG_FILE"

        # Mostrar primeros caracteres del JSON para diagnóstico
        if [ "$VERBOSE" = true ]; then
            echo -e "${CYAN}  Primeros 200 caracteres del JSON:${NC}"
            head -c 200 "$report_file"
            echo ""
        fi

        # Contar vulnerabilidades
        local counts
        counts=$(count_vulns "$report_file" 2>&1)
        local count_stderr
        count_stderr=$(count_vulns "$report_file" 2>&1 1>/dev/null)

        if [ -n "$count_stderr" ]; then
            echo -e "${YELLOW}  [!] Advertencia al contar vulnerabilidades: ${count_stderr}${NC}"
            echo "  Count warning: ${count_stderr}" >> "$LOG_FILE"
        fi

        # Extraer los valores (tomar solo la última línea que tiene los números)
        local count_line
        count_line=$(echo "$counts" | grep -E '^[0-9]' | tail -1)

        if [ -z "$count_line" ]; then
            echo -e "${RED}  [X] No se pudieron contar las vulnerabilidades${NC}"
            echo -e "  Salida del contador: '${counts}'"
            echo "  Count output: '${counts}'" >> "$LOG_FILE"
            continue
        fi

        critical=$(echo "$count_line" | awk '{print $1}')
        high=$(echo "$count_line" | awk '{print $2}')
        medium=$(echo "$count_line" | awk '{print $3}')
        low=$(echo "$count_line" | awk '{print $4}')
        total=$(echo "$count_line" | awk '{print $5}')

        # Asegurar que los valores son numéricos
        critical=${critical:-0}
        high=${high:-0}
        medium=${medium:-0}
        low=${low:-0}
        total=${total:-0}

        echo "  Counts: C=${critical} H=${high} M=${medium} L=${low} T=${total}" >> "$LOG_FILE"

        # Validar: si total es 0, verificar la estructura del JSON
        if [ "$total" = "0" ] && [ $attempt -lt $MAX_RETRIES ]; then
            echo -e "${YELLOW}  [!] Se detectaron 0 vulnerabilidades. Verificando estructura del JSON...${NC}"

            local json_check
            json_check=$(python3 -c "
import json, sys
try:
    with open(r'''$report_file''', encoding='utf-8-sig') as f:
        content = f.read().lstrip('\ufeff').replace('\x00', '')
    data = json.loads(content)
    results = data.get('Results', [])
    num_results = len(results)
    has_vulns = any('Vulnerabilities' in r for r in results)
    total_pkgs = sum(len(r.get('Packages', [])) for r in results)
    print(f'Results: {num_results}, HasVulns: {has_vulns}, Packages: {total_pkgs}')
except Exception as e:
    print(f'ERROR: {e}')
" 2>&1)

            echo -e "  Diagnostico JSON: ${json_check}"
            echo "  JSON check: ${json_check}" >> "$LOG_FILE"

            # Si no hay key Vulnerabilities pero sí hay Results, puede ser legítimo
            if echo "$json_check" | grep -q "HasVulns: False"; then
                if echo "$json_check" | grep -q "Packages: 0"; then
                    echo -e "${YELLOW}  [!] Trivy no detecto paquetes. Posible problema de cache. Reintentando...${NC}"
                    continue
                else
                    echo -e "${YELLOW}  [i] Trivy detecto paquetes pero no vulnerabilidades. Puede ser legitimo.${NC}"
                fi
            fi
            if echo "$json_check" | grep -q "ERROR"; then
                echo -e "${RED}  [X] Error al analizar el JSON. Reintentando...${NC}"
                continue
            fi
        fi

        scan_ok=true
    done

    if [ "$scan_ok" = false ]; then
        echo -e "${RED}  [X] No se pudo obtener resultados para ${service_name} despues de ${MAX_RETRIES} intentos${NC}"
        echo -e "${YELLOW}  Revise el log para mas detalles: ${LOG_FILE}${NC}"
        echo -e "${YELLOW}  Revise el error de Trivy: ${error_file}${NC}"
        echo '{"Results":[]}' > "$report_file"
        critical=0; high=0; medium=0; low=0; total=0
    fi

    # Limpiar archivo de error si el scan fue exitoso
    if [ "$scan_ok" = true ] && [ -f "$error_file" ]; then
        rm -f "$error_file"
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
rm -f "${REPORT_DIR}"/*_error.log

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
echo -e "${CYAN}     Log de diagnostico: ${LOG_FILE}${NC}"
echo ""
echo -e "  Si hay problemas, ejecute con modo verbose para mas detalles:"
echo -e "    ${BOLD}./scripts/scan.sh --verbose${NC}"
echo ""
