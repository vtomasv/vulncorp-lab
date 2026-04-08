#!/usr/bin/env bash
###############################################################################
#  VulnCorp Lab 02 -- Escaneo de Vulnerabilidades con Grype
#  Curso: Gestion de Vulnerabilidades con Enfoque MITRE -- 2026
#
#  Compatible con: Linux, macOS, Windows (Git Bash MINGW64 / WSL2)
#
#  Toma los SBOMs generados por Syft (CycloneDX JSON) y los pasa por Grype
#  para detectar vulnerabilidades conocidas.
#
#  SOLUCION WINDOWS: Grype es un binario nativo de Windows (.exe).
#  Cuando se ejecuta desde Git Bash, las rutas POSIX (/c/Users/...)
#  NO son reconocidas por Grype. Este script convierte las rutas
#  a formato Windows nativo (C:\Users\...) para los argumentos de Grype,
#  mientras mantiene rutas POSIX para los comandos de bash.
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

# =====================================================================
#  FUNCION CRITICA: Convertir ruta POSIX a ruta Windows nativa
#  En Git Bash: /c/Users/nombre/... -> C:\Users\nombre\...
#  En Linux/macOS: devuelve la ruta sin cambios
# =====================================================================
to_win_path() {
    local p="$1"
    if [ "$IS_GITBASH" = true ]; then
        # Intentar con cygpath (viene con Git Bash)
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -w "$p"
        else
            # Fallback: conversion manual /c/... -> C:\...
            echo "$p" | sed -E 's|^/([a-zA-Z])/|\1:\\|' | sed 's|/|\\|g'
        fi
    else
        echo "$p"
    fi
}

# --- Directorios ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB02_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SBOM_DIR="${LAB02_DIR}/data/sbom"
GRYPE_DIR="${LAB02_DIR}/data/grype"
mkdir -p "$GRYPE_DIR"

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

log ""
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|  VulnCorp Lab 02 -- Escaneo de Vulnerabilidades con Grype  |${N}"
log "${BOLD}${C}|  Fuente: SBOMs CycloneDX generados por Syft               |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

# Verificar Grype
if ! command -v grype >/dev/null 2>&1; then
    fail "Grype no encontrado."
    if [ "$IS_WINDOWS" = true ]; then
        info "Instale con: choco install grype  o  scoop install grype"
    else
        info "Ejecute primero: ./scripts/setup_lab02.sh"
    fi
    exit 1
fi
grype_ver=$(grype version 2>/dev/null | grep -i 'version' | head -1 || grype version 2>/dev/null | head -1 || echo "desconocida")
ok "Grype: ${grype_ver}"

# Mostrar plataforma detectada
if [ "$IS_GITBASH" = true ]; then
    info "Plataforma: Windows (Git Bash / MINGW)"
    info "Las rutas se convertiran a formato Windows para Grype"
elif [ "$IS_WINDOWS" = true ]; then
    info "Plataforma: Windows (Cygwin)"
else
    info "Plataforma: $(uname -s)"
fi

# =====================================================================
#  Buscar SBOMs
# =====================================================================
info "Buscando SBOMs en: ${SBOM_DIR}/"

# Listar archivos para diagnostico
if [ "$IS_WINDOWS" = true ]; then
    info "Contenido del directorio SBOM:"
    ls -la "$SBOM_DIR"/ 2>/dev/null | while IFS= read -r line; do
        info "  $line"
    done
fi

shopt -s nullglob
SBOM_FILES=("$SBOM_DIR"/*_sbom_cyclonedx.json)
shopt -u nullglob

if [ ${#SBOM_FILES[@]} -eq 0 ]; then
    fail "No se encontraron SBOMs en ${SBOM_DIR}/"
    info "Archivos existentes en data/sbom/:"
    ls -1 "$SBOM_DIR"/ 2>/dev/null | while IFS= read -r f; do
        info "  - $f"
    done
    info ""
    info "Ejecute primero:"
    if [ "$IS_WINDOWS" = true ]; then
        info "  PowerShell: .\\scripts\\generate_sbom.ps1"
        info "  Git Bash:   bash scripts/generate_sbom.sh"
    else
        info "  ./scripts/generate_sbom.sh"
    fi
    exit 1
fi
ok "SBOMs encontrados: ${#SBOM_FILES[@]} archivos"
log ""

# Actualizar DB de Grype
info "Actualizando base de datos de vulnerabilidades de Grype..."
if grype db update 2>&1 | tail -3; then
    ok "Base de datos actualizada"
else
    warn "Usando base de datos existente"
fi
log ""

# Limpiar resumen anterior
rm -f "${GRYPE_DIR}/grype_summary.jsonl"

TOTAL=${#SBOM_FILES[@]}
CURRENT=0
SCANNED_OK=0

for SBOM_FILE in "${SBOM_FILES[@]}"; do
    CURRENT=$((CURRENT + 1))
    BASENAME=$(basename "$SBOM_FILE" | sed 's/_sbom_cyclonedx\.json//')

    log "  ${B}------------------------------------------------------------${N}"
    log "  ${BOLD}[${CURRENT}/${TOTAL}] Escaneando: ${C}${BASENAME}${N}"
    log "  ${B}------------------------------------------------------------${N}"

    # =====================================================================
    #  CLAVE: Convertir la ruta del SBOM para Grype
    #  En Git Bash, Grype necesita: sbom:C:\Users\...\file.json
    #  En Linux/macOS:              sbom:/home/user/.../file.json
    # =====================================================================
    if [ "$IS_WINDOWS" = true ]; then
        SBOM_NATIVE=$(to_win_path "$SBOM_FILE")
        GRYPE_INPUT="sbom:${SBOM_NATIVE}"
        info "Ruta POSIX:   ${SBOM_FILE}"
        info "Ruta Windows: ${SBOM_NATIVE}"
    else
        GRYPE_INPUT="sbom:${SBOM_FILE}"
    fi
    info "Argumento Grype: ${GRYPE_INPUT}"

    # Verificar que el SBOM existe y tiene contenido
    if [ ! -f "$SBOM_FILE" ]; then
        fail "SBOM no encontrado: ${SBOM_FILE}"
        continue
    fi
    SBOM_SIZE=$(wc -c < "$SBOM_FILE" 2>/dev/null | tr -d ' ')
    if [ "${SBOM_SIZE:-0}" -lt 10 ]; then
        fail "SBOM vacio o corrupto: ${SBOM_FILE} (${SBOM_SIZE} bytes)"
        continue
    fi
    info "SBOM valido: ${SBOM_SIZE} bytes"

    # --- CycloneDX output (para DefectDojo) ---
    CYCLONEDX_OUT="${GRYPE_DIR}/${BASENAME}_grype_cyclonedx.json"
    info "Generando reporte CycloneDX..."

    # Capturar stderr para diagnostico
    GRYPE_ERR="${GRYPE_DIR}/${BASENAME}_grype_error.log"

    if grype "${GRYPE_INPUT}" -o cyclonedx-json > "$CYCLONEDX_OUT" 2>"$GRYPE_ERR"; then
        clean_bom "$CYCLONEDX_OUT"
        if [ -f "$CYCLONEDX_OUT" ] && [ -s "$CYCLONEDX_OUT" ]; then
            ok "CycloneDX: $(basename "$CYCLONEDX_OUT")"
            rm -f "$GRYPE_ERR" 2>/dev/null || true
        else
            fail "Archivo CycloneDX vacio para ${BASENAME}"
            if [ -f "$GRYPE_ERR" ] && [ -s "$GRYPE_ERR" ]; then
                warn "Error de Grype:"
                head -5 "$GRYPE_ERR" | while IFS= read -r line; do warn "  $line"; done
            fi
        fi
    else
        fail "Error ejecutando Grype para ${BASENAME}"
        if [ -f "$GRYPE_ERR" ] && [ -s "$GRYPE_ERR" ]; then
            warn "Detalle del error:"
            head -10 "$GRYPE_ERR" | while IFS= read -r line; do warn "  $line"; done
        fi
        # Intentar sin el prefijo sbom: como fallback
        info "Intentando sin prefijo sbom:..."
        if [ "$IS_WINDOWS" = true ]; then
            FALLBACK_INPUT="${SBOM_NATIVE}"
        else
            FALLBACK_INPUT="${SBOM_FILE}"
        fi
        if grype "${FALLBACK_INPUT}" -o cyclonedx-json > "$CYCLONEDX_OUT" 2>"$GRYPE_ERR"; then
            clean_bom "$CYCLONEDX_OUT"
            ok "CycloneDX (fallback): $(basename "$CYCLONEDX_OUT")"
        else
            fail "Fallback tambien fallo para ${BASENAME}"
            if [ -f "$GRYPE_ERR" ] && [ -s "$GRYPE_ERR" ]; then
                head -5 "$GRYPE_ERR" | while IFS= read -r line; do warn "  $line"; done
            fi
            continue
        fi
    fi

    # --- JSON detallado ---
    JSON_OUT="${GRYPE_DIR}/${BASENAME}_grype_detail.json"
    grype "${GRYPE_INPUT}" -o json > "$JSON_OUT" 2>/dev/null || \
        grype "${FALLBACK_INPUT:-$SBOM_FILE}" -o json > "$JSON_OUT" 2>/dev/null || true
    clean_bom "$JSON_OUT"

    # --- Contar vulnerabilidades ---
    CRIT=0; HIGH=0; MED=0; LOW=0; NEG=0; TOT=0
    if [ -f "$JSON_OUT" ] && [ -s "$JSON_OUT" ]; then
        PY_COUNT="${GRYPE_DIR}/_count_tmp.py"
        cat > "$PY_COUNT" << 'PYSCRIPT'
import json, sys
fpath = sys.argv[1]
try:
    with open(fpath, 'rb') as f:
        raw = f.read()
    if raw[:3] == b'\xef\xbb\xbf': raw = raw[3:]
    data = json.loads(raw.decode('utf-8', errors='ignore'))
    matches = data.get('matches', [])
    counts = {'Critical':0, 'High':0, 'Medium':0, 'Low':0, 'Negligible':0}
    for m in matches:
        sev = m.get('vulnerability',{}).get('severity','Unknown')
        if sev in counts: counts[sev] += 1
    total = sum(counts.values())
    print(f"{counts['Critical']} {counts['High']} {counts['Medium']} {counts['Low']} {counts['Negligible']} {total}")
except Exception as e:
    print('0 0 0 0 0 0')
    print(f'ERROR: {e}', file=sys.stderr)
PYSCRIPT

        COUNTS=$("$PYTHON_CMD" "$PY_COUNT" "$JSON_OUT" 2>/dev/null || echo "0 0 0 0 0 0")
        rm -f "$PY_COUNT" 2>/dev/null || true

        read -r CRIT HIGH MED LOW NEG TOT <<< "$COUNTS"
        CRIT=${CRIT:-0}; HIGH=${HIGH:-0}; MED=${MED:-0}; LOW=${LOW:-0}; NEG=${NEG:-0}; TOT=${TOT:-0}

        log "  ${R}CRITICAL: ${CRIT}${N} | ${Y}HIGH: ${HIGH}${N} | ${B}MEDIUM: ${MED}${N} | ${G}LOW: ${LOW}${N} | NEG: ${NEG} | TOTAL: ${TOT}"
        SCANNED_OK=$((SCANNED_OK + 1))
    fi

    # --- Tabla resumen ---
    TABLE_OUT="${GRYPE_DIR}/${BASENAME}_grype_table.txt"
    grype "${GRYPE_INPUT}" -o table > "$TABLE_OUT" 2>/dev/null || \
        grype "${FALLBACK_INPUT:-$SBOM_FILE}" -o table > "$TABLE_OUT" 2>/dev/null || true
    ok "Tabla: $(basename "$TABLE_OUT")"

    # Guardar linea de resumen
    printf '{"service":"%s","critical":%d,"high":%d,"medium":%d,"low":%d,"negligible":%d,"total":%d}\n' \
        "$BASENAME" "$CRIT" "$HIGH" "$MED" "$LOW" "$NEG" "$TOT" \
        >> "${GRYPE_DIR}/grype_summary.jsonl"

    # Limpiar log de error si todo salio bien
    rm -f "$GRYPE_ERR" 2>/dev/null || true

    log ""
done

# =====================================================================
#  Resumen consolidado
# =====================================================================
log "${BOLD}${C}+============================================================+${N}"
log "${BOLD}${C}|           RESUMEN DE VULNERABILIDADES (GRYPE)              |${N}"
log "${BOLD}${C}+============================================================+${N}"
log ""

PY_GRYPE_SUMMARY="${GRYPE_DIR}/_grype_summary_tmp.py"
cat > "$PY_GRYPE_SUMMARY" << 'PYSCRIPT'
import json, os, sys

grype_dir = sys.argv[1] if len(sys.argv) > 1 else './data/grype'
summary_file = os.path.join(grype_dir, 'grype_summary.jsonl')

if not os.path.exists(summary_file):
    print("  No se encontraron resultados.")
    sys.exit(0)

services = []
with open(summary_file, 'rb') as f:
    raw = f.read()
if raw[:3] == b'\xef\xbb\xbf': raw = raw[3:]
text = raw.decode('utf-8', errors='ignore')

for line in text.splitlines():
    line = line.strip()
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
PYSCRIPT

"$PYTHON_CMD" "$PY_GRYPE_SUMMARY" "$GRYPE_DIR"
rm -f "$PY_GRYPE_SUMMARY" 2>/dev/null || true

log ""
ok "Escaneo con Grype completado (${SCANNED_OK}/${TOTAL} exitosos)"
info "Reportes en: ${GRYPE_DIR}/"
log ""
info "Proximo paso:"
if [ "$IS_WINDOWS" = true ]; then
    log "    Subir a plataformas: ${C}${PYTHON_CMD} scripts/upload_reports.py${N}"
else
    log "    Subir a plataformas: ${C}${PYTHON_CMD} scripts/upload_reports.py${N}"
fi
log ""
