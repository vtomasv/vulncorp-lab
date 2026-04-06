#!/usr/bin/env bash
###############################################################################
#  VulnCorp Lab 02 -- Setup del Pipeline de Gestion de Vulnerabilidades
#  Curso: Gestion de Vulnerabilidades con Enfoque MITRE -- 2026
#
#  Este script instala las herramientas CLI necesarias:
#    1. Syft  -- Generador de SBOM (Software Bill of Materials)
#    2. Grype -- Escaner de vulnerabilidades basado en SBOM
#
#  Y levanta las plataformas de gestion:
#    3. Dependency-Track -- Analisis continuo de SBOM
#    4. DefectDojo        -- Gestion centralizada de vulnerabilidades
#
#  Compatible con:
#    - macOS ARM64 (Apple Silicon M1/M2/M3/M4)
#    - macOS AMD64 (Intel)
#    - Linux AMD64 / ARM64
#    - Windows (Git Bash MINGW64 / WSL2 + Docker Desktop)
###############################################################################

set -e

# --- Detectar plataforma ---
PLATFORM="linux"
IS_WINDOWS=false
IS_MACOS=false

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        PLATFORM="windows"
        IS_WINDOWS=true
        ;;
    Darwin*)
        PLATFORM="macos"
        IS_MACOS=true
        ;;
    Linux*)
        if [ -f /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
            PLATFORM="wsl2"
        fi
        ;;
esac

# --- Colores (compatibles con Git Bash) ---
R=''; G=''; Y=''; C=''; BOLD=''; N=''
if [ -t 1 ]; then
    if command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
        C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
    elif [ -n "${TERM:-}" ] && [ "${TERM:-}" != "dumb" ]; then
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
        C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
    fi
fi

log()  { printf "%b\n" "$*"; }
ok()   { log "  ${G}[OK]${N} $*"; }
warn() { log "  ${Y}[!]${N} $*"; }
fail() { log "  ${R}[X]${N} $*"; }
info() { log "  ${C}[i]${N} $*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB02_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

log ""
log "${BOLD}${C}+==============================================================+${N}"
log "${BOLD}${C}|  VulnCorp Lab 02 -- Pipeline de Gestion de Vulnerabilidades  |${N}"
log "${BOLD}${C}|  Setup Inicial                                               |${N}"
log "${BOLD}${C}+==============================================================+${N}"
log ""

# Detectar arquitectura y SO
ARCH=$(uname -m)
info "Arquitectura: ${BOLD}${ARCH}${N} | Plataforma: ${BOLD}${PLATFORM}${N}"
log ""

# ===================== 1. INSTALAR SYFT =====================
log "${Y}[1/4] Instalando Syft (generador de SBOM)...${N}"

if command -v syft >/dev/null 2>&1; then
    SYFT_VER=$(syft version 2>/dev/null | head -3)
    ok "Syft ya instalado"
    log "      ${SYFT_VER}"
else
    info "Descargando Syft..."
    if [ "$IS_MACOS" = true ] && command -v brew >/dev/null 2>&1; then
        brew install syft
    elif [ "$IS_WINDOWS" = true ]; then
        fail "Syft no encontrado. En Windows, instale con:"
        log "    choco install syft"
        log "    scoop install syft"
        log "  Luego vuelva a ejecutar este script."
        exit 1
    else
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    if command -v syft >/dev/null 2>&1; then
        ok "Syft instalado correctamente"
    else
        fail "Error instalando Syft"
        info "Instale manualmente: https://github.com/anchore/syft#installation"
    fi
fi

# ===================== 2. INSTALAR GRYPE =====================
log ""
log "${Y}[2/4] Instalando Grype (escaner de vulnerabilidades)...${N}"

if command -v grype >/dev/null 2>&1; then
    GRYPE_VER=$(grype version 2>/dev/null | head -3)
    ok "Grype ya instalado"
    log "      ${GRYPE_VER}"
else
    info "Descargando Grype..."
    if [ "$IS_MACOS" = true ] && command -v brew >/dev/null 2>&1; then
        brew install grype
    elif [ "$IS_WINDOWS" = true ]; then
        fail "Grype no encontrado. En Windows, instale con:"
        log "    choco install grype"
        log "    scoop install grype"
        log "  Luego vuelva a ejecutar este script."
        exit 1
    else
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    if command -v grype >/dev/null 2>&1; then
        ok "Grype instalado correctamente"
    else
        fail "Error instalando Grype"
        info "Instale manualmente: https://github.com/anchore/grype#installation"
    fi
fi

# ===================== 3. VERIFICAR PYTHON =====================
log ""
log "${Y}[3/4] Verificando Python y dependencias...${N}"

# Detectar Python (compatible Git Bash: python3 no existe en Windows)
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

if [ -n "$PYTHON_CMD" ]; then
    PY_VER=$("$PYTHON_CMD" --version 2>/dev/null)
    ok "Python: ${PY_VER}"
else
    fail "Python 3 no encontrado. Es necesario para los scripts de integracion."
    info "Instale Python 3.8+ desde https://www.python.org/downloads/"
fi

# Instalar requests si no esta disponible
if [ -n "$PYTHON_CMD" ]; then
    "$PYTHON_CMD" -c "import requests" 2>/dev/null || {
        info "Instalando modulo 'requests' para Python..."
        if [ "$IS_WINDOWS" = true ]; then
            "$PYTHON_CMD" -m pip install requests --quiet 2>/dev/null || {
                warn "No se pudo instalar 'requests'. Instale manualmente: pip install requests"
            }
        else
            pip3 install requests --quiet 2>/dev/null || pip install requests --quiet 2>/dev/null || {
                warn "No se pudo instalar 'requests'. Instale manualmente: pip3 install requests"
            }
        fi
    }
    ok "Dependencias Python listas"
fi

# ===================== 4. LEVANTAR PLATAFORMAS =====================
log ""
log "${Y}[4/4] Levantando plataformas de gestion (Dependency-Track + DefectDojo)...${N}"
info "Esto puede tomar 3-5 minutos en la primera ejecucion..."
log ""

cd "$LAB02_DIR"
docker compose up -d 2>&1

# ===================== ESPERAR Y CAPTURAR CONTRASENA DE DEFECTDOJO =====================
log ""
info "Esperando a que DefectDojo complete la inicializacion..."
info "(La contrasena del admin se genera automaticamente)"
log ""

DD_PASSWORD=""
MAX_WAIT=180
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    # Verificar si el initializer termino
    INIT_STATUS=$(docker inspect --format='{{.State.Status}}' vulncorp-dd-initializer 2>/dev/null || echo "not_found")

    if [ "$INIT_STATUS" = "exited" ]; then
        # Buscar la contrasena en los logs del initializer
        # Usar grep sin -P (PCRE no disponible en Git Bash)
        DD_PASSWORD=$(docker logs vulncorp-dd-initializer 2>&1 | grep -i "Admin password:" | sed 's/.*Admin password: *//' | tr -d '\r\n' || true)

        if [ -z "$DD_PASSWORD" ]; then
            # Intentar otro patron
            DD_PASSWORD=$(docker logs vulncorp-dd-initializer 2>&1 | grep -i "password" | tail -1 | sed 's/.*: *//' | tr -d '\r\n' || true)
        fi
        break
    fi

    sleep 5
    ELAPSED=$((ELAPSED + 5))
    printf "  Esperando... (%ds/%ds)\r" "$ELAPSED" "$MAX_WAIT"
done

log ""

# Guardar la contrasena en un archivo local
if [ -n "$DD_PASSWORD" ]; then
    echo "$DD_PASSWORD" > "$LAB02_DIR/data/.dd_admin_password"
    # chmod 600 no tiene efecto en Git Bash/Windows, pero no causa error
    chmod 600 "$LAB02_DIR/data/.dd_admin_password" 2>/dev/null || true
fi

log ""
log "${G}${BOLD}+==============================================================+${N}"
log "${G}${BOLD}|  [OK] Setup del Lab 02 completado                            |${N}"
log "${G}${BOLD}+==============================================================+${N}"
log ""
log "  ${BOLD}Herramientas CLI instaladas:${N}"
log "    Syft:  $(command -v syft 2>/dev/null || echo 'no instalado')"
log "    Grype: $(command -v grype 2>/dev/null || echo 'no instalado')"
log ""
log "  ${BOLD}Plataformas de gestion:${N}"
log "    Dependency-Track: ${C}http://localhost:8083${N}"
log "      Credenciales:   admin / admin"
log "      (Cambiar en el primer login)"
log ""
log "    DefectDojo:       ${C}http://localhost:8085${N}"
if [ -n "$DD_PASSWORD" ]; then
    log "      Credenciales:   admin / ${BOLD}${DD_PASSWORD}${N}"
    log "      ${Y}(Contrasena guardada en data/.dd_admin_password)${N}"
else
    log "      ${Y}Credenciales: La contrasena se genera automaticamente.${N}"
    log "      ${Y}Para obtenerla ejecute:${N}"
    log "      ${C}docker logs vulncorp-dd-initializer 2>&1 | grep -i password${N}"
fi
log ""
log "  ${BOLD}Proximos pasos:${N}"
log "    ${C}1.${N} Verifique que las plataformas esten listas: ${BOLD}docker compose ps${N}"

if [ "$IS_WINDOWS" = true ]; then
    log "    ${C}2.${N} Genere los SBOMs:       ${BOLD}.\\scripts\\generate_sbom.ps1${N}  (PowerShell)"
    log "       o bien:               ${BOLD}bash scripts/generate_sbom.sh${N}  (Git Bash)"
    log "    ${C}3.${N} Escanee con Grype:      ${BOLD}.\\scripts\\scan_grype.ps1${N}  (PowerShell)"
    log "    ${C}4.${N} Suba a las plataformas: ${BOLD}python scripts/upload_reports.py${N}"
else
    log "    ${C}2.${N} Genere los SBOMs:       ${BOLD}./scripts/generate_sbom.sh${N}"
    log "    ${C}3.${N} Escanee con Grype:      ${BOLD}./scripts/scan_grype.sh${N}"
    log "    ${C}4.${N} Suba a las plataformas: ${BOLD}python3 scripts/upload_reports.py${N}"
fi
log ""
