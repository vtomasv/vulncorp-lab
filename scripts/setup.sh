#!/usr/bin/env bash
###############################################################################
#  VulnCorp Lab -- Script de Setup Inicial
#  Curso: Gestion de Vulnerabilidades con Enfoque MITRE -- 2026
#
#  Ejecutar UNA VEZ antes de iniciar el laboratorio.
#  Instala Trivy y descarga las imagenes Docker necesarias.
#
#  Compatible con: Linux, macOS, Windows (Git Bash MINGW64 / WSL2)
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
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

log ""
log "${BOLD}${C}+==============================================================+${N}"
log "${BOLD}${C}|       VulnCorp Lab -- Setup Inicial                          |${N}"
log "${BOLD}${C}|       Gestion de Vulnerabilidades (MITRE) -- 2026            |${N}"
log "${BOLD}${C}+==============================================================+${N}"
log ""

# 1. Verificar Docker y Docker Compose
log "${Y}[1/4] Verificando requisitos del sistema...${N}"

ARCH=$(uname -m)
info "Arquitectura detectada: ${BOLD}${ARCH}${N}"
info "Plataforma: ${BOLD}${PLATFORM}${N}"

if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    info "Sistema ARM64 (Apple Silicon / ARM). Imagenes compatibles seleccionadas."
elif [ "$ARCH" = "x86_64" ]; then
    info "Sistema AMD64 (Intel/AMD). Todas las imagenes son compatibles."
fi

if ! command -v docker >/dev/null 2>&1; then
    fail "Docker no esta instalado. Instalelo desde https://docs.docker.com/get-docker/"
    exit 1
fi
ok "Docker: $(docker --version)"

COMPOSE_CMD="docker compose"
if ! docker compose version >/dev/null 2>&1; then
    if command -v docker-compose >/dev/null 2>&1; then
        ok "Docker Compose: $(docker-compose --version)"
        COMPOSE_CMD="docker-compose"
    else
        fail "Docker Compose no esta instalado."
        exit 1
    fi
else
    ok "Docker Compose: $(docker compose version)"
fi

# 2. Instalar Trivy
log ""
log "${Y}[2/4] Instalando Trivy (escaner de vulnerabilidades)...${N}"

if ! command -v trivy >/dev/null 2>&1; then
    info "Descargando e instalando Trivy..."
    if [ "$IS_MACOS" = true ] && command -v brew >/dev/null 2>&1; then
        brew install trivy
    elif [ "$IS_WINDOWS" = true ]; then
        # En Git Bash, no hay sudo ni apt. Indicar al usuario.
        fail "Trivy no encontrado. En Windows, instale con:"
        log "    choco install trivy"
        log "    scoop install trivy"
        log "    winget install AquaSecurity.Trivy"
        exit 1
    else
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
    fi
    ok "Trivy instalado: $(trivy --version 2>/dev/null | head -1)"
else
    ok "Trivy ya instalado: $(trivy --version 2>/dev/null | head -1)"
fi

# 3. Descargar imagenes Docker (todas compatibles ARM64 + AMD64)
log ""
log "${Y}[3/4] Descargando imagenes Docker (esto puede tomar varios minutos)...${N}"

IMAGES=(
    "nginx:1.21.0"
    "prestashop/prestashop:1.7.8.0"
    "mariadb:10.5.18"
    "redis:6.2.6"
    "phpmyadmin:5.1.1"
    "ubuntu:20.04"
    "delfer/alpine-ftp-server"
    "node:18-alpine"
)

for img in "${IMAGES[@]}"; do
    info "Descargando ${C}${img}${N}..."
    if docker pull "$img" --quiet 2>/dev/null; then
        ok "${img}"
    elif docker pull "$img" 2>&1 | tail -1; then
        ok "${img}"
    else
        fail "Error descargando ${img}"
        if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
            warn "En Apple Silicon, intente: docker pull --platform linux/amd64 ${img}"
        fi
    fi
done

# 4. Construir el dashboard
log ""
log "${Y}[4/4] Construyendo el dashboard de vulnerabilidades...${N}"

cd "$PROJECT_DIR"
$COMPOSE_CMD build vuln-dashboard 2>/dev/null || {
    warn "El dashboard se construira al iniciar el laboratorio"
}

log ""
log "${G}${BOLD}+==============================================================+${N}"
log "${G}${BOLD}|  [OK] Setup completado exitosamente                          |${N}"
log "${G}${BOLD}+==============================================================+${N}"
log ""
log "  Proximos pasos:"
log "  ${C}1.${N} Iniciar el laboratorio:  ${BOLD}docker compose up -d${N}"
log "  ${C}2.${N} Esperar ~2 min a que PrestaShop se instale"

if [ "$IS_WINDOWS" = true ]; then
    log "  ${C}3.${N} Ejecutar el escaneo:     ${BOLD}.\\scripts\\scan.ps1${N}  (PowerShell recomendado)"
    log "       o bien:               ${BOLD}bash scripts/scan.sh${N}  (Git Bash)"
else
    log "  ${C}3.${N} Ejecutar el escaneo:     ${BOLD}./scripts/scan.sh${N}"
fi

log "  ${C}4.${N} Abrir el dashboard:      ${BOLD}http://localhost:3000${N}"
log "  ${C}5.${N} Abrir PetaShop:          ${BOLD}http://localhost:8080${N}"
log "  ${C}6.${N} Abrir phpMyAdmin:         ${BOLD}http://localhost:8081${N}"
log ""
