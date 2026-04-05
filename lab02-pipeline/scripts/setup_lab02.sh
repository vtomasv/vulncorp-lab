#!/bin/bash
###############################################################################
#  VulnCorp Lab 02 — Setup del Pipeline de Gestión de Vulnerabilidades
#  Curso MAR303 — Universidad Mayor — 2026
#
#  Este script instala las herramientas CLI necesarias:
#    1. Syft  — Generador de SBOM (Software Bill of Materials)
#    2. Grype — Escáner de vulnerabilidades basado en SBOM
#
#  Y levanta las plataformas de gestión:
#    3. Dependency-Track — Análisis continuo de SBOM
#    4. DefectDojo        — Gestión centralizada de vulnerabilidades
#
#  Compatible con: AMD64 (Intel/AMD) y ARM64 (Apple Silicon M1/M2/M3/M4)
###############################################################################

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB02_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║  VulnCorp Lab 02 — Pipeline de Gestión de Vulnerabilidades  ║${NC}"
echo -e "${BOLD}${CYAN}║  Setup Inicial                                              ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Detectar arquitectura y SO
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
echo -e "  [i] Arquitectura: ${BOLD}${ARCH}${NC} | SO: ${BOLD}${OS}${NC}"
echo ""

# ===================== 1. INSTALAR SYFT =====================
echo -e "${YELLOW}[1/4] Instalando Syft (generador de SBOM)...${NC}"

if command -v syft &> /dev/null; then
    SYFT_VER=$(syft version 2>/dev/null | head -3)
    echo -e "${GREEN}  [✓] Syft ya instalado${NC}"
    echo -e "      ${SYFT_VER}"
else
    echo -e "  Descargando Syft..."
    if [ "$OS" = "darwin" ] && command -v brew &> /dev/null; then
        brew install syft
    else
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    if command -v syft &> /dev/null; then
        echo -e "${GREEN}  [✓] Syft instalado correctamente${NC}"
    else
        echo -e "${RED}  [✗] Error instalando Syft${NC}"
        echo -e "${YELLOW}      Instale manualmente: https://github.com/anchore/syft#installation${NC}"
    fi
fi

# ===================== 2. INSTALAR GRYPE =====================
echo ""
echo -e "${YELLOW}[2/4] Instalando Grype (escáner de vulnerabilidades)...${NC}"

if command -v grype &> /dev/null; then
    GRYPE_VER=$(grype version 2>/dev/null | head -3)
    echo -e "${GREEN}  [✓] Grype ya instalado${NC}"
    echo -e "      ${GRYPE_VER}"
else
    echo -e "  Descargando Grype..."
    if [ "$OS" = "darwin" ] && command -v brew &> /dev/null; then
        brew install grype
    else
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
    fi

    if command -v grype &> /dev/null; then
        echo -e "${GREEN}  [✓] Grype instalado correctamente${NC}"
    else
        echo -e "${RED}  [✗] Error instalando Grype${NC}"
        echo -e "${YELLOW}      Instale manualmente: https://github.com/anchore/grype#installation${NC}"
    fi
fi

# ===================== 3. VERIFICAR PYTHON =====================
echo ""
echo -e "${YELLOW}[3/4] Verificando Python y dependencias...${NC}"

if command -v python3 &> /dev/null; then
    PY_VER=$(python3 --version 2>/dev/null)
    echo -e "${GREEN}  [✓] Python: ${PY_VER}${NC}"
else
    echo -e "${RED}  [✗] Python 3 no encontrado. Es necesario para los scripts de integración.${NC}"
    echo -e "${YELLOW}      Instale Python 3.8+ desde https://www.python.org/downloads/${NC}"
fi

# Instalar requests si no está disponible
python3 -c "import requests" 2>/dev/null || {
    echo -e "  Instalando módulo 'requests' para Python..."
    pip3 install requests --quiet 2>/dev/null || pip install requests --quiet 2>/dev/null || {
        echo -e "${YELLOW}  [!] No se pudo instalar 'requests'. Instale manualmente: pip3 install requests${NC}"
    }
}
echo -e "${GREEN}  [✓] Dependencias Python listas${NC}"

# ===================== 4. LEVANTAR PLATAFORMAS =====================
echo ""
echo -e "${YELLOW}[4/4] Levantando plataformas de gestión (Dependency-Track + DefectDojo)...${NC}"
echo -e "${YELLOW}      Esto puede tomar 3-5 minutos en la primera ejecución...${NC}"
echo ""

cd "$LAB02_DIR"
docker compose up -d 2>&1

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  [✓] Setup del Lab 02 completado                            ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Herramientas CLI instaladas:${NC}"
echo -e "    Syft:  $(command -v syft 2>/dev/null || echo 'no instalado')"
echo -e "    Grype: $(command -v grype 2>/dev/null || echo 'no instalado')"
echo ""
echo -e "  ${BOLD}Plataformas de gestión:${NC}"
echo -e "    Dependency-Track: ${CYAN}http://localhost:8083${NC}"
echo -e "      Credenciales:   admin / admin"
echo -e "      (Cambiar en el primer login)"
echo -e ""
echo -e "    DefectDojo:       ${CYAN}http://localhost:8085${NC}"
echo -e "      Credenciales:   admin / VulnCorp2024!"
echo ""
echo -e "  ${BOLD}Próximos pasos:${NC}"
echo -e "    ${CYAN}1.${NC} Espere ~3-5 min a que las plataformas inicialicen"
echo -e "    ${CYAN}2.${NC} Genere los SBOMs:       ${BOLD}./scripts/generate_sbom.sh${NC}"
echo -e "    ${CYAN}3.${NC} Escanee con Grype:      ${BOLD}./scripts/scan_grype.sh${NC}"
echo -e "    ${CYAN}4.${NC} Suba a las plataformas: ${BOLD}python3 scripts/upload_reports.py${NC}"
echo ""
