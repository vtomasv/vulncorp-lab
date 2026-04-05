#!/bin/bash
###############################################################################
#  VulnCorp Lab — Script de Setup Inicial
#  Curso MAR303 — Universidad Mayor — 2026
#
#  Ejecutar UNA VEZ antes de iniciar el laboratorio.
#  Instala Trivy y descarga las imágenes Docker necesarias.
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║       VulnCorp Lab — Setup Inicial                          ║${NC}"
echo -e "${BOLD}${CYAN}║       Gestión de Vulnerabilidades (MITRE) — 2026            ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Verificar Docker y Docker Compose
echo -e "${YELLOW}[1/4] Verificando requisitos del sistema...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}[✗] Docker no está instalado. Instálelo desde https://docs.docker.com/get-docker/${NC}"
    exit 1
fi
echo -e "${GREEN}  [✓] Docker: $(docker --version)${NC}"

if ! docker compose version &> /dev/null 2>&1; then
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}[✗] Docker Compose no está instalado.${NC}"
        exit 1
    fi
    echo -e "${GREEN}  [✓] Docker Compose: $(docker-compose --version)${NC}"
    COMPOSE_CMD="docker-compose"
else
    echo -e "${GREEN}  [✓] Docker Compose: $(docker compose version)${NC}"
    COMPOSE_CMD="docker compose"
fi

# 2. Instalar Trivy
echo ""
echo -e "${YELLOW}[2/4] Instalando Trivy (escáner de vulnerabilidades)...${NC}"

if ! command -v trivy &> /dev/null; then
    echo -e "  Descargando e instalando Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
    echo -e "${GREEN}  [✓] Trivy instalado: $(trivy --version 2>/dev/null | head -1)${NC}"
else
    echo -e "${GREEN}  [✓] Trivy ya instalado: $(trivy --version 2>/dev/null | head -1)${NC}"
fi

# 3. Descargar imágenes Docker
echo ""
echo -e "${YELLOW}[3/4] Descargando imágenes Docker (esto puede tomar varios minutos)...${NC}"

IMAGES=(
    "nginx:1.21.0"
    "prestashop/prestashop:1.7.8.0"
    "mysql:5.7.36"
    "redis:6.2.6"
    "phpmyadmin:5.1.1"
    "ubuntu:20.04"
    "fauria/vsftpd"
)

for img in "${IMAGES[@]}"; do
    echo -e "  Descargando ${CYAN}${img}${NC}..."
    docker pull "$img" --quiet 2>/dev/null || docker pull "$img"
    echo -e "${GREEN}  [✓] ${img}${NC}"
done

# 4. Construir el dashboard
echo ""
echo -e "${YELLOW}[4/4] Construyendo el dashboard de vulnerabilidades...${NC}"

cd "$(dirname "$0")/.."
$COMPOSE_CMD build vuln-dashboard 2>/dev/null || {
    echo -e "${YELLOW}  [!] El dashboard se construirá al iniciar el laboratorio${NC}"
}

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  [✓] Setup completado exitosamente                         ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Próximos pasos:"
echo -e "  ${CYAN}1.${NC} Iniciar el laboratorio:  ${BOLD}docker compose up -d${NC}"
echo -e "  ${CYAN}2.${NC} Esperar ~2 min a que PrestaShop se instale"
echo -e "  ${CYAN}3.${NC} Ejecutar el escaneo:     ${BOLD}./scripts/scan.sh${NC}"
echo -e "  ${CYAN}4.${NC} Abrir el dashboard:      ${BOLD}http://localhost:3000${NC}"
echo -e "  ${CYAN}5.${NC} Abrir PetaShop:          ${BOLD}http://localhost:8080${NC}"
echo -e "  ${CYAN}6.${NC} Abrir phpMyAdmin:         ${BOLD}http://localhost:8081${NC}"
echo ""
