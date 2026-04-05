#!/usr/bin/env python3
"""
VulnCorp Lab 02 — Upload de Reportes a Plataformas de Gestión
Curso MAR303 — Universidad Mayor — 2026

Este script automatiza la subida de:
  1. SBOMs (CycloneDX JSON) → Dependency-Track (vía API v1)
  2. Reportes de Grype (CycloneDX JSON) → DefectDojo (vía API v2)

Requisitos:
  - Python 3.8+
  - módulo 'requests' (pip3 install requests)
  - Dependency-Track corriendo en http://localhost:8084
  - DefectDojo corriendo en http://localhost:8085
"""

import json
import os
import sys
import time
import base64
import glob
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("[✗] Módulo 'requests' no encontrado. Instale con: pip3 install requests")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LAB02_DIR = os.path.dirname(SCRIPT_DIR)
SBOM_DIR = os.path.join(LAB02_DIR, "data", "sbom")
GRYPE_DIR = os.path.join(LAB02_DIR, "data", "grype")

# Dependency-Track
DTRACK_URL = os.environ.get("DTRACK_URL", "http://localhost:8084")
DTRACK_API_KEY = os.environ.get("DTRACK_API_KEY", "")

# DefectDojo
DOJO_URL = os.environ.get("DOJO_URL", "http://localhost:8085")
DOJO_USER = os.environ.get("DOJO_USER", "admin")
DOJO_PASSWORD = os.environ.get("DOJO_PASSWORD", "")
DOJO_TOKEN = os.environ.get("DOJO_TOKEN", "")

# Mapeo de servicios a metadatos
SERVICES = {
    "nginx-proxy":   {"name": "VulnCorp Nginx Proxy",   "version": "1.21.0",    "group": "produccion"},
    "prestashop":    {"name": "VulnCorp PetaShop",       "version": "1.7.8.0",   "group": "produccion"},
    "mariadb-prod":  {"name": "VulnCorp MariaDB",        "version": "10.5.18",   "group": "produccion"},
    "redis-cache":   {"name": "VulnCorp Redis Cache",    "version": "6.2.6",     "group": "produccion"},
    "phpmyadmin":    {"name": "VulnCorp phpMyAdmin",      "version": "5.1.1",     "group": "corporativa"},
    "workstation":   {"name": "VulnCorp Workstation",     "version": "20.04",     "group": "corporativa"},
    "ftp-server":    {"name": "VulnCorp FTP Server",      "version": "latest",    "group": "corporativa"},
}

# Colores
class C:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'


def banner():
    print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════╗
║  VulnCorp Lab 02 — Upload de Reportes a Plataformas       ║
║  Dependency-Track + DefectDojo                             ║
╚══════════════════════════════════════════════════════════════╝{C.NC}
""")


# ═══════════════════════════════════════════════════════════════════════════
#  DEPENDENCY-TRACK
# ═══════════════════════════════════════════════════════════════════════════

def dtrack_get_api_key():
    """
    Obtiene un API key de Dependency-Track.
    En la primera ejecución, usa las credenciales default (admin/admin)
    para extraer el API key del equipo 'Administrators'.
    """
    global DTRACK_API_KEY

    if DTRACK_API_KEY:
        return DTRACK_API_KEY

    print(f"  {C.YELLOW}[i] Obteniendo API key de Dependency-Track...{C.NC}")

    # Login con credenciales default para obtener JWT
    try:
        resp = requests.post(
            f"{DTRACK_URL}/api/v1/user/login",
            data="username=admin&password=admin",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        if resp.status_code != 200:
            print(f"  {C.RED}[✗] Login fallido (HTTP {resp.status_code}). ¿Cambió la contraseña?{C.NC}")
            print(f"      Si cambió la contraseña, establezca DTRACK_API_KEY manualmente.")
            return None
        jwt_token = resp.text.strip()
    except requests.exceptions.ConnectionError:
        print(f"  {C.RED}[✗] No se puede conectar a Dependency-Track en {DTRACK_URL}{C.NC}")
        print(f"      Verifique que esté corriendo: docker compose ps")
        return None

    # Obtener API keys del equipo Administrators
    headers = {"Authorization": f"Bearer {jwt_token}"}
    resp = requests.get(f"{DTRACK_URL}/api/v1/team", headers=headers, timeout=10)
    if resp.status_code == 200:
        teams = resp.json()
        for team in teams:
            if team.get("name") == "Administrators":
                api_keys = team.get("apiKeys", [])
                if api_keys:
                    DTRACK_API_KEY = api_keys[0].get("key", "")
                    print(f"  {C.GREEN}[✓] API key obtenido de Dependency-Track{C.NC}")
                    return DTRACK_API_KEY

    print(f"  {C.YELLOW}[!] No se encontró API key. Créelo manualmente en la UI.{C.NC}")
    return None


def dtrack_upload_sbom(service_key, sbom_file):
    """
    Sube un SBOM CycloneDX a Dependency-Track.
    Crea el proyecto automáticamente si no existe.
    """
    api_key = dtrack_get_api_key()
    if not api_key:
        return False

    meta = SERVICES.get(service_key, {"name": service_key, "version": "unknown", "group": "unknown"})

    # Leer y codificar el SBOM en base64
    with open(sbom_file, 'r') as f:
        sbom_content = f.read()
    sbom_b64 = base64.b64encode(sbom_content.encode()).decode()

    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }

    payload = {
        "projectName": meta["name"],
        "projectVersion": meta["version"],
        "autoCreate": True,
        "bom": sbom_b64
    }

    try:
        resp = requests.put(
            f"{DTRACK_URL}/api/v1/bom",
            json=payload,
            headers=headers,
            timeout=30
        )
        if resp.status_code in (200, 201):
            token = resp.json().get("token", "N/A")
            print(f"  {C.GREEN}[✓] SBOM subido: {meta['name']} v{meta['version']} (token: {token[:12]}...){C.NC}")
            return True
        else:
            print(f"  {C.RED}[✗] Error subiendo SBOM (HTTP {resp.status_code}): {resp.text[:200]}{C.NC}")
            return False
    except Exception as e:
        print(f"  {C.RED}[✗] Error de conexión: {e}{C.NC}")
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  DEFECTDOJO
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_dojo_password():
    """
    Resuelve la contraseña de DefectDojo en este orden:
    1. Variable de entorno DOJO_PASSWORD
    2. Archivo data/.dd_admin_password (generado por setup_lab02.sh)
    3. Logs del contenedor initializer
    4. Solicitar al usuario
    """
    global DOJO_PASSWORD

    if DOJO_PASSWORD:
        return DOJO_PASSWORD

    # Intentar leer del archivo generado por setup
    pw_file = os.path.join(LAB02_DIR, "data", ".dd_admin_password")
    if os.path.exists(pw_file):
        with open(pw_file, "r") as f:
            pw = f.read().strip()
            if pw:
                DOJO_PASSWORD = pw
                print(f"  {C.CYAN}[i] Contraseña leída de data/.dd_admin_password{C.NC}")
                return DOJO_PASSWORD

    # Intentar obtener de los logs del initializer
    try:
        import subprocess
        result = subprocess.run(
            ["docker", "logs", "vulncorp-dd-initializer"],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout + result.stderr
        for line in logs.splitlines():
            if "password" in line.lower() and "admin" in line.lower():
                # Extraer la contraseña del log
                parts = line.split(":")
                if len(parts) >= 2:
                    pw = parts[-1].strip()
                    if pw:
                        DOJO_PASSWORD = pw
                        print(f"  {C.CYAN}[i] Contraseña obtenida de los logs del initializer{C.NC}")
                        return DOJO_PASSWORD
    except Exception:
        pass

    # Solicitar al usuario
    print(f"  {C.YELLOW}[!] No se encontró la contraseña de DefectDojo automáticamente.{C.NC}")
    print(f"      Puede obtenerla ejecutando:")
    print(f"      {C.CYAN}docker logs vulncorp-dd-initializer 2>&1 | grep -i password{C.NC}")
    DOJO_PASSWORD = input(f"  Ingrese la contraseña de admin de DefectDojo: ").strip()
    return DOJO_PASSWORD


def dojo_get_token():
    """Obtiene un token de autenticación de DefectDojo."""
    global DOJO_TOKEN

    if DOJO_TOKEN:
        return DOJO_TOKEN

    print(f"  {C.YELLOW}[i] Obteniendo token de DefectDojo...{C.NC}")

    password = _resolve_dojo_password()
    if not password:
        print(f"  {C.RED}[✗] No se proporcionó contraseña de DefectDojo{C.NC}")
        return None

    try:
        resp = requests.post(
            f"{DOJO_URL}/api/v2/api-token-auth/",
            json={"username": DOJO_USER, "password": password},
            timeout=10
        )
        if resp.status_code == 200:
            DOJO_TOKEN = resp.json().get("token", "")
            print(f"  {C.GREEN}[✓] Token obtenido de DefectDojo{C.NC}")
            return DOJO_TOKEN
        else:
            print(f"  {C.RED}[✗] Login fallido en DefectDojo (HTTP {resp.status_code}){C.NC}")
            print(f"      Verifique la contraseña. Puede obtenerla con:")
            print(f"      {C.CYAN}docker logs vulncorp-dd-initializer 2>&1 | grep -i password{C.NC}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"  {C.RED}[✗] No se puede conectar a DefectDojo en {DOJO_URL}{C.NC}")
        print(f"      Verifique que esté corriendo: docker compose ps")
        return None


def dojo_get_or_create_product(product_name, description=""):
    """Obtiene o crea un producto en DefectDojo."""
    token = dojo_get_token()
    if not token:
        return None

    headers = {"Authorization": f"Token {token}"}

    # Buscar producto existente
    resp = requests.get(
        f"{DOJO_URL}/api/v2/products/",
        params={"name": product_name},
        headers=headers,
        timeout=10
    )
    if resp.status_code == 200:
        results = resp.json().get("results", [])
        if results:
            return results[0]["id"]

    # Crear producto
    # Primero obtener un product_type
    resp_pt = requests.get(f"{DOJO_URL}/api/v2/product_types/", headers=headers, timeout=10)
    pt_id = 1
    if resp_pt.status_code == 200:
        pts = resp_pt.json().get("results", [])
        if pts:
            pt_id = pts[0]["id"]

    resp = requests.post(
        f"{DOJO_URL}/api/v2/products/",
        json={
            "name": product_name,
            "description": description or f"VulnCorp Lab - {product_name}",
            "prod_type": pt_id
        },
        headers=headers,
        timeout=10
    )
    if resp.status_code == 201:
        return resp.json()["id"]
    else:
        print(f"  {C.RED}[✗] Error creando producto (HTTP {resp.status_code}): {resp.text[:200]}{C.NC}")
        return None


def dojo_get_or_create_engagement(product_id, engagement_name):
    """Obtiene o crea un engagement en DefectDojo."""
    token = dojo_get_token()
    headers = {"Authorization": f"Token {token}"}

    # Buscar engagement existente
    resp = requests.get(
        f"{DOJO_URL}/api/v2/engagements/",
        params={"product": product_id, "name": engagement_name},
        headers=headers,
        timeout=10
    )
    if resp.status_code == 200:
        results = resp.json().get("results", [])
        if results:
            return results[0]["id"]

    # Crear engagement
    today = datetime.now().strftime("%Y-%m-%d")
    resp = requests.post(
        f"{DOJO_URL}/api/v2/engagements/",
        json={
            "name": engagement_name,
            "product": product_id,
            "target_start": today,
            "target_end": today,
            "engagement_type": "CI/CD",
            "status": "In Progress"
        },
        headers=headers,
        timeout=10
    )
    if resp.status_code == 201:
        return resp.json()["id"]
    else:
        print(f"  {C.RED}[✗] Error creando engagement (HTTP {resp.status_code}): {resp.text[:200]}{C.NC}")
        return None


def dojo_upload_scan(service_key, scan_file):
    """
    Sube un reporte de Grype (CycloneDX) a DefectDojo.
    Crea el producto y engagement si no existen.
    """
    token = dojo_get_token()
    if not token:
        return False

    meta = SERVICES.get(service_key, {"name": service_key, "version": "unknown", "group": "unknown"})

    # Crear o obtener producto
    product_id = dojo_get_or_create_product(
        f"VulnCorp - {meta['name']}",
        f"Servicio {service_key} de la infraestructura VulnCorp PetaShop. Zona: {meta['group']}"
    )
    if not product_id:
        return False

    # Crear o obtener engagement
    engagement_id = dojo_get_or_create_engagement(
        product_id,
        f"Escaneo Grype - Lab 02 - {datetime.now().strftime('%Y-%m-%d')}"
    )
    if not engagement_id:
        return False

    # Subir el scan
    headers = {"Authorization": f"Token {token}"}

    with open(scan_file, 'rb') as f:
        resp = requests.post(
            f"{DOJO_URL}/api/v2/import-scan/",
            headers=headers,
            data={
                "engagement": engagement_id,
                "scan_type": "CycloneDX Scan",
                "active": "true",
                "verified": "false",
                "minimum_severity": "Info",
                "close_old_findings": "false",
                "scan_date": datetime.now().strftime("%Y-%m-%d"),
            },
            files={"file": (os.path.basename(scan_file), f, "application/json")},
            timeout=60
        )

    if resp.status_code in (200, 201):
        test_id = resp.json().get("test", "N/A")
        findings_count = resp.json().get("findings_count", "N/A") if isinstance(resp.json(), dict) else "N/A"
        print(f"  {C.GREEN}[✓] Scan importado en DefectDojo: {meta['name']} (test_id: {test_id}){C.NC}")
        return True
    else:
        print(f"  {C.RED}[✗] Error importando scan (HTTP {resp.status_code}): {resp.text[:300]}{C.NC}")
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    global DTRACK_URL, DOJO_URL

    parser = argparse.ArgumentParser(description="Upload SBOMs y scans a Dependency-Track y DefectDojo")
    parser.add_argument("--dtrack-only", action="store_true", help="Solo subir a Dependency-Track")
    parser.add_argument("--dojo-only", action="store_true", help="Solo subir a DefectDojo")
    parser.add_argument("--dtrack-url", default=DTRACK_URL, help="URL de Dependency-Track API")
    parser.add_argument("--dojo-url", default=DOJO_URL, help="URL de DefectDojo")
    args = parser.parse_args()

    DTRACK_URL = args.dtrack_url
    DOJO_URL = args.dojo_url

    banner()

    upload_dtrack = not args.dojo_only
    upload_dojo = not args.dtrack_only

    # ─── DEPENDENCY-TRACK ───
    if upload_dtrack:
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print(f"{C.BOLD}  FASE 1: Subida de SBOMs a Dependency-Track{C.NC}")
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print()

        sbom_files = sorted(glob.glob(os.path.join(SBOM_DIR, "*_sbom_cyclonedx.json")))
        if not sbom_files:
            print(f"  {C.RED}[✗] No se encontraron SBOMs en {SBOM_DIR}/{C.NC}")
            print(f"      Ejecute primero: ./scripts/generate_sbom.sh")
        else:
            success = 0
            for sbom_file in sbom_files:
                service_key = os.path.basename(sbom_file).replace("_sbom_cyclonedx.json", "")
                if dtrack_upload_sbom(service_key, sbom_file):
                    success += 1
            print()
            print(f"  {C.BOLD}Resultado: {success}/{len(sbom_files)} SBOMs subidos a Dependency-Track{C.NC}")
            print(f"  {C.CYAN}Abrir: {DTRACK_URL.replace(':8084',':8083')}{C.NC}")
        print()

    # ─── DEFECTDOJO ───
    if upload_dojo:
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print(f"{C.BOLD}  FASE 2: Subida de Scans a DefectDojo{C.NC}")
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print()

        grype_files = sorted(glob.glob(os.path.join(GRYPE_DIR, "*_grype_cyclonedx.json")))
        if not grype_files:
            print(f"  {C.RED}[✗] No se encontraron reportes Grype en {GRYPE_DIR}/{C.NC}")
            print(f"      Ejecute primero: ./scripts/scan_grype.sh")
        else:
            success = 0
            for grype_file in grype_files:
                service_key = os.path.basename(grype_file).replace("_grype_cyclonedx.json", "")
                if dojo_upload_scan(service_key, grype_file):
                    success += 1
            print()
            print(f"  {C.BOLD}Resultado: {success}/{len(grype_files)} scans importados en DefectDojo{C.NC}")
            print(f"  {C.CYAN}Abrir: {DOJO_URL}{C.NC}")
        print()

    # ─── RESUMEN FINAL ───
    print(f"{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════╗{C.NC}")
    print(f"{C.BOLD}{C.CYAN}║  Upload completado                                         ║{C.NC}")
    print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════════════╝{C.NC}")
    print()
    print(f"  {C.BOLD}Plataformas:{C.NC}")
    if upload_dtrack:
        print(f"    Dependency-Track: {C.CYAN}http://localhost:8083{C.NC}  (admin/admin)")
    if upload_dojo:
        print(f"    DefectDojo:       {C.CYAN}http://localhost:8085{C.NC}  (admin/VulnCorp2024!)")
    print()


if __name__ == "__main__":
    main()
