#!/usr/bin/env python3
"""
VulnCorp Lab 02 -- Upload de Reportes a Plataformas de Gestion
Curso: Gestion de Vulnerabilidades con Enfoque MITRE -- 2026

Este script automatiza la subida de:
  1. SBOMs (CycloneDX JSON) -> Dependency-Track (via API v1)
  2. Reportes de Grype (CycloneDX JSON) -> DefectDojo (via API v2)

Requisitos:
  - Python 3.8+
  - modulo 'requests' (pip3 install requests)
  - Dependency-Track corriendo en http://localhost:8084
  - DefectDojo corriendo en http://localhost:8085

NOTA IMPORTANTE sobre Dependency-Track 4.13+:
  Los API keys se almacenan en formato HASHEADO en la base de datos.
  Esto significa que NO se pueden leer despues de creados.
  Este script genera un API key NUEVO en cada ejecucion si no tiene
  uno guardado localmente, o usa JWT Bearer auth como alternativa.
"""

import json
import os
import sys
import time
import base64
import glob
import argparse
import subprocess
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] Modulo 'requests' no encontrado. Instale con: pip3 install requests")
    sys.exit(1)

# =====================================================================
#  CONFIGURACION
# =====================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LAB02_DIR = os.path.dirname(SCRIPT_DIR)
SBOM_DIR = os.path.join(LAB02_DIR, "data", "sbom")
GRYPE_DIR = os.path.join(LAB02_DIR, "data", "grype")

# Dependency-Track
DTRACK_URL = os.environ.get("DTRACK_URL", "http://localhost:8084")
DTRACK_API_KEY = os.environ.get("DTRACK_API_KEY", "")
DTRACK_NEW_PASSWORD = os.environ.get("DTRACK_NEW_PASSWORD", "VulnCorp2026!")
# JWT token (se obtiene via login, alternativa a API key)
DTRACK_JWT = ""

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

# Colores (compatibles con terminales basicas)
class C:
    if sys.stdout.isatty():
        RED = '\033[0;31m'
        GREEN = '\033[0;32m'
        YELLOW = '\033[1;33m'
        BLUE = '\033[0;34m'
        CYAN = '\033[0;36m'
        BOLD = '\033[1m'
        NC = '\033[0m'
    else:
        RED = GREEN = YELLOW = BLUE = CYAN = BOLD = NC = ''


def banner():
    print(f"""
{C.BOLD}{C.CYAN}+==============================================================+
|  VulnCorp Lab 02 -- Upload de Reportes a Plataformas         |
|  Dependency-Track + DefectDojo                                |
+==============================================================+{C.NC}
""")


# =====================================================================
#  DEPENDENCY-TRACK: AUTENTICACION
# =====================================================================

def _dtrack_check_connectivity():
    """Verifica que Dependency-Track esta accesible."""
    try:
        resp = requests.get(f"{DTRACK_URL}/api/version", timeout=10)
        if resp.status_code == 200:
            version = resp.json().get("version", "desconocida")
            print(f"  {C.GREEN}[OK] Dependency-Track v{version} accesible en {DTRACK_URL}{C.NC}")
            return True
    except requests.exceptions.ConnectionError:
        pass
    print(f"  {C.RED}[X] No se puede conectar a Dependency-Track en {DTRACK_URL}{C.NC}")
    print(f"      Verifique que este corriendo: docker compose ps")
    return False


def _dtrack_force_change_password():
    """
    En Dependency-Track, el primer login con admin/admin REQUIERE
    un cambio de contrasena obligatorio via el endpoint forceChangePassword.
    Retorna True si el cambio fue exitoso o ya se hizo previamente.
    """
    print(f"  {C.YELLOW}[i] Intentando cambio de contrasena obligatorio (primer login)...{C.NC}")
    try:
        resp = requests.post(
            f"{DTRACK_URL}/api/v1/user/forceChangePassword",
            data={
                "username": "admin",
                "password": "admin",
                "newPassword": DTRACK_NEW_PASSWORD,
                "confirmPassword": DTRACK_NEW_PASSWORD,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        if resp.status_code == 200:
            print(f"  {C.GREEN}[OK] Contrasena de DTrack cambiada exitosamente{C.NC}")
            return True
        elif resp.status_code == 401:
            print(f"  {C.CYAN}[i] La contrasena ya fue cambiada previamente.{C.NC}")
            return True
        else:
            print(f"  {C.YELLOW}[!] forceChangePassword retorno HTTP {resp.status_code}: {resp.text[:200]}{C.NC}")
            return True  # Continuar intentando login
    except requests.exceptions.ConnectionError:
        print(f"  {C.RED}[X] No se puede conectar a Dependency-Track{C.NC}")
        return False


def _dtrack_login(password):
    """Intenta hacer login en Dependency-Track y retorna el JWT token."""
    try:
        resp = requests.post(
            f"{DTRACK_URL}/api/v1/user/login",
            data=f"username=admin&password={requests.utils.quote(password)}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        if resp.status_code == 200:
            return resp.text.strip()
        return None
    except requests.exceptions.ConnectionError:
        return None


def _dtrack_generate_new_api_key(jwt_token):
    """
    Genera un NUEVO API key para el equipo Administrators.
    
    IMPORTANTE: Desde DTrack 4.13, los API keys se almacenan hasheados.
    El key solo es visible en la respuesta de creacion (PUT).
    Los keys existentes NO se pueden leer despues.
    """
    headers = {"Authorization": f"Bearer {jwt_token}"}
    try:
        resp = requests.get(f"{DTRACK_URL}/api/v1/team", headers=headers, timeout=10)
        if resp.status_code != 200:
            print(f"  {C.YELLOW}[!] No se pudo listar equipos (HTTP {resp.status_code}){C.NC}")
            return None

        teams = resp.json()
        for team in teams:
            if team.get("name") == "Administrators":
                team_uuid = team.get("uuid")
                # Generar un NUEVO API key
                resp2 = requests.put(
                    f"{DTRACK_URL}/api/v1/team/{team_uuid}/key",
                    headers=headers,
                    timeout=10
                )
                if resp2.status_code in (200, 201):
                    new_key = resp2.json().get("key", "")
                    if new_key:
                        print(f"  {C.GREEN}[OK] Nuevo API key generado para equipo Administrators{C.NC}")
                        return new_key
                    else:
                        print(f"  {C.YELLOW}[!] Respuesta sin key: {resp2.text[:200]}{C.NC}")
                else:
                    print(f"  {C.YELLOW}[!] Error generando API key (HTTP {resp2.status_code}): {resp2.text[:200]}{C.NC}")

        print(f"  {C.YELLOW}[!] No se encontro el equipo Administrators{C.NC}")
    except Exception as e:
        print(f"  {C.RED}[X] Error generando API key: {e}{C.NC}")
    return None


def _save_dtrack_api_key(api_key):
    """Guarda el API key en un archivo local para futuros usos."""
    try:
        key_file = os.path.join(LAB02_DIR, "data", ".dtrack_api_key")
        with open(key_file, "w") as f:
            f.write(api_key)
        try:
            os.chmod(key_file, 0o600)
        except Exception:
            pass  # chmod puede fallar en Windows
        print(f"  {C.CYAN}[i] API key guardado en data/.dtrack_api_key{C.NC}")
    except Exception:
        pass


def _load_dtrack_api_key():
    """Carga el API key desde archivo local."""
    key_file = os.path.join(LAB02_DIR, "data", ".dtrack_api_key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            key = f.read().strip()
            if key:
                return key
    return None


def _validate_api_key(api_key):
    """Verifica que un API key es valido haciendo una peticion de prueba."""
    try:
        resp = requests.get(
            f"{DTRACK_URL}/api/v1/team",
            headers={"X-Api-Key": api_key},
            timeout=10
        )
        return resp.status_code == 200
    except Exception:
        return False


def dtrack_authenticate():
    """
    Flujo completo de autenticacion para Dependency-Track.
    
    Orden de prioridad:
    1. Variable de entorno DTRACK_API_KEY
    2. API key guardado en archivo local (data/.dtrack_api_key)
    3. Login con JWT + generar nuevo API key
    4. Usar JWT directamente como fallback
    
    Retorna un dict con el metodo de auth a usar:
    {"method": "api_key", "key": "..."} o
    {"method": "jwt", "token": "..."} o
    None si falla todo.
    """
    global DTRACK_API_KEY, DTRACK_JWT

    # Verificar conectividad primero
    if not _dtrack_check_connectivity():
        return None

    # Opcion 1: Variable de entorno
    if DTRACK_API_KEY:
        print(f"  {C.CYAN}[i] Usando API key de variable de entorno DTRACK_API_KEY{C.NC}")
        if _validate_api_key(DTRACK_API_KEY):
            print(f"  {C.GREEN}[OK] API key validado correctamente{C.NC}")
            return {"method": "api_key", "key": DTRACK_API_KEY}
        else:
            print(f"  {C.YELLOW}[!] API key de entorno es invalido (HTTP 401). Intentando alternativas...{C.NC}")

    # Opcion 2: Archivo local
    saved_key = _load_dtrack_api_key()
    if saved_key:
        print(f"  {C.CYAN}[i] API key encontrado en data/.dtrack_api_key{C.NC}")
        if _validate_api_key(saved_key):
            print(f"  {C.GREEN}[OK] API key validado correctamente{C.NC}")
            DTRACK_API_KEY = saved_key
            return {"method": "api_key", "key": saved_key}
        else:
            print(f"  {C.YELLOW}[!] API key guardado es invalido. Generando uno nuevo...{C.NC}")

    # Opcion 3: Login con JWT
    print(f"  {C.CYAN}[i] Autenticando via login...{C.NC}")

    # Intentar con contrasena nueva primero
    jwt_token = _dtrack_login(DTRACK_NEW_PASSWORD)

    if not jwt_token:
        # Intentar con admin/admin
        jwt_token = _dtrack_login("admin")

        if jwt_token:
            # Primer login exitoso con admin/admin -> forzar cambio
            print(f"  {C.GREEN}[OK] Login con admin/admin exitoso. Cambiando contrasena...{C.NC}")
            _dtrack_force_change_password()
            # Re-login con nueva contrasena
            jwt_token = _dtrack_login(DTRACK_NEW_PASSWORD)
        else:
            # Ninguno funciono, intentar forzar cambio
            _dtrack_force_change_password()
            jwt_token = _dtrack_login(DTRACK_NEW_PASSWORD)

    if not jwt_token:
        print(f"  {C.RED}[X] No se pudo autenticar en Dependency-Track.{C.NC}")
        print(f"      Opciones:")
        print(f"        1. Establezca DTRACK_API_KEY con un API key valido")
        print(f"        2. Establezca DTRACK_NEW_PASSWORD con la contrasena actual")
        print(f"        3. Acceda a http://localhost:8083 y obtenga un API key manualmente")
        return None

    print(f"  {C.GREEN}[OK] Login exitoso en Dependency-Track{C.NC}")
    DTRACK_JWT = jwt_token

    # Generar nuevo API key
    new_key = _dtrack_generate_new_api_key(jwt_token)
    if new_key:
        DTRACK_API_KEY = new_key
        _save_dtrack_api_key(new_key)
        return {"method": "api_key", "key": new_key}

    # Fallback: usar JWT directamente
    print(f"  {C.YELLOW}[!] No se pudo generar API key. Usando JWT Bearer como fallback.{C.NC}")
    return {"method": "jwt", "token": jwt_token}


def _dtrack_headers(auth_info):
    """Construye los headers de autenticacion para Dependency-Track."""
    if auth_info["method"] == "api_key":
        return {"X-Api-Key": auth_info["key"], "Content-Type": "application/json"}
    else:
        return {"Authorization": f"Bearer {auth_info['token']}", "Content-Type": "application/json"}


# =====================================================================
#  DEPENDENCY-TRACK: UPLOAD
# =====================================================================

def dtrack_upload_sbom(auth_info, service_key, sbom_file):
    """
    Sube un SBOM CycloneDX a Dependency-Track.
    Crea el proyecto automaticamente si no existe.
    """
    meta = SERVICES.get(service_key, {"name": service_key, "version": "unknown", "group": "unknown"})

    # Leer y codificar el SBOM en base64
    # Usar 'rb' para evitar problemas de encoding en Windows
    with open(sbom_file, 'rb') as f:
        raw = f.read()

    # Eliminar BOM si existe
    if raw[:3] == b'\xef\xbb\xbf':
        raw = raw[3:]
    elif raw[:2] == b'\xff\xfe':
        raw = raw.decode('utf-16-le').encode('utf-8')

    sbom_b64 = base64.b64encode(raw).decode('ascii')

    headers = _dtrack_headers(auth_info)

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
            timeout=60
        )
        if resp.status_code in (200, 201):
            token = resp.json().get("token", "N/A")
            token_display = token[:12] + "..." if len(str(token)) > 12 else str(token)
            print(f"  {C.GREEN}[OK] SBOM subido: {meta['name']} v{meta['version']} (token: {token_display}){C.NC}")
            return True
        elif resp.status_code == 401:
            print(f"  {C.RED}[X] Error de autenticacion (HTTP 401) subiendo SBOM de {meta['name']}{C.NC}")
            print(f"      Metodo usado: {auth_info['method']}")
            print(f"      Respuesta: {resp.text[:300]}")
            return False
        elif resp.status_code == 403:
            print(f"  {C.RED}[X] Sin permisos (HTTP 403) para subir SBOM de {meta['name']}{C.NC}")
            print(f"      El API key no tiene permiso BOM_UPLOAD.")
            print(f"      Verifique los permisos del equipo en Administration > Teams")
            return False
        else:
            print(f"  {C.RED}[X] Error subiendo SBOM (HTTP {resp.status_code}): {resp.text[:300]}{C.NC}")
            return False
    except Exception as e:
        print(f"  {C.RED}[X] Error de conexion: {e}{C.NC}")
        return False


# =====================================================================
#  DEFECTDOJO
# =====================================================================

def _resolve_dojo_password():
    """
    Resuelve la contrasena de DefectDojo en este orden:
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
                print(f"  {C.CYAN}[i] Contrasena leida de data/.dd_admin_password{C.NC}")
                return DOJO_PASSWORD

    # Intentar obtener de los logs del initializer
    try:
        result = subprocess.run(
            ["docker", "logs", "vulncorp-dd-initializer"],
            capture_output=True, text=True, timeout=10
        )
        logs = result.stdout + result.stderr
        for line in logs.splitlines():
            line_lower = line.lower()
            if "password" in line_lower:
                if ":" in line:
                    pw = line.split(":")[-1].strip()
                    if pw and len(pw) > 3:
                        DOJO_PASSWORD = pw
                        try:
                            with open(pw_file, "w") as f:
                                f.write(pw)
                            os.chmod(pw_file, 0o600)
                        except Exception:
                            pass
                        print(f"  {C.CYAN}[i] Contrasena obtenida de los logs del initializer{C.NC}")
                        return DOJO_PASSWORD
    except Exception:
        pass

    # Solicitar al usuario
    print(f"  {C.YELLOW}[!] No se encontro la contrasena de DefectDojo automaticamente.{C.NC}")
    print(f"      Puede obtenerla ejecutando:")
    print(f"      {C.CYAN}docker logs vulncorp-dd-initializer 2>&1 | grep -i password{C.NC}")
    try:
        DOJO_PASSWORD = input(f"  Ingrese la contrasena de admin de DefectDojo: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return DOJO_PASSWORD


def dojo_get_token():
    """Obtiene un token de autenticacion de DefectDojo."""
    global DOJO_TOKEN

    if DOJO_TOKEN:
        return DOJO_TOKEN

    print(f"  {C.YELLOW}[i] Obteniendo token de DefectDojo...{C.NC}")

    password = _resolve_dojo_password()
    if not password:
        print(f"  {C.RED}[X] No se proporciono contrasena de DefectDojo{C.NC}")
        return None

    try:
        resp = requests.post(
            f"{DOJO_URL}/api/v2/api-token-auth/",
            json={"username": DOJO_USER, "password": password},
            timeout=10
        )
        if resp.status_code == 200:
            DOJO_TOKEN = resp.json().get("token", "")
            print(f"  {C.GREEN}[OK] Token obtenido de DefectDojo{C.NC}")
            return DOJO_TOKEN
        else:
            print(f"  {C.RED}[X] Login fallido en DefectDojo (HTTP {resp.status_code}){C.NC}")
            print(f"      Verifique la contrasena. Puede obtenerla con:")
            print(f"      {C.CYAN}docker logs vulncorp-dd-initializer 2>&1 | grep -i password{C.NC}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"  {C.RED}[X] No se puede conectar a DefectDojo en {DOJO_URL}{C.NC}")
        print(f"      Verifique que este corriendo: docker compose ps")
        return None


def dojo_get_or_create_product(product_name, description=""):
    """Obtiene o crea un producto en DefectDojo."""
    token = dojo_get_token()
    if not token:
        return None

    headers = {"Authorization": f"Token {token}"}

    try:
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
    except Exception:
        pass

    # Obtener product_type
    pt_id = 1
    try:
        resp_pt = requests.get(f"{DOJO_URL}/api/v2/product_types/", headers=headers, timeout=10)
        if resp_pt.status_code == 200:
            pts = resp_pt.json().get("results", [])
            if pts:
                pt_id = pts[0]["id"]
    except Exception:
        pass

    try:
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
            print(f"  {C.RED}[X] Error creando producto (HTTP {resp.status_code}): {resp.text[:200]}{C.NC}")
    except Exception as e:
        print(f"  {C.RED}[X] Error creando producto: {e}{C.NC}")
    return None


def dojo_get_or_create_engagement(product_id, engagement_name):
    """Obtiene o crea un engagement en DefectDojo."""
    token = dojo_get_token()
    headers = {"Authorization": f"Token {token}"}

    try:
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
    except Exception:
        pass

    today = datetime.now().strftime("%Y-%m-%d")
    try:
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
            print(f"  {C.RED}[X] Error creando engagement (HTTP {resp.status_code}): {resp.text[:200]}{C.NC}")
    except Exception as e:
        print(f"  {C.RED}[X] Error creando engagement: {e}{C.NC}")
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

    product_id = dojo_get_or_create_product(
        f"VulnCorp - {meta['name']}",
        f"Servicio {service_key} de la infraestructura VulnCorp PetaShop. Zona: {meta['group']}"
    )
    if not product_id:
        return False

    engagement_id = dojo_get_or_create_engagement(
        product_id,
        f"Escaneo Grype - Lab 02 - {datetime.now().strftime('%Y-%m-%d')}"
    )
    if not engagement_id:
        return False

    headers = {"Authorization": f"Token {token}"}

    try:
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
                timeout=120
            )

        if resp.status_code in (200, 201):
            test_id = resp.json().get("test", "N/A")
            print(f"  {C.GREEN}[OK] Scan importado en DefectDojo: {meta['name']} (test_id: {test_id}){C.NC}")
            return True
        else:
            print(f"  {C.RED}[X] Error importando scan (HTTP {resp.status_code}): {resp.text[:300]}{C.NC}")
            return False
    except Exception as e:
        print(f"  {C.RED}[X] Error de conexion: {e}{C.NC}")
        return False


# =====================================================================
#  MAIN
# =====================================================================

def main():
    global DTRACK_URL, DOJO_URL, DTRACK_API_KEY

    parser = argparse.ArgumentParser(description="Upload SBOMs y scans a Dependency-Track y DefectDojo")
    parser.add_argument("--dtrack-only", action="store_true", help="Solo subir a Dependency-Track")
    parser.add_argument("--dojo-only", action="store_true", help="Solo subir a DefectDojo")
    parser.add_argument("--dtrack-url", default=DTRACK_URL, help="URL de Dependency-Track API")
    parser.add_argument("--dojo-url", default=DOJO_URL, help="URL de DefectDojo")
    parser.add_argument("--verbose", "-v", action="store_true", help="Mostrar informacion detallada")
    args = parser.parse_args()

    DTRACK_URL = args.dtrack_url
    DOJO_URL = args.dojo_url

    banner()

    upload_dtrack = not args.dojo_only
    upload_dojo = not args.dtrack_only

    # --- DEPENDENCY-TRACK ---
    if upload_dtrack:
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print(f"{C.BOLD}  FASE 1: Subida de SBOMs a Dependency-Track{C.NC}")
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print()

        # Autenticacion centralizada (una sola vez)
        print(f"  {C.CYAN}[i] Autenticando en Dependency-Track...{C.NC}")
        auth_info = dtrack_authenticate()

        if not auth_info:
            print(f"  {C.RED}[X] No se pudo autenticar. Saltando Dependency-Track.{C.NC}")
        else:
            print(f"  {C.GREEN}[OK] Autenticado con metodo: {auth_info['method']}{C.NC}")
            print()

            sbom_files = sorted(glob.glob(os.path.join(SBOM_DIR, "*_sbom_cyclonedx.json")))
            if not sbom_files:
                print(f"  {C.RED}[X] No se encontraron SBOMs en {SBOM_DIR}/{C.NC}")
                print(f"      Ejecute primero: ./scripts/generate_sbom.sh")
            else:
                print(f"  {C.CYAN}[i] Encontrados {len(sbom_files)} SBOMs para subir{C.NC}")
                if args.verbose:
                    for f in sbom_files:
                        size = os.path.getsize(f)
                        print(f"      - {os.path.basename(f)} ({size:,} bytes)")
                print()

                success = 0
                for sbom_file in sbom_files:
                    service_key = os.path.basename(sbom_file).replace("_sbom_cyclonedx.json", "")
                    if dtrack_upload_sbom(auth_info, service_key, sbom_file):
                        success += 1

                print()
                color = C.GREEN if success == len(sbom_files) else C.YELLOW if success > 0 else C.RED
                print(f"  {color}{C.BOLD}Resultado: {success}/{len(sbom_files)} SBOMs subidos a Dependency-Track{C.NC}")
                print(f"  {C.CYAN}Abrir: http://localhost:8083{C.NC}")
        print()

    # --- DEFECTDOJO ---
    if upload_dojo:
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print(f"{C.BOLD}  FASE 2: Subida de Scans a DefectDojo{C.NC}")
        print(f"{C.BOLD}{'='*62}{C.NC}")
        print()

        grype_files = sorted(glob.glob(os.path.join(GRYPE_DIR, "*_grype_cyclonedx.json")))
        if not grype_files:
            print(f"  {C.RED}[X] No se encontraron reportes Grype en {GRYPE_DIR}/{C.NC}")
            print(f"      Ejecute primero: ./scripts/scan_grype.sh")
        else:
            print(f"  {C.CYAN}[i] Encontrados {len(grype_files)} reportes para subir{C.NC}")
            print()

            success = 0
            for grype_file in grype_files:
                service_key = os.path.basename(grype_file).replace("_grype_cyclonedx.json", "")
                if dojo_upload_scan(service_key, grype_file):
                    success += 1

            print()
            color = C.GREEN if success == len(grype_files) else C.YELLOW if success > 0 else C.RED
            print(f"  {color}{C.BOLD}Resultado: {success}/{len(grype_files)} scans importados en DefectDojo{C.NC}")
            print(f"  {C.CYAN}Abrir: {DOJO_URL}{C.NC}")
        print()

    # --- RESUMEN FINAL ---
    print(f"{C.BOLD}{C.CYAN}+==============================================================+")
    print(f"|  Upload completado                                           |")
    print(f"+==============================================================+{C.NC}")
    print()
    print(f"  {C.BOLD}Plataformas:{C.NC}")
    if upload_dtrack:
        print(f"    Dependency-Track: {C.CYAN}http://localhost:8083{C.NC}")
    if upload_dojo:
        print(f"    DefectDojo:       {C.CYAN}http://localhost:8085{C.NC}")
    print()


if __name__ == "__main__":
    main()
