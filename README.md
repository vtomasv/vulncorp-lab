# VulnCorp Lab — Gestión de Vulnerabilidades (MITRE)

## Unidad 1: Anatomía de la Superficie de Ataque

**Curso:** MAR303 — Universidad Mayor — 2026  
**Profesor:** Tomás Vera  

---

## Descripción

VulnCorp Lab es un entorno de laboratorio completamente funcional basado en Docker Compose que simula la infraestructura tecnológica de una empresa real de comercio electrónico llamada **PetaShop** (tienda de productos para mascotas). El laboratorio está diseñado para que los estudiantes experimenten de primera mano el proceso completo de gestión de vulnerabilidades: desde el descubrimiento y análisis de la superficie de ataque, hasta la priorización inteligente y la propuesta de remediación.

El entorno incluye software **intencionalmente vulnerable** con CVEs reales y conocidos, un escáner de vulnerabilidades integrado (Trivy), y un dashboard web interactivo donde los estudiantes pueden visualizar, filtrar y priorizar las vulnerabilidades encontradas.

> **ADVERTENCIA:** Este laboratorio contiene software intencionalmente vulnerable. Utilícelo exclusivamente con fines educativos en redes aisladas. No exponer a Internet. No usar en producción.

---

## Arquitectura

El laboratorio simula una empresa con tres zonas de red diferenciadas:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INTERNET                                     │
│                           │                                         │
│                      ┌────┴────┐                                    │
│                      │ :8080   │                                    │
│  ┌───────────────────┴─────────┴───────────────────┐                │
│  │         RED DE PRODUCCIÓN (172.20.0.0/24)        │                │
│  │                                                  │                │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────────┐  │                │
│  │  │  Nginx   │→ │PrestaShop │→ │    Redis     │  │                │
│  │  │  1.21.0  │  │  1.7.8.0  │  │    6.2.6     │  │                │
│  │  │ (proxy)  │  │ (tienda)  │  │   (caché)    │  │                │
│  │  └──────────┘  └───────────┘  └──────────────┘  │                │
│  │                      │                           │                │
│  │                ┌─────┴─────┐                     │                │
│  │                │ MariaDB   │◄────────────────┐   │                │
│  │                │ 10.5.18   │                 │   │                │
│  │                │   (BD)    │                 │   │                │
│  └────────────────┴───────────┴─────────────────┘   │                │
│                         │                           │                │
│  ┌──────────────────────┴───────────────────────┐   │                │
│  │       RED CORPORATIVA (172.21.0.0/24)         │   │                │
│  │                                               │   │                │
│  │  ┌───────────┐  ┌────────────┐  ┌──────────┐ │   │                │
│  │  │phpMyAdmin │  │Workstation │  │   FTP    │ │   │                │
│  │  │   5.1.1   │  │Ubuntu 20.04│  │ vsftpd   │ │   │                │
│  │  │ (:8081)   │  │ (soporte)  │  │(archivos)│ │   │                │
│  │  └───────────┘  └────────────┘  └──────────┘ │   │                │
│  └───────────────────────────────────────────────┘   │                │
│                                                      │                │
│  ┌───────────────────────────────────────────────┐   │                │
│  │       RED DE GESTIÓN (172.22.0.0/24)           │   │                │
│  │                                               │   │                │
│  │  ┌──────────────────────────────────────────┐ │   │                │
│  │  │   Dashboard de Vulnerabilidades (:3000)  │ │   │                │
│  │  └──────────────────────────────────────────┘ │   │                │
│  └───────────────────────────────────────────────┘   │                │
└──────────────────────────────────────────────────────┘                │
```

### Servicios y Versiones Vulnerables

| Servicio | Imagen Docker | Red | Exposición | CVEs Conocidos |
|----------|--------------|-----|------------|----------------|
| Nginx Proxy | `nginx:1.21.0` | Producción | Internet (8080) | CVE-2021-23017, CVE-2021-3618 y otros |
| PrestaShop | `prestashop/prestashop:1.7.8.0` | Producción | Via proxy | CVE-2022-31101, CVE-2022-35933 y otros |
| MariaDB | `mariadb:10.5.18` | Prod + Corp | Interna | CVE-2022-32084, CVE-2022-32091 y otros |
| Redis | `redis:6.2.6` | Producción | Interna | CVE-2022-24735, CVE-2022-24736 y otros |
| phpMyAdmin | `phpmyadmin:5.1.1` | Corporativa | Interna (8081) | CVE-2022-23807, CVE-2022-0813 y otros |
| Workstation | `ubuntu:20.04` | Corporativa | Interna | Múltiples CVEs de paquetes del sistema |
| FTP Server | `delfer/alpine-ftp-server` | Corporativa | Interna | Transmisión en texto plano |

---

## Compatibilidad

Este laboratorio es compatible con las siguientes arquitecturas:

| Arquitectura | Plataforma | Estado |
|-------------|-----------|--------|
| AMD64 (x86_64) | Intel / AMD (Windows, Linux, Mac Intel) | Totalmente compatible |
| ARM64 (aarch64) | Apple Silicon M1/M2/M3/M4, Raspberry Pi | Totalmente compatible |

Todas las imágenes Docker seleccionadas tienen soporte nativo multi-arquitectura. Se utiliza **MariaDB 10.5** en lugar de MySQL 5.7 porque MySQL 5.7 no tiene imagen oficial para ARM64.

---

## Inicio Rápido

### Requisitos previos

- Docker Desktop v24+ o Docker Engine + Docker Compose v2+
- 8 GB de RAM disponibles
- 10 GB de espacio en disco
- Git

### Instalación (Linux / macOS)

```bash
# 1. Clonar el repositorio
git clone https://github.com/vtomasv/vulncorp-lab.git
cd vulncorp-lab

# 2. Ejecutar setup (instala Trivy y descarga imágenes)
chmod +x scripts/setup.sh scripts/scan.sh
./scripts/setup.sh

# 3. Levantar el entorno
docker compose up -d

# 4. Esperar ~2-3 minutos y verificar
docker compose ps

# 5. Ejecutar el escaneo de vulnerabilidades
./scripts/scan.sh

# 6. Abrir el dashboard
# http://localhost:3000
```

### Instalación (Windows)

**Requisitos adicionales:** Trivy instalado (`choco install trivy`, `scoop install trivy` o `winget install AquaSecurity.Trivy`) y Python 3.

**Opción A: PowerShell (recomendado en Windows)**
```powershell
# 1. Clonar el repositorio
git clone https://github.com/vtomasv/vulncorp-lab.git
cd vulncorp-lab

# 2. Levantar el entorno
docker compose up -d

# 3. Esperar ~2-3 minutos y verificar
docker compose ps

# 4. Ejecutar el escaneo de vulnerabilidades
.\scripts\scan.ps1

# 5. Abrir el dashboard
# http://localhost:3000
```

**Opción B: Git Bash**
```bash
# 1. Clonar el repositorio
git clone https://github.com/vtomasv/vulncorp-lab.git
cd vulncorp-lab

# 2. Levantar el entorno
docker compose up -d

# 3. Esperar ~2-3 minutos y verificar
docker compose ps

# 4. Ejecutar el escaneo de vulnerabilidades
bash scripts/scan.sh

# 5. Abrir el dashboard
# http://localhost:3000
```

> **Nota sobre Windows:** Si el escaneo muestra problemas, use el script PowerShell (`scan.ps1`) que es nativo de Windows y evita los problemas de conversión de rutas de Git Bash/MINGW. Si el dashboard no carga los datos, visite `http://localhost:3000/api/debug` para diagnosticar.

### URLs de Acceso

| Servicio | URL | Credenciales |
|----------|-----|-------------|
| PetaShop (tienda) | http://localhost:8080 | — |
| PetaShop Admin | http://localhost:8080/admin4vulncorp | admin@vulncorp.local / VulnCorp2024! |
| Nginx Proxy | http://localhost:8082 | — |
| phpMyAdmin | http://localhost:8081 | root / R00tVulnCorp! |
| Dashboard | http://localhost:3000 | — |

### Detener el laboratorio

```bash
docker compose down -v
```

---

## Estructura del Repositorio

```
vulncorp-lab/
├── docker-compose.yml          # Lab 01: Infraestructura VulnCorp PetaShop
├── README.md                   # Este archivo
├── config/
│   └── nginx/
│       └── default.conf        # Configuración vulnerable de Nginx
├── dashboard/
│   ├── Dockerfile              # Imagen del dashboard
│   ├── package.json            # Dependencias Node.js
│   ├── server.js               # API del dashboard
│   └── public/
│       └── index.html          # Interfaz web del dashboard
├── scripts/
│   ├── setup.sh                # Setup inicial (Trivy + imágenes)
│   ├── scan.sh                 # Escaneo de vulnerabilidades (Linux/macOS/Git Bash)
│   └── scan.ps1                # Escaneo de vulnerabilidades (Windows PowerShell)
├── data/                       # Reportes generados (gitignored)
├── docs/
│   ├── LAB_01_STUDENT.md       # Guía del estudiante (Lab 01)
│   └── LAB_01_INSTRUCTOR.md    # Guía del instructor (Lab 01)
├── lab02-pipeline/             # Lab 02: Pipeline profesional
│   ├── docker-compose.yml      # Dependency-Track + DefectDojo
│   ├── README.md               # Documentación del Lab 02
│   ├── scripts/
│   │   ├── setup_lab02.sh      # Setup (Syft + Grype + plataformas)
│   │   ├── generate_sbom.sh    # Genera SBOMs con Syft (Linux/macOS/Git Bash)
│   │   ├── generate_sbom.ps1   # Genera SBOMs con Syft (Windows PowerShell)
│   │   ├── scan_grype.sh       # Escanea con Grype (Linux/macOS/Git Bash)
│   │   ├── scan_grype.ps1      # Escanea con Grype (Windows PowerShell)
│   │   └── upload_reports.py   # Sube a DTrack y DefectDojo
│   ├── data/
│   │   ├── sbom/               # SBOMs generados
│   │   ├── grype/              # Reportes de Grype
│   │   └── cyclonedx-examples/ # Ejemplo anotado de CycloneDX
│   └── docs/
│       ├── LAB_02_STUDENT.md   # Guía del estudiante (Lab 02)
│       └── LAB_02_INSTRUCTOR.md# Guía del instructor (Lab 02)
└── .gitignore
```

---

## Objetivos Pedagógicos

Este laboratorio está diseñado para la primera clase del curso de Gestión de Vulnerabilidades y busca generar un impacto inmediato en los estudiantes al demostrar que la gestión de vulnerabilidades es un proceso proactivo, continuo y sistemático cuyo objetivo principal es reducir la superficie de ataque y el riesgo operativo, protegiendo a la organización de ciberataques antes de que sean explotados, pero optimizando todos los recursos disponibles.

Los conceptos clave que se trabajan en este laboratorio incluyen:

- **Superficie de ataque** y cómo mapearla en una infraestructura real
- **Diferencia entre severidad (CVSS) y prioridad operativa**
- **Contexto empresarial** como factor determinante en la priorización
- **Decisiones arquitectónicas** y su impacto en seguridad y costos
- **Herramientas de escaneo** (Trivy) y dashboards de gestión
- Introducción a **CVE, CVSS, EPSS, KEV** y su uso práctico

---

## Licencia

Este material es de uso exclusivamente educativo, creado para el curso MAR303 de la Universidad Mayor. El software vulnerable incluido es propiedad de sus respectivos autores y se utiliza con fines de enseñanza.

---

## Créditos

- **Profesor:** Tomás Vera — Universidad Mayor — 2026
- **Frameworks de referencia:** MITRE ATT&CK, CVE, CVSS, EPSS, CISA KEV
- **Herramientas:** Trivy (Aqua Security), Syft, Grype (Anchore), Dependency-Track (OWASP), DefectDojo, Docker, PrestaShop, MariaDB
