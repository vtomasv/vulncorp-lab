# Lab 02 — Pipeline Profesional de Gestión de Vulnerabilidades

## SBOM (Syft) → Escaneo (Grype) → Monitoreo (Dependency-Track) → Gestión (DefectDojo)

Este laboratorio es la **segunda fase** del curso de Gestión de Vulnerabilidades con Enfoque MITRE. Reutiliza la infraestructura del Lab 01 (VulnCorp PetaShop) y agrega un pipeline profesional de herramientas de seguridad.

---

## Arquitectura del Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    INFRAESTRUCTURA VULNCORP (Lab 01)                    │
│  ┌──────────┐ ┌─────────────┐ ┌──────────┐ ┌───────┐ ┌────────────┐  │
│  │  Nginx   │ │ PrestaShop  │ │ MariaDB  │ │ Redis │ │ phpMyAdmin │  │
│  │  :8082   │ │   :8080     │ │  :3306   │ │ :6379 │ │   :8081    │  │
│  └──────────┘ └─────────────┘ └──────────┘ └───────┘ └────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
        │                                                     │
        ▼                                                     ▼
┌───────────────┐    ┌───────────────┐    ┌──────────────────────────────┐
│     SYFT      │───▶│    GRYPE      │    │      PLATAFORMAS (Lab 02)    │
│  Genera SBOM  │    │  Escanea CVEs │    │                              │
│  CycloneDX    │    │  CycloneDX    │    │  ┌────────────────────────┐  │
└───────────────┘    └───────┬───────┘    │  │  Dependency-Track      │  │
                             │            │  │  Frontend: :8083       │  │
                             │            │  │  API:      :8084       │  │
                             │            │  └────────────────────────┘  │
                             │            │                              │
                             │            │  ┌────────────────────────┐  │
                             └───────────▶│  │  DefectDojo            │  │
                                          │  │  Web UI:   :8085       │  │
                                          │  └────────────────────────┘  │
                                          └──────────────────────────────┘
```

---

## Herramientas

| Herramienta | Tipo | Función | Formato |
|-------------|------|---------|---------|
| [Syft](https://github.com/anchore/syft) | CLI | Genera SBOM (inventario de componentes) | CycloneDX JSON/XML |
| [Grype](https://github.com/anchore/grype) | CLI | Escanea vulnerabilidades desde SBOM | CycloneDX JSON |
| [Dependency-Track](https://dependencytrack.org/) | Plataforma web | Monitoreo continuo de la cadena de suministro | Consume CycloneDX |
| [DefectDojo](https://defectdojo.com/) | Plataforma web | Gestión centralizada de vulnerabilidades | Importa CycloneDX |

---

## Inicio Rápido

### Prerrequisitos

El Lab 01 debe estar funcionando. Verifique con:

```bash
cd vulncorp-lab
docker compose ps
```

### Instalación y ejecución

```bash
# 1. Entrar al directorio del Lab 02
cd lab02-pipeline

# 2. Ejecutar setup (instala Syft, Grype y levanta plataformas)
./scripts/setup_lab02.sh

# 3. Esperar 3-5 minutos a que las plataformas inicialicen

# 4. Generar SBOMs de la infraestructura del Lab 01
./scripts/generate_sbom.sh

# 5. Escanear vulnerabilidades con Grype
./scripts/scan_grype.sh

# 6. Subir resultados a las plataformas
python3 scripts/upload_reports.py
```

### URLs de Acceso

| Plataforma | URL | Credenciales |
|------------|-----|-------------|
| Dependency-Track | http://localhost:8083 | admin / VulnCorp2026! (o admin/admin en primer login) |
| DefectDojo | http://localhost:8085 | admin / (ver nota abajo) |

DefectDojo genera una contraseña aleatoria para el admin en la primera ejecución. El script `setup_lab02.sh` intenta capturarla y guardarla en `data/.dd_admin_password`. Si necesita obtenerla manualmente:

```bash
docker logs vulncorp-dd-initializer 2>&1 | grep -i password
```

---

## Estructura del Directorio

```
lab02-pipeline/
├── docker-compose.yml          # Plataformas: DTrack + DefectDojo
├── README.md                   # Este archivo
├── scripts/
│   ├── setup_lab02.sh          # Setup inicial (instala herramientas + levanta plataformas)
│   ├── generate_sbom.sh        # Genera SBOMs con Syft (CycloneDX)
│   ├── scan_grype.sh           # Escanea vulnerabilidades con Grype
│   └── upload_reports.py       # Sube resultados a DTrack y DefectDojo
├── data/
│   ├── sbom/                   # SBOMs generados por Syft
│   ├── grype/                  # Reportes de Grype
│   └── cyclonedx-examples/     # Ejemplo anotado de CycloneDX
└── docs/
    ├── LAB_02_STUDENT.md       # Guía del estudiante
    └── LAB_02_INSTRUCTOR.md    # Guía del instructor (confidencial)
```

---

## Formato CycloneDX

Este laboratorio utiliza **CycloneDX** como formato estándar para SBOMs y reportes de vulnerabilidades. CycloneDX es un estándar OWASP que permite describir la composición de software de forma estructurada.

En el directorio `data/cyclonedx-examples/` encontrará un archivo JSON anotado que explica cada campo del estándar con comentarios educativos.

### Campos principales de un CycloneDX SBOM

| Campo | Descripción |
|-------|-------------|
| `bomFormat` | Siempre "CycloneDX" |
| `specVersion` | Versión del estándar (ej: "1.5") |
| `serialNumber` | UUID único del SBOM |
| `metadata` | Quién, cuándo y con qué herramienta se generó |
| `components` | Lista de componentes de software (nombre, versión, PURL, licencias, hashes) |
| `vulnerabilities` | Lista de vulnerabilidades (solo en reportes de escaneo) |

---

## Gestión del Lab 02

```bash
# Ver estado de servicios
docker compose ps

# Ver logs de Dependency-Track
docker compose logs -f dtrack-apiserver

# Ver logs de DefectDojo
docker compose logs -f defectdojo-uwsgi

# Detener Lab 02 (conserva datos)
docker compose down

# Detener Lab 02 y borrar todos los datos
docker compose down -v

# Reiniciar Lab 02
docker compose restart
```

---

## Compatibilidad

Este laboratorio es compatible con **AMD64** (Intel/AMD) y **ARM64** (Apple Silicon M1/M2/M3/M4).

### Requisitos de recursos

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| RAM | 6 GB (solo Lab 02) | 12 GB (Lab 01 + Lab 02) |
| CPU | 2 cores | 4 cores |
| Disco | 5 GB | 10 GB |

---

*Laboratorio diseñado por el Profesor MITRE VulnMaster — Curso de Gestión de Vulnerabilidades con Enfoque MITRE — 2026*
