# Lab 02 — Pipeline Profesional de Gestión de Vulnerabilidades

## SBOM con Syft, Escaneo con Grype, Gestión con Dependency-Track y DefectDojo

**Curso:** Gestión de Vulnerabilidades con Enfoque MITRE — 2026
**Duración estimada:** 90 minutos
**Prerrequisito:** Lab 01 completado (VulnCorp PetaShop funcionando)

---

## Objetivos de Aprendizaje

Al completar este laboratorio, el estudiante será capaz de:

1. Generar un **Software Bill of Materials (SBOM)** en formato **CycloneDX** usando **Syft**.
2. Interpretar la estructura de un archivo CycloneDX JSON (componentes, PURLs, hashes, licencias).
3. Escanear un SBOM con **Grype** para detectar vulnerabilidades conocidas (CVEs).
4. Diferenciar entre un SBOM (inventario) y un reporte de vulnerabilidades (escaneo).
5. Importar SBOMs en **Dependency-Track** para análisis continuo de la cadena de suministro.
6. Importar resultados de escaneo en **DefectDojo** para gestión centralizada de vulnerabilidades.
7. Establecer criterios de priorización usando contexto del negocio, CVSS, EPSS y KEV.

---

## Contexto del Ejercicio

En el Lab 01, levantamos la infraestructura de **VulnCorp PetaShop** y descubrimos que tiene cientos de vulnerabilidades. Ahora, como equipo de seguridad, necesitamos pasar del "descubrimiento caótico" a un **pipeline profesional y repetible** de gestión de vulnerabilidades.

El pipeline que construiremos sigue el flujo estándar de la industria:

```
┌─────────┐    ┌─────────┐    ┌──────────────────┐    ┌────────────┐
│  SYFT   │───▶│  GRYPE  │───▶│ DEPENDENCY-TRACK │───▶│ DEFECTDOJO │
│ (SBOM)  │    │ (Scan)  │    │ (Supply Chain)   │    │ (Vuln Mgmt)│
└─────────┘    └─────────┘    └──────────────────┘    └────────────┘
  Inventario    Escaneo         Monitoreo continuo      Triaje y
  CycloneDX     CycloneDX       de componentes          remediación
```

---

## Material Necesario

- Lab 01 funcionando (`docker compose ps` muestra todos los servicios "Up")
- Docker y Docker Compose instalados
- Conexión a internet (para descargar herramientas y bases de datos de vulnerabilidades)
- Mínimo 8 GB de RAM disponible (Dependency-Track y DefectDojo son exigentes)
- Navegador web moderno

---

## Parte 1 — Preparación del Entorno (10 minutos)

### Paso 1.1: Verificar que el Lab 01 está corriendo

```bash
cd vulncorp-lab
docker compose ps
```

Todos los servicios del Lab 01 deben estar en estado "Up". Si no lo están, levántelos:

```bash
docker compose up -d
```

### Paso 1.2: Instalar herramientas y levantar plataformas del Lab 02

```bash
cd lab02-pipeline
chmod +x scripts/*.sh
./scripts/setup_lab02.sh
```

Este script instalará **Syft** y **Grype** en su sistema, y levantará **Dependency-Track** y **DefectDojo** como contenedores Docker.

### Paso 1.3: Esperar la inicialización

Las plataformas necesitan entre 3 y 5 minutos para inicializar completamente (especialmente en la primera ejecución). Verifique el estado:

```bash
docker compose ps
```

Cuando todos los servicios muestren estado "Up" o "running", continúe.

### Paso 1.3b: Obtener la contraseña de DefectDojo
DefectDojo genera una contraseña aleatoria para el usuario admin en la primera ejecución. El script `setup_lab02.sh` intenta capturarla automáticamente y guardarla en `data/.dd_admin_password`. Si no la capturó, obténgala manualmente:

```bash
docker logs vulncorp-dd-initializer 2>&1 | grep -i password
```

Anote la contraseña, la necesitará para acceder a la plataforma.

### Paso 1.4: Verificar acceso a las plataformas

| Plataforma | URL | Credenciales |
|------------|-----|-------------|
| Dependency-Track | http://localhost:8083 | admin / VulnCorp2026! (o admin/admin en primer login) |
| DefectDojo | http://localhost:8085 | admin / (contraseña del paso 1.3b) |

**Evidencia 1:** Tome una captura de pantalla del login exitoso en ambas plataformas.

---

## Parte 2 — Generación de SBOM con Syft (20 minutos)

### Conceptos previos

Un **SBOM (Software Bill of Materials)** es el equivalente digital de la lista de ingredientes de un producto alimenticio. Describe exactamente qué componentes de software contiene una aplicación, incluyendo versiones, licencias y orígenes.

**CycloneDX** es un estándar OWASP para representar SBOMs. Es el formato más adoptado en la industria para la seguridad de la cadena de suministro de software.

### Paso 2.1: Generar un SBOM individual (exploración manual)

Antes de ejecutar el script automatizado, generemos un SBOM manualmente para entender el proceso:

```bash
# Generar SBOM de la imagen de PrestaShop en formato CycloneDX JSON
syft prestashop/prestashop:1.7.8.0 -o cyclonedx-json > /tmp/prestashop_sbom.json

# Ver las primeras líneas del SBOM
head -50 /tmp/prestashop_sbom.json
```

### Paso 2.2: Analizar la estructura del CycloneDX

Abra el archivo de ejemplo anotado incluido en el laboratorio:

```bash
cat data/cyclonedx-examples/ejemplo_cyclonedx_anotado.json
```

Responda las siguientes preguntas en su informe:

1. ¿Qué campo identifica la versión del estándar CycloneDX utilizado?
2. ¿Qué es un PURL (Package URL) y por qué es importante?
3. ¿Cuál es la diferencia entre el campo `cpe` y el campo `purl`?
4. ¿Qué herramienta generó el SBOM según los metadatos?

### Paso 2.3: Comparar formatos de salida de Syft

```bash
# Formato tabla (legible por humanos)
syft prestashop/prestashop:1.7.8.0 -o table | head -30

# Formato CycloneDX XML (alternativo)
syft prestashop/prestashop:1.7.8.0 -o cyclonedx-xml | head -30

# Formato SPDX JSON (otro estándar, para comparación)
syft prestashop/prestashop:1.7.8.0 -o spdx-json | head -30
```

**Pregunta para el informe:** ¿Qué diferencias observa entre CycloneDX y SPDX? ¿Cuál le parece más legible? ¿Cuál tiene más información de seguridad?

### Paso 2.4: Generar SBOMs de toda la infraestructura

```bash
./scripts/generate_sbom.sh
```

Observe la tabla de resumen que muestra el script. Anote cuántos componentes tiene cada imagen.

**Evidencia 2:** Captura de pantalla de la tabla de resumen de SBOMs generados.

### Paso 2.5: Análisis de componentes

Usando Python o `jq`, analice el SBOM de PrestaShop:

```bash
# Contar componentes por tipo de paquete
python3 -c "
import json
with open('data/sbom/prestashop_sbom_cyclonedx.json') as f:
    data = json.load(f)
types = {}
for comp in data.get('components', []):
    purl = comp.get('purl', 'unknown')
    pkg_type = purl.split(':')[1].split('/')[0] if ':' in purl else 'unknown'
    types[pkg_type] = types.get(pkg_type, 0) + 1
for t, c in sorted(types.items(), key=lambda x: -x[1]):
    print(f'  {t}: {c} componentes')
"
```

**Pregunta para el informe:** ¿Qué tipos de paquetes encontró en PrestaShop? ¿Qué ecosistemas de software están representados (Debian, PHP/Composer, npm, etc.)?

---

## Parte 3 — Escaneo de Vulnerabilidades con Grype (15 minutos)

### Conceptos previos

**Grype** es un escáner de vulnerabilidades que toma un SBOM como entrada y cruza cada componente contra múltiples bases de datos de vulnerabilidades (NVD, GitHub Advisories, distribuciones Linux, etc.).

La diferencia clave entre Syft y Grype es:
- **Syft** responde: "¿Qué software hay instalado?" (inventario)
- **Grype** responde: "¿Qué vulnerabilidades tiene ese software?" (escaneo)

### Paso 3.1: Escanear manualmente un SBOM

```bash
# Escanear el SBOM de PrestaShop
grype sbom:data/sbom/prestashop_sbom_cyclonedx.json -o table | head -40
```

Observe la tabla de resultados. Cada fila muestra:
- **NAME**: Nombre del paquete vulnerable
- **INSTALLED**: Versión instalada
- **FIXED-IN**: Versión que corrige la vulnerabilidad
- **TYPE**: Tipo de paquete (deb, npm, composer, etc.)
- **VULNERABILITY**: ID del CVE
- **SEVERITY**: Severidad (Critical, High, Medium, Low, Negligible)

### Paso 3.2: Escanear toda la infraestructura

```bash
./scripts/scan_grype.sh
```

**Evidencia 3:** Captura de pantalla de la tabla de resumen de vulnerabilidades por servicio.

### Paso 3.3: Análisis comparativo

Responda en su informe:

1. ¿Qué servicio tiene más vulnerabilidades críticas? ¿Por qué cree que es así?
2. ¿Qué servicio tiene menos vulnerabilidades? ¿Qué relación tiene con la imagen base usada?
3. Si tuviera que priorizar la remediación de UN solo servicio, ¿cuál elegiría y por qué? Considere: exposición a internet, criticidad del dato, número de vulnerabilidades críticas.

### Paso 3.4: Investigar un CVE específico

Elija una vulnerabilidad CRITICAL del reporte de PrestaShop y busque información:

```bash
# Ver detalles de vulnerabilidades críticas
python3 -c "
import json
with open('data/grype/prestashop_grype_detail.json') as f:
    data = json.load(f)
for m in data.get('matches', []):
    vuln = m.get('vulnerability', {})
    if vuln.get('severity') == 'Critical':
        print(f\"CVE: {vuln.get('id')}\")
        print(f\"  Paquete: {m.get('artifact',{}).get('name')}\")
        print(f\"  Versión: {m.get('artifact',{}).get('version')}\")
        print(f\"  Fix:     {vuln.get('fix',{}).get('versions', ['No fix'])}\")
        print(f\"  URLs:    {vuln.get('urls', [])[:2]}\")
        print()
" | head -30
```

Visite la página del CVE en NVD (https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX) y responda:

1. ¿Cuál es el vector CVSS de esta vulnerabilidad?
2. ¿Tiene un CWE asociado? ¿Cuál es la debilidad raíz?
3. ¿Está en la lista KEV de CISA (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)?
4. ¿Cuál es su score EPSS (https://epss.cyentia.com)?

**Evidencia 4:** Captura de pantalla de la investigación del CVE en NVD.

---

## Parte 4 — Dependency-Track: Monitoreo de la Cadena de Suministro (20 minutos)

### Conceptos previos

**Dependency-Track** es una plataforma OWASP que consume SBOMs y monitorea continuamente los componentes de software contra nuevas vulnerabilidades. A diferencia de un escaneo puntual (Grype), Dependency-Track mantiene un inventario vivo y alerta cuando se descubren nuevos CVEs que afectan a los componentes ya registrados.

### Paso 4.1: Subir SBOMs a Dependency-Track

```bash
python3 scripts/upload_reports.py --dtrack-only
```

### Paso 4.2: Explorar la interfaz de Dependency-Track

Abra http://localhost:8083 en su navegador e inicie sesión.
   - Si el script `upload_reports.py` ya se ejecutó, la contraseña es **VulnCorp2026!**
   - Si es su primer acceso manual, use **admin/admin** y el sistema le pedirá cambiarla.

1. Vaya a **Projects**: Debería ver un proyecto por cada servicio de VulnCorp.
2. Haga clic en **VulnCorp PetaShop** (PrestaShop).
3. Explore las pestañas:
   - **Components**: Lista de todos los componentes del SBOM
   - **Vulnerabilities**: Vulnerabilidades detectadas automáticamente
   - **Policy Violations**: Violaciones de políticas (si las hay)
   - **Audit Trail**: Historial de cambios

**Evidencia 5:** Captura de pantalla del dashboard de Dependency-Track mostrando los proyectos de VulnCorp.

### Paso 4.3: Crear una política de seguridad

En Dependency-Track, vaya a **Administration > Policy Management** y cree una política:

1. Nombre: "VulnCorp - Componentes Críticos"
2. Condición: Severity = CRITICAL
3. Acción: FAIL (marcar como violación)

Aplique la política a todos los proyectos de VulnCorp.

**Pregunta para el informe:** ¿Cuántos proyectos violan esta política? ¿Qué utilidad tiene esto en un pipeline CI/CD real?

### Paso 4.4: Analizar métricas del portfolio

En el dashboard principal de Dependency-Track, observe:

1. **Portfolio Vulnerabilities**: Distribución de vulnerabilidades por severidad
2. **Vulnerable Components**: Porcentaje de componentes con vulnerabilidades conocidas
3. **Policy Violations**: Número de violaciones de política

**Evidencia 6:** Captura de pantalla de las métricas del portfolio en Dependency-Track.

---

## Parte 5 — DefectDojo: Gestión Centralizada de Vulnerabilidades (20 minutos)

### Conceptos previos

**DefectDojo** es una plataforma de gestión de vulnerabilidades que actúa como "fuente única de la verdad" (Single Source of Truth). Permite importar resultados de múltiples escáneres, deduplicar hallazgos, asignar responsables, hacer seguimiento de la remediación y generar métricas ejecutivas.

### Paso 5.1: Subir reportes de Grype a DefectDojo

```bash
python3 scripts/upload_reports.py --dojo-only
```

### Paso 5.2: Explorar DefectDojo

Abra http://localhost:8085 e inicie sesión (admin/VulnCorp2024!).

1. Vaya a **Products**: Verá un producto por cada servicio de VulnCorp.
2. Haga clic en un producto (ej: "VulnCorp - VulnCorp PetaShop").
3. Explore:
   - **Findings**: Lista de vulnerabilidades importadas
   - **Endpoints**: Componentes afectados
   - **Engagements**: Sesiones de escaneo

### Paso 5.3: Triaje de vulnerabilidades

En la lista de **Findings** de PetaShop:

1. Filtre por severidad **Critical**.
2. Seleccione una vulnerabilidad y revise sus detalles.
3. Cambie su estado:
   - Si es un falso positivo → marque como **False Positive**
   - Si es válida pero no aplica al contexto → marque como **Out of Scope**
   - Si es válida y debe remediarse → marque como **Active** y asígnele una fecha objetivo

**Evidencia 7:** Captura de pantalla mostrando al menos 3 findings con diferentes estados de triaje.

### Paso 5.4: Comparar productos por riesgo

En DefectDojo, vaya al dashboard principal y compare los productos:

1. ¿Cuál producto tiene más findings activos?
2. ¿Cuál tiene la mayor proporción de vulnerabilidades críticas?
3. ¿Cuál debería recibir atención primero considerando su exposición en la red?

**Pregunta para el informe:** Si usted fuera el CISO de VulnCorp y solo tuviera presupuesto para remediar 2 de los 7 servicios este trimestre, ¿cuáles elegiría y por qué? Justifique usando datos de DefectDojo, contexto de red (Lab 01) y criterios SSVC.

---

## Parte 6 — Reflexión y Entrega (5 minutos)

### Preguntas finales

1. **Pipeline vs. escaneo manual:** ¿Qué ventajas tiene el pipeline Syft → Grype → DTrack → DefectDojo frente a ejecutar un escáner manualmente?

2. **CycloneDX como lingua franca:** ¿Por qué es importante que todas las herramientas del pipeline usen el mismo formato (CycloneDX)?

3. **SBOM en la cadena de suministro:** Si VulnCorp recibiera un SBOM de un proveedor de software, ¿cómo lo usaría para evaluar el riesgo antes de instalar ese software?

4. **Conexión con MITRE:** ¿Cómo se relacionan los CVEs encontrados con las técnicas de ATT&CK? Busque al menos un CVE que tenga una técnica ATT&CK asociada en la NVD.

---

## Entregables

| # | Entregable | Formato |
|---|-----------|---------|
| 1 | Capturas de pantalla (Evidencias 1-7) | Imágenes PNG/JPG |
| 2 | Respuestas a todas las preguntas del laboratorio | Documento PDF o Markdown |
| 3 | Archivo SBOM CycloneDX de PrestaShop | JSON (generado por Syft) |
| 4 | Reporte de Grype de PrestaShop | JSON CycloneDX (generado por Grype) |
| 5 | Propuesta de priorización (Parte 5, Paso 5.4) | Tabla con justificación |

---

## Rúbrica de Evaluación

| Criterio | Excelente (5) | Bueno (4) | Suficiente (3) | Insuficiente (1-2) |
|----------|--------------|-----------|-----------------|-------------------|
| **Generación de SBOM** | Genera SBOMs de todas las imágenes, analiza estructura CycloneDX en profundidad | Genera SBOMs correctamente, análisis básico de estructura | Genera SBOMs pero no analiza la estructura | No logra generar SBOMs |
| **Escaneo con Grype** | Ejecuta escaneo completo, investiga CVEs en NVD/EPSS/KEV | Ejecuta escaneo, investiga al menos un CVE | Ejecuta escaneo pero no investiga CVEs | No logra ejecutar el escaneo |
| **Dependency-Track** | Sube SBOMs, crea políticas, analiza métricas del portfolio | Sube SBOMs y explora la interfaz | Sube SBOMs pero no explora funcionalidades | No logra subir SBOMs |
| **DefectDojo** | Importa scans, realiza triaje completo, compara productos | Importa scans y realiza triaje básico | Importa scans pero no realiza triaje | No logra importar scans |
| **Análisis y priorización** | Propuesta de priorización fundamentada con datos, contexto de red y criterios SSVC | Propuesta con datos pero sin contexto completo | Propuesta genérica sin datos específicos | Sin propuesta de priorización |
| **Calidad del informe** | Profesional, bien estructurado, con evidencias claras | Completo pero con formato mejorable | Incompleto pero con contenido correcto | Incompleto y con errores |

**Puntaje total:** 30 puntos (6 criterios x 5 puntos)

---

## Comandos de Referencia Rápida

```bash
# === SYFT (Generación de SBOM) ===
syft <imagen> -o cyclonedx-json          # SBOM en CycloneDX JSON
syft <imagen> -o cyclonedx-xml           # SBOM en CycloneDX XML
syft <imagen> -o spdx-json               # SBOM en SPDX JSON
syft <imagen> -o table                   # Tabla legible

# === GRYPE (Escaneo de vulnerabilidades) ===
grype <imagen>                           # Escaneo directo de imagen
grype sbom:<archivo.json>                # Escaneo desde SBOM
grype sbom:<archivo.json> -o json        # Salida JSON detallada
grype sbom:<archivo.json> -o cyclonedx-json  # Salida CycloneDX
grype db update                          # Actualizar base de datos

# === SCRIPTS DEL LAB 02 ===
./scripts/setup_lab02.sh                 # Setup inicial
./scripts/generate_sbom.sh               # Generar todos los SBOMs
./scripts/scan_grype.sh                  # Escanear con Grype
python3 scripts/upload_reports.py        # Subir a plataformas
python3 scripts/upload_reports.py --dtrack-only  # Solo Dependency-Track
python3 scripts/upload_reports.py --dojo-only    # Solo DefectDojo

# === GESTIÓN DEL LAB 02 ===
docker compose ps                        # Ver estado de servicios
docker compose logs -f dtrack-apiserver  # Ver logs de DTrack
docker compose down                      # Detener Lab 02
docker compose down -v                   # Detener y borrar datos
```

---

*Laboratorio diseñado por el Profesor MITRE VulnMaster para el curso de Gestión de Vulnerabilidades — 2026*
