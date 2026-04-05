# Lab 02 — Guía del Instructor (CONFIDENCIAL)

## Pipeline Profesional de Gestión de Vulnerabilidades

**Documento confidencial — No distribuir a los estudiantes**

---

## Resumen Ejecutivo

Este laboratorio introduce a los estudiantes en el pipeline profesional de gestión de vulnerabilidades: SBOM (Syft) → Escaneo (Grype) → Monitoreo de Supply Chain (Dependency-Track) → Gestión centralizada (DefectDojo). El objetivo pedagógico principal es que comprendan que la gestión de vulnerabilidades no es un evento puntual sino un proceso continuo y automatizable.

---

## Distribución de Tiempos Sugerida (90 minutos)

| Fase | Tiempo | Actividad del Profesor |
|------|--------|----------------------|
| Preparación | 10 min | Verificar que el Lab 01 funciona. Circular mientras los estudiantes ejecutan `setup_lab02.sh`. Aprovechar el tiempo de descarga para explicar la arquitectura del pipeline. |
| SBOM con Syft | 20 min | Demostrar en vivo la generación de un SBOM. Abrir el JSON y explicar cada sección. Hacer énfasis en PURL como identificador universal. |
| Escaneo con Grype | 15 min | Ejecutar el escaneo en vivo. Mostrar cómo Grype cruza componentes contra NVD. Destacar la diferencia entre "tener un componente" y "tener una vulnerabilidad". |
| Dependency-Track | 20 min | Demostrar la subida de SBOMs. Navegar la interfaz. Crear una política en vivo. Explicar el concepto de monitoreo continuo. |
| DefectDojo | 20 min | Importar scans. Demostrar el triaje. Mostrar cómo se asignan findings a equipos. Explicar métricas ejecutivas. |
| Reflexión | 5 min | Discusión grupal sobre priorización. Conectar con MITRE ATT&CK. |

---

## Prerequisitos Técnicos

Antes de la clase, el instructor debe verificar que tiene al menos **8 GB de RAM disponible** para ejecutar Dependency-Track y DefectDojo simultáneamente. En máquinas con 16 GB, se recomienda cerrar aplicaciones innecesarias. Si la máquina del instructor tiene limitaciones, se puede ejecutar solo una plataforma a la vez usando los flags `--dtrack-only` o `--dojo-only`.

---

## Respuestas Esperadas a las Preguntas del Lab

### Parte 2 — Análisis de CycloneDX

**Pregunta: ¿Qué campo identifica la versión del estándar?**
Respuesta esperada: El campo `specVersion`. Actualmente la versión estable más reciente es 1.5 (1.6 está en desarrollo). Es importante porque determina qué campos están disponibles en el esquema.

**Pregunta: ¿Qué es un PURL?**
Respuesta esperada: Package URL es un esquema estandarizado para identificar paquetes de software de forma universal. Estructura: `pkg:tipo/namespace/nombre@version?qualifiers#subpath`. Ejemplo: `pkg:deb/debian/openssl@1.1.1n`. Es importante porque permite identificar el mismo paquete independientemente de la herramienta o base de datos que lo reporte.

**Pregunta: Diferencia entre CPE y PURL**
Respuesta esperada: CPE (Common Platform Enumeration) es un estándar del NIST usado principalmente por NVD para identificar productos. PURL es un estándar más moderno y específico para paquetes de software. CPE identifica "productos" de forma genérica; PURL identifica "paquetes" de forma precisa incluyendo el ecosistema (npm, pip, deb, etc.).

**Pregunta: CycloneDX vs SPDX**
Respuesta esperada: CycloneDX (OWASP) está más orientado a seguridad y tiene soporte nativo para vulnerabilidades, servicios y dependencias. SPDX (Linux Foundation) está más orientado a licencias y cumplimiento legal. CycloneDX es más compacto y fácil de parsear. Ambos son válidos, pero CycloneDX es el preferido en contextos de seguridad.

### Parte 3 — Análisis de Grype

**Pregunta: ¿Qué servicio tiene más vulnerabilidades críticas?**
Respuesta esperada: Generalmente PrestaShop (por ser la imagen más grande con más componentes: PHP, Apache, librerías del SO) o MariaDB (por usar una versión antigua). El instructor debe verificar los resultados reales del escaneo antes de la clase.

**Pregunta: ¿Qué servicio tiene menos vulnerabilidades?**
Respuesta esperada: Generalmente Redis (imagen pequeña, basada en Alpine/Debian slim) o el FTP server (Alpine Linux minimal). Las imágenes más pequeñas tienen menos superficie de ataque.

**Pregunta: Priorización de un servicio**
Respuesta esperada: La mejor respuesta prioriza PrestaShop o Nginx porque están expuestos a internet (red de producción, accesibles desde el exterior). Aunque MariaDB pueda tener más CVEs, está en una red interna y no es directamente accesible. El contexto de exposición es más importante que el número bruto de vulnerabilidades. Esto conecta directamente con el concepto de SSVC (Stakeholder-Specific Vulnerability Categorization).

### Parte 4 — Dependency-Track

**Pregunta: ¿Cuántos proyectos violan la política de severidad CRITICAL?**
Respuesta esperada: Probablemente todos o casi todos los proyectos violarán la política, lo cual demuestra que una política de "cero vulnerabilidades críticas" es poco realista en software legacy. Esto abre la discusión sobre la necesidad de políticas contextualizadas.

**Utilidad en CI/CD:** En un pipeline CI/CD real, Dependency-Track puede actuar como "quality gate": si un build introduce un componente con vulnerabilidades críticas, el pipeline se detiene automáticamente. Esto se llama "shift left" en seguridad.

### Parte 5 — DefectDojo y Priorización

**Pregunta: Si fuera CISO y solo pudiera remediar 2 servicios...**

Respuesta modelo (excelente):

> "Priorizaría **PrestaShop** y **Nginx Proxy** por las siguientes razones:
>
> 1. **Exposición**: Ambos están en la red de producción y son accesibles desde internet, lo que los convierte en el vector de ataque más probable.
> 2. **Criticidad del dato**: PrestaShop maneja datos de clientes (PII) y transacciones financieras (PCI-DSS). Una brecha aquí tiene impacto regulatorio y reputacional.
> 3. **Datos de DefectDojo**: PrestaShop tiene X findings críticos activos, de los cuales Y tienen fix disponible (remediación viable).
> 4. **SSVC**: Usando el framework SSVC, ambos servicios califican como 'Attend' o 'Act' por su exposición pública y la automatización de exploits disponible.
> 5. **Costo-beneficio**: Actualizar Nginx es relativamente simple (cambio de imagen Docker). PrestaShop requiere más esfuerzo pero el impacto de no hacerlo es mayor.
>
> Los servicios internos (phpMyAdmin, workstation, FTP) pueden esperar al siguiente trimestre, pero recomendaría eliminar phpMyAdmin completamente y reemplazarlo con acceso CLI seguro."

### Parte 6 — Reflexión

**Pipeline vs. escaneo manual:**
Respuesta esperada: Repetibilidad, automatización en CI/CD, historial de cambios, deduplicación de hallazgos, métricas de tendencia, asignación de responsables, integración con ticketing.

**CycloneDX como lingua franca:**
Respuesta esperada: Permite que herramientas de diferentes fabricantes se comuniquen sin pérdida de información. Un SBOM generado por Syft puede ser consumido por Grype, Dependency-Track, DefectDojo o cualquier otra herramienta compatible. Esto evita el "vendor lock-in".

---

## Errores Comunes de los Estudiantes

1. **No esperar la inicialización**: Dependency-Track y DefectDojo necesitan 3-5 minutos para inicializar. Los estudiantes impacientes intentan acceder antes y creen que está roto.

2. **Confundir SBOM con reporte de vulnerabilidades**: El SBOM es un inventario (Syft). El reporte de vulnerabilidades es el resultado de escanear ese inventario (Grype). Son documentos diferentes aunque ambos pueden estar en formato CycloneDX.

3. **Priorizar solo por CVSS**: Muchos estudiantes priorizarán por número de vulnerabilidades o por CVSS score sin considerar el contexto (exposición, criticidad del activo, explotabilidad real). Esto es una oportunidad para introducir EPSS, KEV y SSVC.

4. **No entender la deduplicación**: DefectDojo deduplica findings automáticamente. Si un estudiante importa el mismo scan dos veces, no verá el doble de findings. Esto es una feature, no un bug.

5. **Problemas de memoria**: En máquinas con 8 GB de RAM, ejecutar Lab 01 + Lab 02 simultáneamente puede ser ajustado. Si hay problemas, sugerir detener los servicios del Lab 01 que no se necesitan (FTP, workstation).

---

## Puntos de Conexión con Otros Módulos del Curso

| Concepto del Lab 02 | Conexión con el Curso |
|---------------------|----------------------|
| SBOM / CycloneDX | Módulo de Inventario y Contexto (SBOM, VEX/OpenVEX, CycloneDX/SPDX) |
| Grype + CVEs | Módulo de Taxonomías (CVE, CWE, CVSS v4.0, CAPEC, NVD) |
| Dependency-Track | Módulo de Priorización Moderna (CVSS vs EPSS, KEV, SSVC) |
| DefectDojo triaje | Módulo de Flujo Completo de Remediación + Métricas |
| Pipeline automatizado | Módulo de Secure Software Delivery (SSDF) |
| Políticas de DTrack | Módulo de Scoping y Reglas del Juego |

---

## Preparación Pre-Clase

1. Ejecutar el Lab 02 completo al menos una vez antes de la clase.
2. Anotar los números reales de vulnerabilidades para cada servicio (varían según la fecha por actualizaciones de la base de datos de Grype).
3. Verificar que Dependency-Track sincroniza correctamente con NVD (puede tomar hasta 24 horas en la primera ejecución).
4. Preparar un CVE específico para la demostración en vivo (elegir uno que esté en KEV y tenga EPSS alto).
5. Tener abierta la página de EPSS (https://epss.cyentia.com) y KEV (https://www.cisa.gov/known-exploited-vulnerabilities-catalog) para consultas en vivo.

---

*Guía del instructor — Profesor MITRE VulnMaster — 2026*
