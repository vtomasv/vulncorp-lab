# Laboratorio 01 — VulnCorp: Anatomía de la Superficie de Ataque

## Gestión de Vulnerabilidades (MITRE) — Unidad 1

**Curso:** MAR303 — Universidad Mayor — 2026  
**Profesor:** Tomás Vera  
**Duración estimada:** 90 minutos  
**Nivel:** Introductorio-Intermedio

---

## Objetivos de Aprendizaje

Al completar este laboratorio, el estudiante será capaz de:

1. Identificar y mapear la **superficie de ataque** de una infraestructura empresarial típica.
2. Ejecutar un **escáner de vulnerabilidades** (Trivy) contra imágenes de contenedores en producción.
3. Interpretar reportes de vulnerabilidades diferenciando entre **severidad (CVSS)** y **prioridad operativa**.
4. Aplicar criterios de **contexto empresarial** (exposición, criticidad del activo, datos sensibles) para priorizar la remediación.
5. Comprender cómo las **decisiones arquitectónicas** impactan tanto en la seguridad como en los recursos necesarios para remediar.
6. Registrar y justificar decisiones de priorización en un dashboard de gestión.

---

## Escenario

Usted acaba de ser contratado como el primer **Analista de Ciberseguridad** de **VulnCorp**, una empresa mediana de comercio electrónico que opera la tienda online **PetaShop** (venta de productos para mascotas).

La empresa nunca ha tenido un programa formal de gestión de vulnerabilidades. Su infraestructura fue montada por el equipo de desarrollo hace tres años y "funciona bien" según el CTO. El CEO le ha dado a usted un presupuesto limitado y le pide un informe en 48 horas con las vulnerabilidades más urgentes y un plan de acción realista.

La infraestructura de VulnCorp tiene dos redes principales:

| Red | Subred | Propósito | Servicios |
|-----|--------|-----------|-----------|
| Producción | 172.20.0.0/24 | E-commerce público | Nginx (proxy), PrestaShop (tienda), MySQL (BD), Redis (caché) |
| Corporativa | 172.21.0.0/24 | Operaciones internas | phpMyAdmin (admin BD), Workstation (soporte), FTP (archivos) |

**Punto crítico:** La base de datos MySQL está conectada a **ambas redes**, y phpMyAdmin accede con credenciales de root desde la red corporativa.

---

## Material Necesario

Antes de comenzar, asegúrese de tener instalado en su equipo:

- **Docker Desktop** (v24+) o Docker Engine + Docker Compose (v2+)
- **Git** para clonar el repositorio
- Un **navegador web** moderno (Chrome, Firefox, Edge)
- **Terminal** (bash, zsh, PowerShell)
- Al menos **8 GB de RAM** disponibles y **10 GB de disco**

---

## Parte 1 — Levantamiento del Entorno (15 minutos)

### Paso 1.1: Clonar el repositorio

```bash
git clone https://github.com/vtomasv/vulncorp-lab.git
cd vulncorp-lab
```

### Paso 1.2: Ejecutar el setup inicial

```bash
chmod +x scripts/setup.sh scripts/scan.sh
./scripts/setup.sh
```

Este script instalará Trivy (escáner de vulnerabilidades) y descargará las imágenes Docker necesarias.

### Paso 1.3: Levantar la infraestructura

```bash
docker compose up -d
```

Espere aproximadamente 2-3 minutos a que todos los servicios estén operativos. Verifique con:

```bash
docker compose ps
```

Todos los servicios deben mostrar estado "running" o "Up".

### Paso 1.4: Verificar acceso a los servicios

Abra en su navegador:

| Servicio | URL | Descripción |
|----------|-----|-------------|
| PetaShop (tienda) | http://localhost:8080 | Comercio electrónico público |
| phpMyAdmin | http://localhost:8081 | Administración de base de datos |
| Dashboard | http://localhost:3000 | Dashboard de vulnerabilidades |

**Evidencia 1:** Tome una captura de pantalla de cada servicio funcionando.

---

## Parte 2 — Reconocimiento y Mapeo de Superficie de Ataque (15 minutos)

Antes de escanear vulnerabilidades, un buen analista primero **entiende qué tiene**.

### Paso 2.1: Inventario de activos

Ejecute los siguientes comandos y documente los resultados:

```bash
# Ver todos los contenedores y sus imágenes
docker compose ps --format "table {{.Name}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"

# Ver las redes creadas
docker network ls | grep vulncorp

# Inspeccionar qué contenedores están en cada red
docker network inspect vulncorp-lab_prod_network --format '{{range .Containers}}{{.Name}} ({{.IPv4Address}}){{"\n"}}{{end}}'
docker network inspect vulncorp-lab_corp_network --format '{{range .Containers}}{{.Name}} ({{.IPv4Address}}){{"\n"}}{{end}}'
```

### Paso 2.2: Identificar puntos de exposición

Responda las siguientes preguntas en su informe:

1. **¿Cuántos servicios están expuestos con puertos al host?** (Pista: revise la columna "Ports")
2. **¿Qué servicio actúa como puente entre las dos redes?** (Pista: busque el que aparece en ambas redes)
3. **¿Por qué es peligroso que phpMyAdmin acceda con credenciales root?**
4. **¿El servidor FTP cifra las comunicaciones?**

### Paso 2.3: Diagrama de superficie de ataque

Dibuje (a mano o con una herramienta) un diagrama que muestre:
- Las dos redes y sus servicios
- Los puertos expuestos al exterior
- Las conexiones entre redes
- Los flujos de datos sensibles (credenciales, datos de clientes)

**Evidencia 2:** Diagrama de superficie de ataque con anotaciones.

---

## Parte 3 — Escaneo de Vulnerabilidades (20 minutos)

### Paso 3.1: Ejecutar el escaneo completo

```bash
./scripts/scan.sh
```

Este script ejecutará Trivy contra cada imagen Docker del laboratorio y generará reportes JSON en el directorio `data/`.

**Nota:** El primer escaneo puede tomar 5-10 minutos mientras Trivy descarga su base de datos de vulnerabilidades.

### Paso 3.2: Revisar el resumen en terminal

Observe la tabla de resumen que muestra el script. Anote:
- Total de vulnerabilidades encontradas
- Distribución por severidad (CRITICAL, HIGH, MEDIUM, LOW)
- Qué servicio tiene más vulnerabilidades críticas

### Paso 3.3: Explorar el Dashboard

Abra http://localhost:3000 y explore las siguientes secciones:

1. **Resumen Ejecutivo:** Observe los KPIs y gráficos de distribución.
2. **Mapa de Red:** Identifique visualmente qué zonas tienen más riesgo.
3. **Vulnerabilidades:** Use los filtros para explorar las CVEs encontradas.

**Evidencia 3:** Captura del dashboard mostrando el resumen ejecutivo con los KPIs.

---

## Parte 4 — El Dilema de la Priorización (25 minutos)

Esta es la parte más importante del laboratorio. Aquí aprenderá que **severidad no es igual a prioridad**.

### Paso 4.1: El error del novato

Imagine que decide remediar **todas** las vulnerabilidades CRITICAL y HIGH. Cuente cuántas son en total.

Ahora considere:
- Actualizar cada paquete requiere testing, ventana de mantenimiento y posible downtime.
- El equipo de TI tiene 2 personas y el negocio no puede parar más de 2 horas al mes.
- Cada actualización de componente mayor (ej: MySQL 5.7 a 8.0) puede romper la aplicación.

**Pregunta clave:** ¿Es viable remediar todo? ¿Qué pasa si intenta hacerlo?

### Paso 4.2: Priorización con contexto

Ahora aplique los siguientes criterios para priorizar de forma inteligente:

| Criterio | Pregunta clave | Peso |
|----------|---------------|------|
| **Exposición** | ¿El servicio es accesible desde Internet? | Alto |
| **Explotabilidad** | ¿Existe un exploit público? ¿Está en el KEV de CISA? | Alto |
| **Datos en riesgo** | ¿Qué datos se comprometen? ¿PII? ¿Financieros? | Alto |
| **Criticidad del activo** | ¿Qué pasa si este servicio cae? | Medio |
| **Fix disponible** | ¿Hay parche? ¿Es fácil de aplicar? | Medio |
| **Costo de remediación** | ¿Actualizar rompe algo? ¿Cuánto tiempo toma? | Medio |

### Paso 4.3: Investigar CVEs específicos

Seleccione **5 vulnerabilidades** (al menos 2 CRITICAL y 1 de cada otro nivel) y para cada una investigue en:

- **NVD:** https://nvd.nist.gov/vuln/detail/{CVE-ID}
- **EPSS:** https://epss.cyentia.com/ (probabilidad de explotación en 30 días)
- **KEV:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog (¿está siendo explotada activamente?)

### Paso 4.4: Registrar decisiones en el Dashboard

Vaya a la pestaña **"Priorización"** en el dashboard (http://localhost:3000) y registre sus 5 decisiones con:

- CVE ID
- Servicio afectado
- Prioridad asignada (P1 a P5)
- Costo estimado de remediación
- Justificación detallada

**Evidencia 4:** Exportar las decisiones desde el dashboard (botón "Exportar Decisiones").

---

## Parte 5 — Análisis Arquitectónico (15 minutos)

### Paso 5.1: Identificar el error arquitectónico principal

Responda: ¿Cuál es el mayor riesgo de la arquitectura actual de VulnCorp? (Pista: piense en el acceso de phpMyAdmin a la base de datos de producción con credenciales root desde la red corporativa).

### Paso 5.2: Propuesta de mejora arquitectónica

Proponga al menos **3 cambios arquitectónicos** que reduzcan la superficie de ataque sin necesidad de parchear cada CVE individual. Ejemplos de categorías:

- Segmentación de red
- Principio de mínimo privilegio
- Eliminación de servicios innecesarios
- Cifrado de comunicaciones
- Controles de acceso

### Paso 5.3: Cálculo de impacto

Para cada cambio propuesto, estime:
- ¿Cuántas vulnerabilidades dejan de ser explotables con este cambio?
- ¿Cuál es el costo aproximado (bajo/medio/alto)?
- ¿Cuánto tiempo tomaría implementarlo?

**Evidencia 5:** Tabla comparativa de cambios arquitectónicos con análisis costo-beneficio.

---

## Entregables

El estudiante debe entregar un **informe en formato PDF o Markdown** que contenga:

| N.° | Entregable | Descripción |
|-----|-----------|-------------|
| 1 | Capturas de pantalla | Servicios funcionando (PetaShop, phpMyAdmin, Dashboard) |
| 2 | Diagrama de superficie de ataque | Mapa de redes, servicios, exposición y flujos de datos |
| 3 | Dashboard con KPIs | Captura del resumen ejecutivo post-escaneo |
| 4 | Análisis de 5 CVEs | Investigación con NVD, EPSS, KEV para cada uno |
| 5 | Decisiones de priorización | Archivo JSON exportado del dashboard |
| 6 | Propuesta arquitectónica | 3 cambios con análisis costo-beneficio |
| 7 | Reflexión final | Párrafo respondiendo: "¿Por qué la gestión de vulnerabilidades es más que solo parchear?" |

---

## Rúbrica de Evaluación

| Criterio | Excelente (5) | Bueno (4) | Suficiente (3) | Insuficiente (1-2) | Peso |
|----------|--------------|-----------|-----------------|-------------------|------|
| Inventario y mapeo | Diagrama completo con todos los servicios, redes, puertos y flujos | Diagrama con la mayoría de elementos | Diagrama básico | Incompleto o ausente | 15% |
| Escaneo y dashboard | Escaneo exitoso, dashboard funcional, KPIs documentados | Escaneo exitoso con documentación parcial | Solo ejecutó el escaneo | No logró ejecutar | 15% |
| Análisis de CVEs | 5 CVEs con NVD+EPSS+KEV, análisis profundo | 5 CVEs con al menos NVD | 3-4 CVEs analizados | Menos de 3 CVEs | 20% |
| Priorización | Decisiones justificadas con múltiples criterios, coherentes | Decisiones justificadas pero con criterios limitados | Decisiones sin justificación sólida | Sin decisiones registradas | 25% |
| Propuesta arquitectónica | 3+ cambios con análisis costo-beneficio detallado | 3 cambios con análisis básico | 1-2 cambios propuestos | Sin propuesta | 15% |
| Reflexión y redacción | Reflexión profunda, bien redactada, con referencias | Reflexión adecuada | Reflexión superficial | Ausente | 10% |

**Nota mínima de aprobación:** 60% (3.6 sobre 5.0)

---

## Limpieza del Entorno

Al finalizar el laboratorio, detenga y elimine los contenedores:

```bash
docker compose down -v
```

El flag `-v` eliminará también los volúmenes de datos (base de datos MySQL).

---

## Referencias

- MITRE ATT&CK: https://attack.mitre.org/
- NVD (National Vulnerability Database): https://nvd.nist.gov/
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- EPSS (Exploit Prediction Scoring System): https://www.first.org/epss/
- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
- Trivy Documentation: https://trivy.dev/
- SSVC (Stakeholder-Specific Vulnerability Categorization): https://www.cisa.gov/ssvc

---

*Laboratorio diseñado para el curso MAR303 — Gestión de Vulnerabilidades (MITRE) — Universidad Mayor — 2026*
