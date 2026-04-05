# Guía del Instructor — Laboratorio 01: VulnCorp

## Gestión de Vulnerabilidades (MITRE) — Unidad 1

**Documento confidencial — Solo para el profesor**

---

## Preparación Pre-Clase

### Requisitos del aula

El instructor debe verificar antes de la clase que el aula cuente con conexión a Internet estable (para descargar imágenes Docker) y que los equipos de los estudiantes tengan Docker Desktop instalado. Se recomienda ejecutar `./scripts/setup.sh` en al menos un equipo de prueba el día anterior para validar que todas las imágenes se descargan correctamente.

### Tiempos sugeridos

| Fase | Actividad | Duración | Notas |
|------|-----------|----------|-------|
| 1 | Presentación del escenario y contexto | 10 min | Usar slides de la Unidad 1 |
| 2 | Setup del entorno (docker compose up) | 15 min | Los estudiantes siguen la guía |
| 3 | Reconocimiento y mapeo | 15 min | Trabajo individual |
| 4 | Escaneo con Trivy | 15 min | Esperar a que termine el escaneo |
| 5 | Exploración del dashboard y priorización | 25 min | Trabajo en parejas recomendado |
| 6 | Discusión grupal y cierre | 10 min | El instructor guía la reflexión |

### Puntos clave para enfatizar durante la clase

El instructor debe hacer énfasis en que la gestión de vulnerabilidades no es simplemente "parchear todo". La primera reacción de los estudiantes al ver cientos de vulnerabilidades será querer arreglarlas todas, y ese es precisamente el momento pedagógico más valioso. El instructor debe guiar la discusión hacia el concepto de que los recursos son finitos y que la priorización inteligente es la habilidad más valiosa de un profesional de ciberseguridad.

---

## Respuestas Esperadas

### Parte 2 — Reconocimiento

**Pregunta 1:** ¿Cuántos servicios están expuestos con puertos al host?

Tres servicios exponen puertos al host: Nginx en el puerto 8080 (proxy de la tienda), phpMyAdmin en el puerto 8081 (administración de BD), y el Dashboard en el puerto 3000 (herramienta de gestión). El punto crítico es que phpMyAdmin no debería estar expuesto, ya que da acceso directo a la base de datos de producción.

**Pregunta 2:** ¿Qué servicio actúa como puente entre las dos redes?

MariaDB (vulncorp-mariadb) está conectado tanto a `prod_network` (172.20.0.30) como a `corp_network` (172.21.0.30). Esto permite que phpMyAdmin desde la red corporativa acceda directamente a los datos de producción, creando un vector de movimiento lateral.

**Pregunta 3:** ¿Por qué es peligroso que phpMyAdmin acceda con credenciales root?

Porque las credenciales root permiten acceso total a la base de datos, incluyendo la capacidad de leer, modificar o eliminar todos los datos de clientes, transacciones y configuración de la tienda. Si un atacante compromete phpMyAdmin (que tiene CVEs conocidos), obtiene acceso completo a los datos más sensibles de la empresa. Esto viola el principio de mínimo privilegio.

**Pregunta 4:** ¿El servidor FTP cifra las comunicaciones?

No. vsftpd en su configuración por defecto transmite credenciales y datos en texto plano. Cualquier persona con acceso a la red corporativa podría capturar las credenciales mediante sniffing. La alternativa segura sería SFTP o FTPS.

### Parte 4 — Priorización (Respuestas modelo)

A continuación se presenta un ejemplo de cómo debería lucir una priorización bien justificada. Los CVEs específicos variarán según la fecha del escaneo, pero la lógica debe ser similar.

**Ejemplo de decisión P1 (Inmediata):** Una vulnerabilidad CRITICAL en Nginx que permita ejecución remota de código (RCE) debe ser P1 porque Nginx es el servicio directamente expuesto a Internet. Un atacante externo podría explotarla sin autenticación. Si además está en el catálogo KEV de CISA, la urgencia es máxima.

**Ejemplo de decisión P3 (Planificada):** Una vulnerabilidad HIGH en Redis que requiera acceso a la red interna para ser explotada puede ser P3 porque Redis no está expuesto al exterior y el atacante necesitaría primero comprometer otro servicio. El riesgo existe pero no es inmediato.

**Ejemplo de decisión P4 (Aceptar riesgo):** Una vulnerabilidad MEDIUM en la workstation Ubuntu que afecte a un paquete no utilizado puede ser P4 porque el impacto es mínimo, la workstation no contiene datos sensibles y el costo de actualizar todo el sistema operativo supera el beneficio.

### Parte 5 — Propuesta Arquitectónica (Solución modelo)

Los tres cambios arquitectónicos más impactantes que los estudiantes deberían identificar son los siguientes.

**Cambio 1: Eliminar phpMyAdmin y reemplazarlo con acceso seguro.** En lugar de exponer phpMyAdmin con credenciales root, se debería usar un túnel SSH o una VPN para que los administradores accedan a MariaDB solo cuando sea necesario, con credenciales de solo lectura para consultas y credenciales limitadas para operaciones específicas. Este cambio elimina de golpe todas las vulnerabilidades de phpMyAdmin y reduce drásticamente el riesgo de acceso no autorizado a la base de datos. Costo: bajo. Tiempo: 1 día.

**Cambio 2: Separar MariaDB de la red corporativa.** MariaDB no debería estar en ambas redes. Si los empleados necesitan consultar datos, se debería crear una API intermedia o una réplica de solo lectura en la red corporativa. Esto elimina el vector de movimiento lateral. Costo: medio. Tiempo: 1 semana.

**Cambio 3: Agregar headers de seguridad y WAF al Nginx.** Configurar X-Frame-Options, Content-Security-Policy, HSTS y un WAF básico (como ModSecurity) en el proxy inverso. Esto mitiga múltiples vectores de ataque web sin necesidad de parchear PrestaShop. Costo: bajo. Tiempo: 2 horas.

---

## Errores Comunes de los Estudiantes

El error más frecuente es priorizar exclusivamente por score CVSS sin considerar el contexto. Un estudiante que asigne P1 a todas las vulnerabilidades CRITICAL sin importar si el servicio está expuesto a Internet o no, demuestra que no ha comprendido el concepto central de la clase.

Otro error común es proponer "actualizar todo" como solución sin considerar el impacto en la disponibilidad del servicio. Actualizar MariaDB de 10.5 a 11.x puede romper la aplicación PrestaShop y requiere testing extensivo, lo cual no siempre es viable en el corto plazo.

---

## Extensiones Opcionales

Para grupos avanzados o sesiones de 120 minutos, el instructor puede agregar las siguientes actividades.

Se puede pedir a los estudiantes que ejecuten `docker exec -it vulncorp-workstation bash` y desde ahí intenten conectarse a MariaDB con `mysql -h mariadb-prod -u root -pR00tVulnCorp!` para demostrar en vivo cómo el movimiento lateral es posible gracias a la arquitectura actual.

También se puede introducir el concepto de SBOM (Software Bill of Materials) ejecutando `trivy image --format cyclonedx prestashop/prestashop:1.7.8.0` para generar un inventario completo de componentes de software.

---

*Documento confidencial para uso exclusivo del instructor — MAR303 — 2026*
