/**
 * VulnCorp — Dashboard de Gestión de Vulnerabilidades
 * Curso: Gestión de Vulnerabilidades con Enfoque MITRE — 2026
 * 
 * Servidor Express que sirve el dashboard y la API de datos.
 * Compatible con Linux, macOS y Windows (Docker Desktop).
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// ─── Directorio de datos ────────────────────────────────────────────────────
// Dentro del contenedor Docker siempre es /app/data (montado como volumen).
// Fuera de Docker (desarrollo local), usar ./data relativo al script.
const DATA_DIR = fs.existsSync('/app/data') ? '/app/data' : path.join(__dirname, '..', 'data');

console.log(`[VulnCorp] Directorio de datos: ${DATA_DIR}`);
console.log(`[VulnCorp] Directorio existe: ${fs.existsSync(DATA_DIR)}`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Utilidades ─────────────────────────────────────────────────────────────

/**
 * Lee un archivo JSON de forma robusta, manejando:
 * - BOM (Byte Order Mark) de Windows (EF BB BF)
 * - Line endings CRLF (\r\n) de Windows
 * - Codificación UTF-8
 */
function readJsonSafe(filePath) {
    try {
        let content = fs.readFileSync(filePath, 'utf8');
        
        // Eliminar BOM UTF-8 si existe (común en archivos generados en Windows)
        if (content.charCodeAt(0) === 0xFEFF) {
            content = content.substring(1);
        }
        // También eliminar BOM como bytes (EF BB BF en UTF-8 puede aparecer como \uFEFF)
        content = content.replace(/^\uFEFF/, '');
        
        // Normalizar line endings (CRLF -> LF)
        content = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        
        // Eliminar caracteres nulos que a veces aparecen en Windows
        content = content.replace(/\0/g, '');
        
        // Trim whitespace
        content = content.trim();
        
        if (!content) {
            console.warn(`[VulnCorp] Archivo vacío: ${filePath}`);
            return null;
        }
        
        return JSON.parse(content);
    } catch (err) {
        console.error(`[VulnCorp] Error leyendo ${filePath}: ${err.message}`);
        // Intentar leer los primeros bytes para diagnóstico
        try {
            const buf = fs.readFileSync(filePath);
            const hex = buf.slice(0, 20).toString('hex').match(/.{2}/g).join(' ');
            console.error(`[VulnCorp] Primeros bytes (hex): ${hex}`);
        } catch (e) {
            // Ignorar error de diagnóstico
        }
        return null;
    }
}

/**
 * Lista archivos en el directorio de datos de forma segura.
 */
function listDataFiles(suffix) {
    try {
        if (!fs.existsSync(DATA_DIR)) {
            console.warn(`[VulnCorp] Directorio de datos no existe: ${DATA_DIR}`);
            return [];
        }
        const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith(suffix));
        console.log(`[VulnCorp] Archivos encontrados (*${suffix}): ${files.length} -> [${files.join(', ')}]`);
        return files;
    } catch (err) {
        console.error(`[VulnCorp] Error listando archivos: ${err.message}`);
        return [];
    }
}

// ─── API: Reporte consolidado ───────────────────────────────────────────────
app.get('/api/report', (req, res) => {
    const reportPath = path.join(DATA_DIR, 'consolidated_report.json');
    console.log(`[VulnCorp] GET /api/report -> ${reportPath} (existe: ${fs.existsSync(reportPath)})`);
    
    if (fs.existsSync(reportPath)) {
        const data = readJsonSafe(reportPath);
        if (data) {
            return res.json(data);
        }
    }
    
    // Si no hay reporte consolidado, intentar construirlo desde los archivos individuales
    const trivyFiles = listDataFiles('_trivy.json');
    if (trivyFiles.length > 0) {
        console.log(`[VulnCorp] No hay reporte consolidado, construyendo desde ${trivyFiles.length} archivos Trivy...`);
        const services = [];
        let totalC = 0, totalH = 0, totalM = 0, totalL = 0;
        
        trivyFiles.forEach(file => {
            const serviceName = file.replace('_trivy.json', '');
            const filePath = path.join(DATA_DIR, file);
            const data = readJsonSafe(filePath);
            if (!data) return;
            
            let critical = 0, high = 0, medium = 0, low = 0;
            (data.Results || []).forEach(result => {
                (result.Vulnerabilities || []).forEach(vuln => {
                    switch (vuln.Severity) {
                        case 'CRITICAL': critical++; break;
                        case 'HIGH': high++; break;
                        case 'MEDIUM': medium++; break;
                        case 'LOW': low++; break;
                    }
                });
            });
            
            const total = critical + high + medium + low;
            services.push({
                service: serviceName,
                image: serviceName,
                zone: 'desconocida',
                exposure: 'desconocida',
                criticality: 'desconocida',
                critical, high, medium, low, total,
                timestamp: new Date().toISOString()
            });
            totalC += critical;
            totalH += high;
            totalM += medium;
            totalL += low;
        });
        
        return res.json({
            scan_timestamp: new Date().toISOString(),
            total_services: services.length,
            total_vulnerabilities: totalC + totalH + totalM + totalL,
            by_severity: { critical: totalC, high: totalH, medium: totalM, low: totalL },
            services: services,
            note: "Reporte generado dinámicamente desde archivos individuales"
        });
    }
    
    res.json({
        scan_timestamp: null,
        total_services: 0,
        total_vulnerabilities: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
        services: [],
        message: "No se han ejecutado escaneos aún. Ejecute: ./scripts/scan.sh"
    });
});

// ─── API: Detalle de un servicio ────────────────────────────────────────────
app.get('/api/service/:name', (req, res) => {
    const serviceName = req.params.name;
    const reportPath = path.join(DATA_DIR, `${serviceName}_trivy.json`);
    console.log(`[VulnCorp] GET /api/service/${serviceName} -> ${reportPath} (existe: ${fs.existsSync(reportPath)})`);
    
    if (fs.existsSync(reportPath)) {
        const data = readJsonSafe(reportPath);
        if (data) {
            return res.json(data);
        }
        return res.status(500).json({ error: `Error leyendo reporte de: ${serviceName}` });
    }
    res.status(404).json({ error: `Reporte no encontrado para: ${serviceName}` });
});

// ─── API: Listar servicios disponibles ──────────────────────────────────────
app.get('/api/services', (req, res) => {
    const files = listDataFiles('_trivy.json');
    const services = files.map(f => f.replace('_trivy.json', ''));
    res.json(services);
});

// ─── API: Vulnerabilidades con filtros ──────────────────────────────────────
app.get('/api/vulnerabilities', (req, res) => {
    const { severity, service, fixable } = req.query;
    const files = listDataFiles('_trivy.json');
    let allVulns = [];

    files.forEach(file => {
        const serviceName = file.replace('_trivy.json', '');
        if (service && serviceName !== service) return;

        const data = readJsonSafe(path.join(DATA_DIR, file));
        if (!data) return;
        
        (data.Results || []).forEach(result => {
            (result.Vulnerabilities || []).forEach(vuln => {
                if (severity && vuln.Severity !== severity.toUpperCase()) return;
                if (fixable === 'true' && !vuln.FixedVersion) return;
                if (fixable === 'false' && vuln.FixedVersion) return;

                allVulns.push({
                    service: serviceName,
                    package_name: vuln.PkgName || '',
                    vulnerability_id: vuln.VulnerabilityID || '',
                    severity: vuln.Severity || 'UNKNOWN',
                    installed_version: vuln.InstalledVersion || '',
                    fixed_version: vuln.FixedVersion || 'Sin fix disponible',
                    title: vuln.Title || '',
                    description: (vuln.Description || '').substring(0, 200),
                    cvss_score: vuln.CVSS ? 
                        (Object.values(vuln.CVSS)[0] || {}).V3Score || 
                        (Object.values(vuln.CVSS)[0] || {}).V2Score || 0 : 0,
                    references: (vuln.References || []).slice(0, 3)
                });
            });
        });
    });

    // Ordenar por severidad
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4 };
    allVulns.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

    res.json(allVulns);
});

// ─── API: Guardar decisiones del estudiante ─────────────────────────────────
app.post('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    let decisions = [];
    if (fs.existsSync(decisionsPath)) {
        const data = readJsonSafe(decisionsPath);
        if (data && Array.isArray(data)) {
            decisions = data;
        }
    }
    decisions.push({
        ...req.body,
        timestamp: new Date().toISOString()
    });
    // Escribir con LF (no CRLF) para consistencia cross-platform
    fs.writeFileSync(decisionsPath, JSON.stringify(decisions, null, 2) + '\n', { encoding: 'utf8' });
    res.json({ success: true, total_decisions: decisions.length });
});

// ─── API: Obtener decisiones guardadas ──────────────────────────────────────
app.get('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    if (fs.existsSync(decisionsPath)) {
        const data = readJsonSafe(decisionsPath);
        if (data) {
            return res.json(data);
        }
    }
    res.json([]);
});

// ─── API: Diagnóstico (útil para debugging en Windows) ──────────────────────
app.get('/api/debug', (req, res) => {
    const info = {
        data_dir: DATA_DIR,
        data_dir_exists: fs.existsSync(DATA_DIR),
        platform: process.platform,
        arch: process.arch,
        node_version: process.version,
        files: []
    };
    
    if (fs.existsSync(DATA_DIR)) {
        try {
            info.files = fs.readdirSync(DATA_DIR).map(f => {
                const filePath = path.join(DATA_DIR, f);
                const stats = fs.statSync(filePath);
                return {
                    name: f,
                    size: stats.size,
                    modified: stats.mtime.toISOString(),
                    is_file: stats.isFile()
                };
            });
        } catch (err) {
            info.error = err.message;
        }
    }
    
    res.json(info);
});

// ─── Iniciar servidor ───────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n+========================================================+`);
    console.log(`|  VulnCorp Dashboard corriendo en http://localhost:${PORT}  |`);
    console.log(`+========================================================+\n`);
    
    // Listar archivos disponibles al inicio
    if (fs.existsSync(DATA_DIR)) {
        const files = fs.readdirSync(DATA_DIR);
        console.log(`[VulnCorp] Archivos en ${DATA_DIR}: ${files.length}`);
        files.forEach(f => {
            const stats = fs.statSync(path.join(DATA_DIR, f));
            console.log(`  - ${f} (${stats.size} bytes)`);
        });
    } else {
        console.log(`[VulnCorp] ADVERTENCIA: Directorio de datos no encontrado: ${DATA_DIR}`);
        console.log(`[VulnCorp] Ejecute ./scripts/scan.sh para generar los reportes.`);
    }
});
