/**
 * VulnCorp — Dashboard de Gestión de Vulnerabilidades
 * Curso: Gestión de Vulnerabilidades con Enfoque MITRE — 2026
 *
 * Servidor Express que sirve el dashboard y la API de datos.
 * Compatible con Linux, macOS y Windows (Docker Desktop).
 *
 * NOTA: El dashboard corre DENTRO de un contenedor Docker (Linux),
 * pero los archivos JSON son generados FUERA del contenedor por
 * scan.sh (que puede correr en Windows). Los archivos llegan al
 * contenedor via bind-mount (./data:/app/data).
 *
 * Problemas conocidos en Windows que este codigo maneja:
 * 1. BOM (Byte Order Mark) al inicio de archivos UTF-8
 * 2. Line endings CRLF en lugar de LF
 * 3. Caracteres nulos intercalados
 * 4. Latencia en bind-mounts de Docker Desktop (archivos tardan
 *    en aparecer dentro del contenedor)
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// ─── Directorio de datos ────────────────────────────────────────────────────
const DATA_DIR = fs.existsSync('/app/data')
    ? '/app/data'
    : path.join(__dirname, '..', 'data');

console.log(`[VulnCorp] Inicio: ${new Date().toISOString()}`);
console.log(`[VulnCorp] Directorio de datos: ${DATA_DIR}`);
console.log(`[VulnCorp] Plataforma: ${process.platform} (${process.arch})`);
console.log(`[VulnCorp] Node: ${process.version}`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Utilidades robustas para lectura de archivos ──────────────────────────

/**
 * Lee un archivo y devuelve su contenido como string limpio.
 * Maneja BOM, CRLF, caracteres nulos y errores de codificacion.
 */
function readFileSafe(filePath) {
    try {
        // Leer como buffer primero para detectar BOM
        const buf = fs.readFileSync(filePath);

        // Detectar y eliminar BOM UTF-8 (EF BB BF)
        let start = 0;
        if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
            start = 3;
        }

        let content = buf.slice(start).toString('utf8');

        // Eliminar BOM como caracter Unicode (por si acaso)
        if (content.charCodeAt(0) === 0xFEFF) {
            content = content.substring(1);
        }

        // Normalizar line endings
        content = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

        // Eliminar caracteres nulos
        content = content.replace(/\0/g, '');

        return content.trim();
    } catch (err) {
        console.error(`[VulnCorp] Error leyendo ${filePath}: ${err.message}`);
        return null;
    }
}

/**
 * Lee un archivo JSON de forma robusta.
 */
function readJsonSafe(filePath) {
    const content = readFileSafe(filePath);
    if (!content) return null;

    try {
        return JSON.parse(content);
    } catch (err) {
        console.error(`[VulnCorp] Error parseando JSON ${filePath}: ${err.message}`);
        // Diagnostico: mostrar primeros bytes
        try {
            const buf = fs.readFileSync(filePath);
            const hex = buf.slice(0, 30).toString('hex').match(/.{2}/g).join(' ');
            console.error(`[VulnCorp] Primeros 30 bytes (hex): ${hex}`);
            console.error(`[VulnCorp] Primeros 100 chars: ${buf.slice(0, 100).toString('utf8')}`);
        } catch (e) { /* ignorar */ }
        return null;
    }
}

/**
 * Lee un archivo JSONL (una linea JSON por linea).
 */
function readJsonlSafe(filePath) {
    const content = readFileSafe(filePath);
    if (!content) return [];

    const results = [];
    const lines = content.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
            results.push(JSON.parse(trimmed));
        } catch (err) {
            console.warn(`[VulnCorp] Linea JSONL invalida: ${trimmed.substring(0, 80)}`);
        }
    }
    return results;
}

/**
 * Lista archivos en DATA_DIR con un sufijo dado.
 */
function listDataFiles(suffix) {
    try {
        if (!fs.existsSync(DATA_DIR)) return [];
        return fs.readdirSync(DATA_DIR).filter(f => f.endsWith(suffix));
    } catch (err) {
        console.error(`[VulnCorp] Error listando archivos: ${err.message}`);
        return [];
    }
}

/**
 * Construye el reporte consolidado desde archivos individuales de Trivy.
 * Usa scan_summary.jsonl si existe (tiene metadatos de zona/exposicion),
 * si no, construye desde los archivos _trivy.json.
 */
function buildConsolidatedReport() {
    // Opcion 1: Leer scan_summary.jsonl (generado por scan.sh, tiene metadatos)
    const summaryPath = path.join(DATA_DIR, 'scan_summary.jsonl');
    if (fs.existsSync(summaryPath)) {
        const services = readJsonlSafe(summaryPath);
        if (services.length > 0) {
            let tc = 0, th = 0, tm = 0, tl = 0;
            services.forEach(s => {
                tc += s.critical || 0;
                th += s.high || 0;
                tm += s.medium || 0;
                tl += s.low || 0;
            });
            return {
                scan_timestamp: services[0].timestamp || new Date().toISOString(),
                total_services: services.length,
                total_vulnerabilities: tc + th + tm + tl,
                by_severity: { critical: tc, high: th, medium: tm, low: tl },
                services: services,
                source: 'scan_summary.jsonl'
            };
        }
    }

    // Opcion 2: Construir desde archivos _trivy.json individuales
    const trivyFiles = listDataFiles('_trivy.json');
    if (trivyFiles.length === 0) return null;

    console.log(`[VulnCorp] Construyendo reporte desde ${trivyFiles.length} archivos Trivy`);
    const services = [];
    let tc = 0, th = 0, tm = 0, tl = 0;

    trivyFiles.forEach(file => {
        const serviceName = file.replace('_trivy.json', '');
        const data = readJsonSafe(path.join(DATA_DIR, file));
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
        tc += critical; th += high; tm += medium; tl += low;
    });

    return {
        scan_timestamp: new Date().toISOString(),
        total_services: services.length,
        total_vulnerabilities: tc + th + tm + tl,
        by_severity: { critical: tc, high: th, medium: tm, low: tl },
        services: services,
        source: 'trivy_files_dynamic'
    };
}

// ─── API: Reporte consolidado ───────────────────────────────────────────────
app.get('/api/report', (req, res) => {
    // Primero intentar leer el reporte consolidado pre-generado
    const reportPath = path.join(DATA_DIR, 'consolidated_report.json');
    if (fs.existsSync(reportPath)) {
        const data = readJsonSafe(reportPath);
        if (data) {
            data.source = 'consolidated_report.json';
            return res.json(data);
        }
    }

    // Si no existe, construirlo dinamicamente
    const report = buildConsolidatedReport();
    if (report) return res.json(report);

    // Sin datos
    res.json({
        scan_timestamp: null,
        total_services: 0,
        total_vulnerabilities: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
        services: [],
        message: "No se han ejecutado escaneos. Ejecute: ./scripts/scan.sh"
    });
});

// ─── API: Detalle de un servicio ────────────────────────────────────────────
app.get('/api/service/:name', (req, res) => {
    const serviceName = req.params.name;
    const reportPath = path.join(DATA_DIR, `${serviceName}_trivy.json`);

    if (fs.existsSync(reportPath)) {
        const data = readJsonSafe(reportPath);
        if (data) return res.json(data);
        return res.status(500).json({ error: `Error leyendo reporte de: ${serviceName}` });
    }
    res.status(404).json({ error: `Reporte no encontrado: ${serviceName}` });
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
                    cvss_score: vuln.CVSS
                        ? (Object.values(vuln.CVSS)[0] || {}).V3Score
                          || (Object.values(vuln.CVSS)[0] || {}).V2Score
                          || 0
                        : 0,
                    references: (vuln.References || []).slice(0, 3)
                });
            });
        });
    });

    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
    allVulns.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

    res.json(allVulns);
});

// ─── API: Guardar decisiones del estudiante ─────────────────────────────────
app.post('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    let decisions = [];
    if (fs.existsSync(decisionsPath)) {
        const data = readJsonSafe(decisionsPath);
        if (data && Array.isArray(data)) decisions = data;
    }
    decisions.push({ ...req.body, timestamp: new Date().toISOString() });
    fs.writeFileSync(decisionsPath, JSON.stringify(decisions, null, 2) + '\n', 'utf8');
    res.json({ success: true, total_decisions: decisions.length });
});

// ─── API: Obtener decisiones guardadas ──────────────────────────────────────
app.get('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    if (fs.existsSync(decisionsPath)) {
        const data = readJsonSafe(decisionsPath);
        if (data) return res.json(data);
    }
    res.json([]);
});

// ─── API: Diagnostico ──────────────────────────────────────────────────────
app.get('/api/debug', (req, res) => {
    const info = {
        data_dir: DATA_DIR,
        data_dir_exists: fs.existsSync(DATA_DIR),
        platform: process.platform,
        arch: process.arch,
        node_version: process.version,
        timestamp: new Date().toISOString(),
        files: []
    };

    if (fs.existsSync(DATA_DIR)) {
        try {
            info.files = fs.readdirSync(DATA_DIR).map(f => {
                const fp = path.join(DATA_DIR, f);
                try {
                    const stats = fs.statSync(fp);
                    const result = {
                        name: f,
                        size: stats.size,
                        modified: stats.mtime.toISOString(),
                        is_file: stats.isFile()
                    };
                    // Para archivos JSON, intentar parsear y reportar estado
                    if (f.endsWith('.json') && stats.isFile() && stats.size > 0) {
                        const data = readJsonSafe(fp);
                        result.json_valid = data !== null;
                        if (data && data.Results) {
                            result.results_count = data.Results.length;
                        }
                    }
                    return result;
                } catch (e) {
                    return { name: f, error: e.message };
                }
            });
        } catch (err) {
            info.error = err.message;
        }
    }

    res.json(info);
});

// ─── Iniciar servidor ───────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('+========================================================+');
    console.log(`|  VulnCorp Dashboard corriendo en http://localhost:${PORT}  |`);
    console.log('+========================================================+');
    console.log('');

    // Listar archivos disponibles al inicio
    if (fs.existsSync(DATA_DIR)) {
        const files = fs.readdirSync(DATA_DIR);
        console.log(`[VulnCorp] Archivos en ${DATA_DIR}: ${files.length}`);
        files.forEach(f => {
            try {
                const fp = path.join(DATA_DIR, f);
                const stats = fs.statSync(fp);
                if (stats.isFile()) {
                    console.log(`  - ${f} (${stats.size} bytes)`);
                }
            } catch (e) { /* ignorar */ }
        });
        if (files.length === 0) {
            console.log('[VulnCorp] No hay archivos de escaneo.');
            console.log('[VulnCorp] Ejecute ./scripts/scan.sh para generar reportes.');
        }
    } else {
        console.log(`[VulnCorp] ADVERTENCIA: Directorio no encontrado: ${DATA_DIR}`);
        console.log('[VulnCorp] Ejecute ./scripts/scan.sh para generar reportes.');
    }
});
