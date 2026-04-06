/**
 * VulnCorp Dashboard de Gestion de Vulnerabilidades
 * Curso: Gestion de Vulnerabilidades con Enfoque MITRE 2026
 *
 * Servidor Express que sirve el dashboard y la API de datos.
 *
 * NOTA SOBRE COMPATIBILIDAD WINDOWS:
 * El dashboard corre DENTRO de un contenedor Docker (Linux),
 * pero los archivos JSON son generados FUERA del contenedor por
 * scan.sh o scan.ps1 (que pueden correr en Windows). Los archivos
 * llegan al contenedor via bind-mount (./data:/app/data).
 *
 * Problemas de Windows que este codigo maneja:
 * 1. BOM UTF-8 (EF BB BF) al inicio de archivos
 * 2. BOM UTF-16 LE (FF FE) si PowerShell uso Set-Content -Encoding Unicode
 * 3. Line endings CRLF en lugar de LF
 * 4. Caracteres nulos intercalados (UTF-16 mal decodificado)
 * 5. Latencia en bind-mounts de Docker Desktop para Windows (polling)
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Directorio de datos: dentro del contenedor o local para desarrollo
const DATA_DIR = fs.existsSync('/app/data')
    ? '/app/data'
    : path.join(__dirname, '..', 'data');

// Cache en memoria para el reporte (evita releer archivos en cada request)
let cachedReport = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 5000; // 5 segundos

console.log(`[VulnCorp] Inicio: ${new Date().toISOString()}`);
console.log(`[VulnCorp] Directorio de datos: ${DATA_DIR}`);
console.log(`[VulnCorp] Plataforma: ${process.platform} (${process.arch})`);
console.log(`[VulnCorp] Node: ${process.version}`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// =====================================================================
//  Utilidades robustas para lectura de archivos
// =====================================================================

/**
 * Lee un archivo como buffer raw y lo convierte a string UTF-8 limpio.
 * Maneja: BOM UTF-8, BOM UTF-16LE, CRLF, caracteres nulos.
 */
function readFileSafe(filePath) {
    try {
        const buf = fs.readFileSync(filePath);

        if (buf.length === 0) {
            console.warn(`[VulnCorp] Archivo vacio: ${filePath}`);
            return null;
        }

        let content;

        // Detectar BOM UTF-16 LE (FF FE) - PowerShell a veces genera esto
        if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
            console.log(`[VulnCorp] BOM UTF-16LE detectado en: ${path.basename(filePath)}`);
            content = buf.slice(2).toString('utf16le');
        }
        // Detectar BOM UTF-8 (EF BB BF)
        else if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
            console.log(`[VulnCorp] BOM UTF-8 detectado en: ${path.basename(filePath)}`);
            content = buf.slice(3).toString('utf8');
        }
        // Detectar UTF-16 sin BOM (null bytes intercalados)
        else if (buf.length >= 4 && (buf[1] === 0x00 || buf[0] === 0x00)) {
            // Heuristica: si hay null bytes en las primeras posiciones, es UTF-16
            try {
                content = buf.toString('utf16le');
                console.log(`[VulnCorp] UTF-16LE sin BOM detectado en: ${path.basename(filePath)}`);
            } catch (e) {
                content = buf.toString('utf8');
            }
        }
        else {
            content = buf.toString('utf8');
        }

        // Eliminar BOM Unicode residual (por si acaso)
        if (content.charCodeAt(0) === 0xFEFF) {
            content = content.substring(1);
        }

        // Normalizar line endings
        content = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

        // Eliminar caracteres nulos (comun en archivos UTF-16 mal convertidos)
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
        console.error(`[VulnCorp] Error parseando JSON ${path.basename(filePath)}: ${err.message}`);
        // Diagnostico: mostrar primeros bytes en hex
        try {
            const buf = fs.readFileSync(filePath);
            const hex = [];
            for (let i = 0; i < Math.min(30, buf.length); i++) {
                hex.push(buf[i].toString(16).padStart(2, '0'));
            }
            console.error(`[VulnCorp] Primeros 30 bytes (hex): ${hex.join(' ')}`);
            console.error(`[VulnCorp] Primeros 100 chars: ${content.substring(0, 100)}`);
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
 * Obtiene la fecha de modificacion mas reciente de los archivos de datos.
 */
function getLatestModTime() {
    try {
        if (!fs.existsSync(DATA_DIR)) return 0;
        const files = fs.readdirSync(DATA_DIR);
        let latest = 0;
        for (const f of files) {
            try {
                const fp = path.join(DATA_DIR, f);
                const st = fs.statSync(fp);
                if (st.isFile() && st.mtimeMs > latest) {
                    latest = st.mtimeMs;
                }
            } catch (e) { /* ignorar */ }
        }
        return latest;
    } catch (e) {
        return 0;
    }
}

/**
 * Construye el reporte consolidado desde multiples fuentes.
 * Orden de prioridad:
 *   1. consolidated_report.json (pre-generado por scan.sh/scan.ps1)
 *   2. scan_summary.jsonl (resumen por servicio)
 *   3. Archivos _trivy.json individuales (fallback)
 *
 * Usa cache en memoria con TTL de 5 segundos para evitar releer
 * archivos en cada request (importante para bind-mounts lentos de Windows).
 */
function buildConsolidatedReport(forceRefresh) {
    const now = Date.now();

    // Verificar cache
    if (!forceRefresh && cachedReport && (now - cacheTimestamp) < CACHE_TTL_MS) {
        return cachedReport;
    }

    // Verificar si los archivos cambiaron
    const latestMod = getLatestModTime();
    if (!forceRefresh && cachedReport && latestMod <= cacheTimestamp) {
        return cachedReport;
    }

    let report = null;

    // Opcion 1: Reporte consolidado pre-generado
    const consolidatedPath = path.join(DATA_DIR, 'consolidated_report.json');
    if (fs.existsSync(consolidatedPath)) {
        const data = readJsonSafe(consolidatedPath);
        if (data && data.services && data.services.length > 0) {
            data.source = 'consolidated_report.json';
            report = data;
        }
    }

    // Opcion 2: Leer scan_summary.jsonl
    if (!report) {
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
                report = {
                    scan_timestamp: services[0].timestamp || new Date().toISOString(),
                    total_services: services.length,
                    total_vulnerabilities: tc + th + tm + tl,
                    by_severity: { critical: tc, high: th, medium: tm, low: tl },
                    services: services,
                    source: 'scan_summary.jsonl'
                };
            }
        }
    }

    // Opcion 3: Construir desde archivos _trivy.json individuales
    if (!report) {
        const trivyFiles = listDataFiles('_trivy.json');
        if (trivyFiles.length > 0) {
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

            if (services.length > 0) {
                report = {
                    scan_timestamp: new Date().toISOString(),
                    total_services: services.length,
                    total_vulnerabilities: tc + th + tm + tl,
                    by_severity: { critical: tc, high: th, medium: tm, low: tl },
                    services: services,
                    source: 'trivy_files_dynamic'
                };
            }
        }
    }

    // Actualizar cache
    if (report) {
        cachedReport = report;
        cacheTimestamp = now;
    }

    return report;
}

// =====================================================================
//  API Endpoints
// =====================================================================

// --- Reporte consolidado ---
app.get('/api/report', (req, res) => {
    const report = buildConsolidatedReport(false);
    if (report) return res.json(report);

    res.json({
        scan_timestamp: null,
        total_services: 0,
        total_vulnerabilities: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
        services: [],
        message: "No se han ejecutado escaneos. Ejecute: ./scripts/scan.sh (Linux/macOS) o .\\scripts\\scan.ps1 (Windows)"
    });
});

// --- Detalle de un servicio ---
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

// --- Listar servicios disponibles ---
app.get('/api/services', (req, res) => {
    const files = listDataFiles('_trivy.json');
    const services = files.map(f => f.replace('_trivy.json', ''));
    res.json(services);
});

// --- Vulnerabilidades con filtros ---
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

// --- Guardar decisiones del estudiante ---
app.post('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    let decisions = [];
    if (fs.existsSync(decisionsPath)) {
        const data = readJsonSafe(decisionsPath);
        if (data && Array.isArray(data)) decisions = data;
    }
    decisions.push({ ...req.body, timestamp: new Date().toISOString() });
    // Escribir sin BOM usando Buffer
    const jsonStr = JSON.stringify(decisions, null, 2) + '\n';
    fs.writeFileSync(decisionsPath, Buffer.from(jsonStr, 'utf8'));
    res.json({ success: true, total_decisions: decisions.length });
});

// --- Obtener decisiones guardadas ---
app.get('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    if (fs.existsSync(decisionsPath)) {
        const data = readJsonSafe(decisionsPath);
        if (data) return res.json(data);
    }
    res.json([]);
});

// --- Forzar recarga de datos (invalida cache) ---
app.post('/api/reload', (req, res) => {
    console.log('[VulnCorp] Recarga forzada solicitada');
    cachedReport = null;
    cacheTimestamp = 0;
    const report = buildConsolidatedReport(true);
    if (report) {
        res.json({ success: true, message: 'Datos recargados', report });
    } else {
        res.json({ success: false, message: 'No se encontraron datos de escaneo' });
    }
});

// --- Diagnostico ---
app.get('/api/debug', (req, res) => {
    const info = {
        data_dir: DATA_DIR,
        data_dir_exists: fs.existsSync(DATA_DIR),
        platform: process.platform,
        arch: process.arch,
        node_version: process.version,
        timestamp: new Date().toISOString(),
        cache_age_ms: Date.now() - cacheTimestamp,
        cache_valid: cachedReport !== null,
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
                    if (stats.isFile() && stats.size > 0) {
                        // Detectar encoding
                        const buf = fs.readFileSync(fp);
                        const b0 = buf[0], b1 = buf.length > 1 ? buf[1] : 0, b2 = buf.length > 2 ? buf[2] : 0;
                        if (b0 === 0xEF && b1 === 0xBB && b2 === 0xBF) {
                            result.encoding = 'UTF-8 with BOM';
                        } else if (b0 === 0xFF && b1 === 0xFE) {
                            result.encoding = 'UTF-16LE with BOM';
                        } else if (buf.length >= 4 && (buf[1] === 0x00 || buf[0] === 0x00)) {
                            result.encoding = 'Possible UTF-16 (null bytes detected)';
                        } else {
                            result.encoding = 'UTF-8 (no BOM)';
                        }

                        // Intentar parsear JSON
                        if (f.endsWith('.json') || f.endsWith('.jsonl')) {
                            const data = f.endsWith('.jsonl')
                                ? readJsonlSafe(fp)
                                : readJsonSafe(fp);
                            result.parseable = data !== null && (Array.isArray(data) ? data.length > 0 : true);
                            if (data && !Array.isArray(data) && data.Results) {
                                result.results_count = data.Results.length;
                                let vulnCount = 0;
                                (data.Results || []).forEach(r => {
                                    vulnCount += (r.Vulnerabilities || []).length;
                                });
                                result.vulnerability_count = vulnCount;
                            }
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

// =====================================================================
//  File Watcher (para detectar nuevos archivos sin reiniciar)
// =====================================================================

/**
 * Monitorea el directorio de datos para invalidar el cache cuando
 * se agregan o modifican archivos. Usa polling porque fs.watch no
 * funciona de forma confiable con bind-mounts de Docker Desktop en Windows.
 */
let lastKnownFiles = '';

function pollForChanges() {
    try {
        if (!fs.existsSync(DATA_DIR)) return;
        const files = fs.readdirSync(DATA_DIR)
            .filter(f => f.endsWith('.json') || f.endsWith('.jsonl'))
            .sort();
        let fingerprint = '';
        for (const f of files) {
            try {
                const st = fs.statSync(path.join(DATA_DIR, f));
                fingerprint += `${f}:${st.size}:${st.mtimeMs};`;
            } catch (e) { /* ignorar */ }
        }
        if (fingerprint !== lastKnownFiles) {
            if (lastKnownFiles !== '') {
                console.log(`[VulnCorp] Cambios detectados en archivos de datos. Invalidando cache.`);
                cachedReport = null;
                cacheTimestamp = 0;
            }
            lastKnownFiles = fingerprint;
        }
    } catch (e) { /* ignorar */ }
}

// Polling cada 3 segundos (funciona con bind-mounts lentos de Windows)
setInterval(pollForChanges, 3000);

// =====================================================================
//  Iniciar servidor
// =====================================================================

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('+========================================================+');
    console.log(`|  VulnCorp Dashboard corriendo en http://localhost:${PORT}  |`);
    console.log('+========================================================+');
    console.log('');

    // Listar archivos disponibles al inicio
    if (fs.existsSync(DATA_DIR)) {
        const files = fs.readdirSync(DATA_DIR);
        const dataFiles = files.filter(f => {
            try { return fs.statSync(path.join(DATA_DIR, f)).isFile(); }
            catch (e) { return false; }
        });
        console.log(`[VulnCorp] Archivos en ${DATA_DIR}: ${dataFiles.length}`);
        dataFiles.forEach(f => {
            try {
                const fp = path.join(DATA_DIR, f);
                const stats = fs.statSync(fp);
                const buf = fs.readFileSync(fp);
                let enc = 'UTF-8';
                if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) enc = 'UTF-8+BOM';
                if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) enc = 'UTF-16LE';
                if (buf.length >= 4 && (buf[1] === 0x00 || buf[0] === 0x00) && enc === 'UTF-8') enc = 'UTF-16?';
                console.log(`  - ${f} (${stats.size} bytes, ${enc})`);
            } catch (e) { /* ignorar */ }
        });
        if (dataFiles.length === 0) {
            console.log('[VulnCorp] No hay archivos de escaneo.');
            console.log('[VulnCorp] Ejecute ./scripts/scan.sh o .\\scripts\\scan.ps1');
        }
    } else {
        console.log(`[VulnCorp] ADVERTENCIA: Directorio no encontrado: ${DATA_DIR}`);
    }

    // Inicializar polling
    pollForChanges();
});
