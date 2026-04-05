/**
 * VulnCorp — Dashboard de Gestión de Vulnerabilidades
 * Curso MAR303 — Universidad Mayor — 2026
 * 
 * Servidor Express que sirve el dashboard y la API de datos
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const DATA_DIR = '/app/data';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API: Obtener reporte consolidado
app.get('/api/report', (req, res) => {
    const reportPath = path.join(DATA_DIR, 'consolidated_report.json');
    if (fs.existsSync(reportPath)) {
        const data = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        res.json(data);
    } else {
        res.json({
            scan_timestamp: null,
            total_services: 0,
            total_vulnerabilities: 0,
            by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
            services: [],
            message: "No se han ejecutado escaneos aún. Ejecute: ./scripts/scan.sh"
        });
    }
});

// API: Obtener detalle de un servicio específico
app.get('/api/service/:name', (req, res) => {
    const serviceName = req.params.name;
    const reportPath = path.join(DATA_DIR, `${serviceName}_trivy.json`);
    if (fs.existsSync(reportPath)) {
        const data = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        res.json(data);
    } else {
        res.status(404).json({ error: `Reporte no encontrado para: ${serviceName}` });
    }
});

// API: Listar todos los reportes disponibles
app.get('/api/services', (req, res) => {
    if (!fs.existsSync(DATA_DIR)) {
        return res.json([]);
    }
    const files = fs.readdirSync(DATA_DIR)
        .filter(f => f.endsWith('_trivy.json'))
        .map(f => f.replace('_trivy.json', ''));
    res.json(files);
});

// API: Obtener todas las vulnerabilidades con filtros
app.get('/api/vulnerabilities', (req, res) => {
    const { severity, service, fixable } = req.query;
    
    if (!fs.existsSync(DATA_DIR)) {
        return res.json([]);
    }

    const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('_trivy.json'));
    let allVulns = [];

    files.forEach(file => {
        const serviceName = file.replace('_trivy.json', '');
        if (service && serviceName !== service) return;

        const data = JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), 'utf8'));
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
                        Object.values(vuln.CVSS)[0]?.V3Score || 
                        Object.values(vuln.CVSS)[0]?.V2Score || 0 : 0,
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

// API: Guardar decisiones de priorización del estudiante
app.post('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    let decisions = [];
    if (fs.existsSync(decisionsPath)) {
        decisions = JSON.parse(fs.readFileSync(decisionsPath, 'utf8'));
    }
    decisions.push({
        ...req.body,
        timestamp: new Date().toISOString()
    });
    fs.writeFileSync(decisionsPath, JSON.stringify(decisions, null, 2));
    res.json({ success: true, total_decisions: decisions.length });
});

// API: Obtener decisiones guardadas
app.get('/api/decisions', (req, res) => {
    const decisionsPath = path.join(DATA_DIR, 'student_decisions.json');
    if (fs.existsSync(decisionsPath)) {
        const decisions = JSON.parse(fs.readFileSync(decisionsPath, 'utf8'));
        res.json(decisions);
    } else {
        res.json([]);
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n╔══════════════════════════════════════════════════════════╗`);
    console.log(`║  VulnCorp Dashboard corriendo en http://localhost:${PORT}  ║`);
    console.log(`╚══════════════════════════════════════════════════════════╝\n`);
});
