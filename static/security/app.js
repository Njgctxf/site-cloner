// Mounted inside SiteCloner: every API call goes under the security module's prefix
const SEC = window.SEC_BASE || '';

// app.js - CyberLab SOC Application Controller

let currentTab = 'overview';
let scenariosData = {};
let currentScanData = null;

// Escapes a value for safe HTML insertion (used throughout to display scan/log/module data).
function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    // links from SiteCloner open a given tab, e.g. ...#scanner from a clone's "Audit sécurité" button
    const startTab = location.hash.slice(1);
    if (startTab && document.querySelector(`.nav-item[data-tab="${startTab}"]`)) switchTab(startTab);
    if (new URLSearchParams(location.search).get('run') === '1') triggerScan();  // ?target=...&run=1
    loadOverview();
    loadDomains();
    loadScenarios();
    loadLearningModules();
    loadReportsList();
    
    // Auto-refresh overview telemetry every 10 seconds
    setInterval(loadOverview, 10000);
});

// --- NAVIGATION ---
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const tab = item.getAttribute('data-tab');
            switchTab(tab);
        });
    });
}

function switchTab(tabId) {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    const navItem = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
    const pane = document.getElementById(`tab-${tabId}`);

    if (navItem && pane) {
        navItem.classList.add('active');
        pane.classList.add('active');
        currentTab = tabId;

        // Trigger tab-specific refreshes
        if (tabId === 'overview') loadOverview();
        if (tabId === 'domains') loadDomains();
        if (tabId === 'reports') loadReportsList();
        if (tabId === 'network') renderNetworkTraffic();
        if (tabId === 'cicd') loadCicdTab();
    }
}

// --- OVERVIEW MODULE ---
async function loadOverview() {
    try {
        const res = await fetch(SEC + '/api/overview');
        const data = await res.json();

        // Metrics
        document.getElementById('metric-scans').textContent = data.metrics.total_scans;
        document.getElementById('metric-vulns').textContent = data.metrics.total_vulnerabilities;
        document.getElementById('metric-sims').textContent = data.metrics.total_simulations;
        
        const riskBadge = document.getElementById('metric-risk');
        riskBadge.textContent = data.metrics.overall_risk;
        riskBadge.style.color = data.metrics.risk_color;
        
        document.getElementById('metric-posture').textContent = data.metrics.posture_score + '/100';

        // Lab mode indicator
        const labModeBadge = document.getElementById('lab-mode-badge');
        if (labModeBadge) {
            labModeBadge.textContent = data.lab_status.mode;
            labModeBadge.className = data.lab_status.mode === 'VULNERABLE' ? 'badge-tag badge-crit' : 'badge-tag badge-safe';
        }

        // Live Log Stream
        const logBody = document.getElementById('overview-logs');
        if (logBody && data.recent_logs) {
            logBody.innerHTML = '';
            data.recent_logs.forEach(log => {
                const line = document.createElement('div');
                line.className = 'log-line';
                let sevClass = 'log-info';
                if (log.severity === 'WARN') sevClass = 'log-warn';
                if (log.severity === 'HIGH' || log.severity === 'CRITICAL') sevClass = 'log-crit';

                line.innerHTML = `<span class="log-time">[${log.timestamp}]</span> <span class="log-src">&lt;${log.source}&gt;</span> <span class="${sevClass}">[${log.event_type}] ${escapeHtml(log.message)}</span>`;
                logBody.appendChild(line);
            });
        }

        // Update Vuln Distribution Chart if Chart.js is present
        updateVulnChart(data.vuln_distribution);

    } catch (e) {
        console.error("Error loading overview telemetry:", e);
    }
}

let vulnChartInstance = null;
function updateVulnChart(dist) {
    const ctx = document.getElementById('vulnChart');
    if (!ctx || typeof Chart === 'undefined') return;

    const chartData = [dist.critical, dist.high, dist.medium, dist.low];
    if (vulnChartInstance) {
        vulnChartInstance.data.datasets[0].data = chartData;
        vulnChartInstance.update();
    } else {
        vulnChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critique', 'Élevé', 'Moyen', 'Faible'],
                datasets: [{
                    data: chartData,
                    backgroundColor: ['#ff3366', '#ff9900', '#eab308', '#00f0ff'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Inter' } } }
                }
            }
        });
    }
}

// --- LAB ENVIRONMENT CONTROLLER ---
async function toggleLabProtection() {
    try {
        const res = await fetch(SEC + '/api/lab/toggle-mode', { method: 'POST' });
        const data = await res.json();
        showToast(`Mode du laboratoire : ${data.mode}`);
        loadOverview();
        if (currentTab === 'simulations') loadScenarios();
    } catch (e) {
        showToast("Erreur lors du basculement", "error");
    }
}

async function resetLabDatabase() {
    if (!confirm("Réinitialiser l'environnement de laboratoire (données et fichiers de test) ?")) return;
    try {
        const res = await fetch(SEC + '/api/lab/reset', { method: 'POST' });
        const data = await res.json();
        showToast(data.message);
        loadOverview();
    } catch (e) {
        showToast("Erreur lors de la réinitialisation", "error");
    }
}

// --- DEFENSIVE SECURITY SCANNER ---
function getSelectedScanCategories() {
    return Array.from(document.querySelectorAll('.scan-category-checkbox:checked')).map(cb => cb.value);
}

function setScanCategories(checked) {
    document.querySelectorAll('.scan-category-checkbox').forEach(cb => { cb.checked = checked; });
}

async function triggerScan() {
    const target = document.getElementById('scan-target-input').value.trim();
    if (!target) {
        showToast("Veuillez saisir une URL de laboratoire", "error");
        return;
    }
    const categories = getSelectedScanCategories();
    if (categories.length === 0) {
        showToast("Sélectionnez au moins une catégorie à analyser", "error");
        return;
    }

    const btn = document.getElementById('btn-start-scan');
    btn.disabled = true;
    btn.innerHTML = `<span>Analyse en cours...</span>`;

    try {
        const res = await fetch(SEC + '/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target_url: target, categories: categories })
        });
        const data = await res.json();
        btn.disabled = false;
        btn.innerHTML = `<span>Lancer l'Audit Défensif</span>`;

        if (!data.success) {
            showToast(data.error || "Échec de l'audit", "error");
            return;
        }

        currentScanData = data;
        renderScanResults(data);
        showToast(`Audit terminé : Note ${data.grade} (${data.risk_score}/100)`);
        loadOverview();
        loadReportsList();

    } catch (e) {
        btn.disabled = false;
        btn.innerHTML = `<span>Lancer l'Audit Défensif</span>`;
        showToast("Erreur lors de la communication avec le scanner", "error");
    }
}

function renderScanResults(scan) {
    currentScanData = scan;
    const container = document.getElementById('scan-results-container');
    container.style.display = 'block';

    document.getElementById('scan-res-target').textContent = scan.target_url;
    document.getElementById('scan-res-date').textContent = scan.timestamp;
    document.getElementById('scan-res-score').textContent = scan.risk_score + '/100';
    
    const gradeBadge = document.getElementById('scan-res-grade');
    gradeBadge.textContent = 'GRADE ' + scan.grade;
    gradeBadge.className = (scan.grade === 'A' || scan.grade === 'B') ? 'badge-tag badge-safe' : 'badge-tag badge-crit';

    const list = document.getElementById('scan-findings-list');
    list.innerHTML = '';

    if (scan.findings.length === 0) {
        list.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--green);"> Aucune vulnérabilité ou anomalie détectée sur la cible !</div>`;
        return;
    }

    scan.findings.forEach(f => {
        let badgeClass = 'badge-tag badge-info';
        if (f.severity === 'CRITICAL') badgeClass = 'badge-tag badge-crit';
        if (f.severity === 'HIGH') badgeClass = 'badge-tag badge-high';
        if (f.severity === 'MEDIUM') badgeClass = 'badge-tag badge-med';
        if (f.severity === 'LOW') badgeClass = 'badge-tag badge-low';

        const item = document.createElement('div');
        item.className = 'card';
        item.style.marginBottom = '1rem';
        item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                <div>
                    <span class="${badgeClass}">${f.severity}</span>
                    <span style="font-weight: 700; margin-left: 0.5rem; font-size: 1rem;">${escapeHtml(f.title)}</span>
                </div>
                <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">${f.category}</span>
            </div>
            <p style="color: var(--text-secondary); font-size: 0.88rem; margin: 0.5rem 0;">${escapeHtml(f.description)}</p>
            
            <div style="background: #080a10; padding: 0.75rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.8rem; margin: 0.5rem 0; border: 1px solid var(--border-color);">
                <div style="color: var(--cyan); margin-bottom: 0.25rem;"> Preuve d'audit :</div>
                <div style="color: #cbd5e1;">${escapeHtml(f.proof)}</div>
            </div>

            <div style="background: rgba(0, 255, 136, 0.05); padding: 0.75rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.8rem; margin-top: 0.5rem; border-left: 3px solid var(--green);">
                <div style="color: var(--green); margin-bottom: 0.25rem;"> Recommandation de remédiation :</div>
                <div style="color: #e2e8f0;">${escapeHtml(f.remediation)}</div>
            </div>
        `;
        list.appendChild(item);
    });
}

// --- ATTACK SIMULATIONS MODULE ---
async function loadScenarios() {
    try {
        const res = await fetch(SEC + '/api/simulations/scenarios');
        const data = await res.json();
        scenariosData = data.scenarios;

        const select = document.getElementById('sim-scenario-select');
        select.innerHTML = '';
        Object.keys(scenariosData).forEach(key => {
            const sc = scenariosData[key];
            const opt = document.createElement('option');
            opt.value = sc.id;
            opt.textContent = `${sc.title} (${sc.owasp})`;
            select.appendChild(opt);
        });

        onScenarioChange();
    } catch (e) {
        console.error("Error loading scenarios:", e);
    }
}

function onScenarioChange() {
    const sel = document.getElementById('sim-scenario-select').value;
    const sc = scenariosData[sel];
    if (!sc) return;

    document.getElementById('sim-desc').textContent = sc.description;
    document.getElementById('sim-cwe').textContent = sc.cwe;

    const payloadSel = document.getElementById('sim-payload-preset');
    payloadSel.innerHTML = '';
    sc.payloads.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.value;
        opt.textContent = `${p.name} -> [ ${p.value} ]`;
        payloadSel.appendChild(opt);
    });

    onPayloadPresetChange();

    // Code diffs
    document.getElementById('sim-code-vuln').textContent = sc.vulnerable_code;
    document.getElementById('sim-code-sec').textContent = sc.secured_code;
}

function onPayloadPresetChange() {
    const p = document.getElementById('sim-payload-preset').value;
    document.getElementById('sim-payload-custom').value = p;
}

async function executeSimulationTest(forceMode = null) {
    const vulnType = document.getElementById('sim-scenario-select').value;
    const payload = document.getElementById('sim-payload-custom').value;

    const logBox = document.getElementById('sim-terminal');
    logBox.innerHTML = `<div class="log-line log-info"> Initialisation de la démonstration pédagogique...</div>`;

    try {
        const res = await fetch(SEC + '/api/simulations/run', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                vuln_type: vulnType,
                payload: payload,
                mode: forceMode
            })
        });
        const data = await res.json();

        // Print step-by-step logs into terminal
        logBox.innerHTML = '';
        data.steps.forEach((st, idx) => {
            setTimeout(() => {
                const line = document.createElement('div');
                line.className = 'log-line';
                line.textContent = st;
                logBox.appendChild(line);
                logBox.scrollTop = logBox.scrollHeight;
            }, idx * 100);
        });

        // Update result box
        const resCard = document.getElementById('sim-result-card');
        resCard.style.display = 'block';

        const outcomeBadge = document.getElementById('sim-outcome-badge');
        if (data.outcome === 'VULNERABILITY_CONFIRMED') {
            outcomeBadge.textContent = 'EXPLOITATION EFFECTIVE (MODE VULNÉRABLE)';
            outcomeBadge.className = 'badge-tag badge-crit';
            document.getElementById('sim-outcome-msg').textContent = 'La vulnérabilité a été exploitée avec succès dans le laboratoire. Les données ou l\'exécution de script ont été démontrées.';
        } else {
            outcomeBadge.textContent = 'NEUTRALISÉ / PROTÉGÉ (MODE SÉCURISÉ)';
            outcomeBadge.className = 'badge-tag badge-safe';
            document.getElementById('sim-outcome-msg').textContent = 'La protection active a bloqué l\'injection. La remédiation est vérifiée fonctionnelle.';
        }

        document.getElementById('sim-telemetry-raw').textContent = JSON.stringify(data.result_data, null, 2);

        loadOverview();

    } catch (e) {
        showToast("Erreur lors de l'exécution de la simulation", "error");
    }
}

// --- LEARNING CENTER ---
async function loadLearningModules() {
    try {
        const res = await fetch(SEC + '/api/learning/modules');
        const data = await res.json();
        const container = document.getElementById('learning-modules-list');
        if (!container) return;

        container.innerHTML = '';
        data.modules.forEach(m => {
            const card = document.createElement('div');
            card.className = 'card';
            card.style.marginBottom = '1.5rem';
            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                    <h3 style="font-size: 1.1rem; color: var(--text-primary);">${m.title}</h3>
                    <div>
                        <span class="badge-tag badge-info">${m.difficulty}</span>
                        <span style="font-size: 0.8rem; color: var(--text-muted); margin-left: 0.5rem;"> ${m.duration}</span>
                    </div>
                </div>
                <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1rem;">${m.summary}</p>
                <div style="background: rgba(255,255,255,0.03); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
                    <strong style="color: var(--cyan); font-size: 0.85rem;">Principes clés de défense :</strong>
                    <ul style="margin: 0.5rem 0 0 1.5rem; color: #cbd5e1; font-size: 0.85rem; line-height: 1.6;">
                        ${m.key_takeaways.map(t => `<li>${t}</li>`).join('')}
                    </ul>
                </div>

                <div style="border-top: 1px solid var(--border-color); padding-top: 1rem;">
                    <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 0.5rem;"> Quiz de validation : ${m.quiz.question}</div>
                    <div style="display: flex; flex-direction: column; gap: 0.4rem;">
                        ${m.quiz.options.map((opt, oIdx) => `
                            <button class="btn btn-secondary" style="justify-content: flex-start; text-align: left;" onclick="checkQuizAnswer(this, ${oIdx}, ${m.quiz.answer_index}, '${escapeHtml(m.quiz.explanation)}')">
                                <span>${String.fromCharCode(65 + oIdx)}. ${opt}</span>
                            </button>
                        `).join('')}
                    </div>
                    <div class="quiz-feedback" style="display: none; margin-top: 0.75rem; font-size: 0.85rem; padding: 0.75rem; border-radius: 6px;"></div>
                </div>
            `;
            container.appendChild(card);
        });
    } catch (e) {
        console.error("Error loading learning modules:", e);
    }
}

function checkQuizAnswer(btn, chosen, correct, explanation) {
    const parent = btn.parentElement;
    const feedback = parent.nextElementSibling;
    parent.querySelectorAll('button').forEach(b => b.disabled = true);

    if (chosen === correct) {
        btn.style.background = 'rgba(0, 255, 136, 0.2)';
        btn.style.borderColor = 'var(--green)';
        feedback.style.display = 'block';
        feedback.style.background = 'rgba(0, 255, 136, 0.1)';
        feedback.style.color = 'var(--green)';
        feedback.innerHTML = ` <strong>Correct !</strong> ${explanation}`;
    } else {
        btn.style.background = 'rgba(255, 51, 102, 0.2)';
        btn.style.borderColor = 'var(--red)';
        feedback.style.display = 'block';
        feedback.style.background = 'rgba(255, 51, 102, 0.1)';
        feedback.style.color = 'var(--red)';
        feedback.innerHTML = ` <strong>Incorrect.</strong> ${explanation}`;
    }
}

// --- VULNERABILITY REPORTS MODULE ---
async function loadReportsList() {
    try {
        const res = await fetch(SEC + '/api/scans');
        const data = await res.json();
        const tbody = document.getElementById('reports-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';
        if (data.scans.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">Aucun rapport généré. Réalisez un audit dans l'onglet 'Security Scanner'.</td></tr>`;
            return;
        }

        data.scans.forEach(s => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-color)';
            tr.innerHTML = `
                <td style="padding: 1rem; font-family: var(--font-mono);">#${s.id}</td>
                <td style="padding: 1rem; font-weight: 600;">${s.target_url}</td>
                <td style="padding: 1rem; color: var(--text-muted); font-size: 0.85rem;">${s.timestamp}</td>
                <td style="padding: 1rem;"><span class="badge-tag ${(s.grade==='A'||s.grade==='B')?'badge-safe':'badge-crit'}">${s.grade} (${s.risk_score}/100)</span></td>
                <td style="padding: 1rem; font-family: var(--font-mono);"><span style="color: var(--red); font-weight: 700;">${s.critical_count}</span> / <span style="color: var(--orange);">${s.high_count}</span></td>
                <td style="padding: 1rem;">
                    <a href="${SEC}/api/scans/${s.id}/report" target="_blank" class="btn btn-secondary" style="padding: 0.4rem 0.8rem; font-size: 0.8rem; text-decoration: none;">
                        <span>Ouvrir Rapport PDF / Print</span>
                    </a>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading reports:", e);
    }
}

// --- NETWORK MONITORING SIMULATOR ---
function renderNetworkTraffic() {
    const list = document.getElementById('network-traffic-list');
    if (!list) return;

    const mockPackets = [
        { time: '15:10:02', src: '127.0.0.1:54210', dst: '127.0.0.1:5050', proto: 'HTTP/1.1', method: 'GET', path: '/lab', status: 200, label: 'Standard browsing' },
        { time: '15:10:14', src: '127.0.0.1:54215', dst: '127.0.0.1:5050', proto: 'HTTP/1.1', method: 'POST', path: '/lab/login', status: 401, label: 'Failed auth attempt' },
        { time: '15:10:28', src: '127.0.0.1:54220', dst: '127.0.0.1:5050', proto: 'HTTP/1.1', method: 'GET', path: '/lab/profile/1', status: 200, label: 'Accessing user record' },
        { time: '15:11:05', src: '127.0.0.1:54230', dst: '127.0.0.1:5050', proto: 'HTTP/1.1', method: 'GET', path: '/.env', status: 404, label: 'Sensitive probe scan' }
    ];

    list.innerHTML = '';
    mockPackets.forEach(p => {
        const row = document.createElement('tr');
        row.style.borderBottom = '1px solid var(--border-color)';
        row.innerHTML = `
            <td style="padding: 0.8rem; font-family: var(--font-mono); font-size: 0.8rem;">${p.time}</td>
            <td style="padding: 0.8rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--cyan);">${p.src}</td>
            <td style="padding: 0.8rem; font-family: var(--font-mono); font-size: 0.8rem;">${p.dst}</td>
            <td style="padding: 0.8rem;"><span class="badge-tag badge-info">${p.proto}</span></td>
            <td style="padding: 0.8rem; font-weight: 600;">${p.method} <span style="font-family: var(--font-mono); font-weight: normal; color: #cbd5e1;">${p.path}</span></td>
            <td style="padding: 0.8rem;"><span style="color: ${p.status === 200 ? 'var(--green)' : 'var(--orange)'}; font-family: var(--font-mono);">${p.status}</span></td>
            <td style="padding: 0.8rem; color: var(--text-muted); font-size: 0.85rem;">${p.label}</td>
        `;
        list.appendChild(row);
    });
}

// --- UTILITIES ---
function showToast(msg, type = 'success') {
    const toast = document.createElement('div');
    toast.style.position = 'fixed';
    toast.style.bottom = '2rem';
    toast.style.right = '2rem';
    toast.style.padding = '0.9rem 1.5rem';
    toast.style.borderRadius = '8px';
    toast.style.color = '#fff';
    toast.style.fontFamily = 'Inter, sans-serif';
    toast.style.fontSize = '0.88rem';
    toast.style.fontWeight = '600';
    toast.style.zIndex = '9999';
    toast.style.boxShadow = '0 10px 30px rgba(0,0,0,0.5)';
    toast.style.background = type === 'error' ? 'var(--red)' : '#0f766e';
    toast.style.border = type === 'error' ? '1px solid #ff4d4d' : '1px solid #14b8a6';
    toast.innerHTML = (type === 'error' ? ' ' : ' ') + escapeHtml(msg);

    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// --- DOMAIN MANAGEMENT (ENTERPRISE AUDIT SCOPE) ---

let currentChallengeToken = '';

async function loadDomains() {
    try {
        const res = await fetch(SEC + '/api/domains');
        const data = await res.json();
        const domains = data.domains || [];

        // 1. Populate table in Domains tab
        const tbody = document.getElementById('domains-table-body');
        if (tbody) {
            tbody.innerHTML = '';
            if (domains.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="padding: 1.5rem; text-align: center; color: var(--text-muted);">Aucun domaine d'entreprise enregistré. Ajoutez votre domaine ci-dessus pour démarrer.</td></tr>`;
            } else {
                domains.forEach(d => {
                    const tr = document.createElement('tr');
                    tr.style.borderBottom = '1px solid var(--border-color)';
                    const isVerified = d.is_verified === 1;
                    const statusBadge = isVerified 
                        ? `<span class="badge-tag badge-safe">✓ Vérifié</span>`
                        : `<span class="badge-tag badge-crit"> En attente</span>`;

                    tr.innerHTML = `
                        <td style="padding: 0.75rem; font-weight: 600; font-family: var(--font-mono); color: var(--cyan);">${escapeHtml(d.domain)}</td>
                        <td style="padding: 0.75rem;"><span class="badge-tag badge-info">${escapeHtml(d.verification_method)}</span></td>
                        <td style="padding: 0.75rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(d.verification_token)}</td>
                        <td style="padding: 0.75rem;">${statusBadge}</td>
                        <td style="padding: 0.75rem; font-size: 0.8rem; color: var(--text-muted);">${d.verified_at || 'Non vérifié'}</td>
                        <td style="padding: 0.75rem; text-align: right; display: flex; gap: 0.5rem; justify-content: flex-end;">
                            ${isVerified 
                                ? `<button class="btn btn-primary" style="padding: 0.35rem 0.75rem; font-size: 0.8rem;" onclick="auditThisDomain('${escapeHtml(d.domain)}')"> Auditer</button>` 
                                : `<button class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.8rem;" onclick="verifyDomainNow(${d.id})"> Vérifier</button>`
                            }
                            <button class="btn btn-danger" style="padding: 0.35rem 0.6rem; font-size: 0.8rem;" onclick="deleteDomain(${d.id})"></button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        }

        // 2. Populate quick preset select in Scanner tab
        const presetSelect = document.getElementById('scan-domain-preset');
        if (presetSelect) {
            presetSelect.innerHTML = '<option value="">-- Choisir un domaine autorisé ou le laboratoire --</option>';
            
            // Add lab default
            const labOpt = document.createElement('option');
            labOpt.value = window.location.origin + SEC + '/lab';
            labOpt.textContent = ' InnoTech Mock Lab (Environnement de test local)';
            presetSelect.appendChild(labOpt);

            // Add verified domains
            const verifiedList = domains.filter(d => d.is_verified === 1);
            if (verifiedList.length > 0) {
                const grp = document.createElement('optgroup');
                grp.label = "Domaines Entreprise Vérifiés";
                verifiedList.forEach(d => {
                    const opt = document.createElement('option');
                    opt.value = `https://${d.domain}`;
                    opt.textContent = ` ${d.domain}`;
                    grp.appendChild(opt);
                });
                presetSelect.appendChild(grp);
            }
        }

        // 3. Load schedules table
        loadSchedules();

    } catch (e) {
        console.error("Error loading domains:", e);
    }
}

async function registerDomain() {
    const input = document.getElementById('domain-input');
    const methodSelect = document.getElementById('domain-method-select');
    const domain = (input.value || '').trim();
    const method = methodSelect.value;

    if (!domain) {
        showToast("Veuillez saisir un nom de domaine valide (ex: entreprise.com)", "error");
        return;
    }

    try {
        const res = await fetch(SEC + '/api/domains', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain, verification_method: method })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast(data.error || "Erreur lors de l'enregistrement", "error");
            return;
        }

        showToast(`Domaine ${domain} enregistré. Veuillez compléter la vérification.`, "success");
        input.value = '';
        currentChallengeToken = data.domain.verification_token;

        // Display instructions
        const box = document.getElementById('domain-instructions-box');
        const nameEl = document.getElementById('instr-domain-name');
        const detailsEl = document.getElementById('instr-details');
        
        nameEl.textContent = domain;
        box.style.display = 'block';

        if (method === 'dns_txt') {
            const instr = data.instructions.dns_txt;
            detailsEl.innerHTML = `
                <div><strong>1. Type d'enregistrement DNS :</strong> <code>${instr.record_type}</code></div>
                <div><strong>2. Nom de l'hôte :</strong> <code>${instr.record_name}</code></div>
                <div><strong>3. Valeur du jeton :</strong> <code style="color: var(--cyan); background: rgba(0,0,0,0.5); padding: 2px 6px; border-radius: 4px;">${instr.value}</code></div>
                <div style="margin-top: 0.5rem; color: var(--text-muted); font-size: 0.8rem;">Une fois l'enregistrement ajouté chez votre registrar/DNS, cliquez sur <strong>Vérifier</strong> ci-dessous. La propagation DNS prend généralement de 1 à 5 minutes.</div>
            `;
        } else {
            const instr = data.instructions.http_file;
            detailsEl.innerHTML = `
                <div><strong>1. URL requise :</strong> <code>${instr.url}</code></div>
                <div><strong>2. Contenu exact du fichier :</strong> <code style="color: var(--cyan); background: rgba(0,0,0,0.5); padding: 2px 6px; border-radius: 4px;">${instr.content}</code></div>
                <div style="margin-top: 0.5rem; color: var(--text-muted); font-size: 0.8rem;">Publiez ce fichier texte brut statique, puis cliquez sur <strong>Vérifier</strong> ci-dessous.</div>
            `;
        }

        loadDomains();

    } catch (e) {
        showToast("Erreur réseau: " + e.message, "error");
    }
}

async function verifyDomainNow(id) {
    showToast("Vérification DNS/HTTP en cours...", "success");
    try {
        const res = await fetch(SEC + `/api/domains/${id}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ method: 'auto' })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message || "Domaine vérifié avec succès !", "success");
            loadDomains();
        } else {
            showToast(data.error || "Échec de vérification", "error");
        }
    } catch (e) {
        showToast("Erreur lors de la vérification: " + e.message, "error");
    }
}

async function deleteDomain(id) {
    if (!confirm("Voulez-vous vraiment révoquer l'autorisation d'audit pour ce domaine ?")) return;
    try {
        const res = await fetch(SEC + `/api/domains/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message, "success");
            loadDomains();
        } else {
            showToast(data.error, "error");
        }
    } catch (e) {
        showToast("Erreur: " + e.message, "error");
    }
}

function auditThisDomain(domain) {
    const targetInput = document.getElementById('scan-target-input');
    if (targetInput) {
        targetInput.value = `https://${domain}`;
    }
    switchTab('scanner');
}

function onSelectPresetDomain(val) {
    if (val) {
        document.getElementById('scan-target-input').value = val;
    }
}

function copyChallengeToken() {
    if (!currentChallengeToken) return;
    navigator.clipboard.writeText(currentChallengeToken);
    showToast("Jeton copié dans le presse-papier !", "success");
}

// --- SCHEDULED AUDITS CONTROLLER ---

async function loadSchedules() {
    try {
        const res = await fetch(SEC + '/api/schedules');
        const data = await res.json();
        const schedules = data.schedules || [];
        const tbody = document.getElementById('schedules-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';
        if (schedules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding: 1.25rem; text-align: center; color: var(--text-muted);">Aucune surveillance récurrente programmée. Activez-en une ci-dessus.</td></tr>`;
            return;
        }

        schedules.forEach(s => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-color)';
            const isActive = s.is_active === 1;
            const statusBadge = isActive 
                ? `<span class="badge-tag badge-safe">● Active</span>`
                : `<span class="badge-tag badge-crit"> En pause</span>`;

            tr.innerHTML = `
                <td style="padding: 0.75rem; font-family: var(--font-mono); color: var(--cyan);">${escapeHtml(s.target_url)}</td>
                <td style="padding: 0.75rem;"><span class="badge-tag badge-info">${escapeHtml(s.frequency)}</span></td>
                <td style="padding: 0.75rem; font-size: 0.85rem; color: var(--text-muted);">${s.next_run || 'Dès que possible'}</td>
                <td style="padding: 0.75rem;">${statusBadge}</td>
                <td style="padding: 0.75rem; text-align: right; display: flex; gap: 0.5rem; justify-content: flex-end;">
                    <button class="btn btn-secondary" style="padding: 0.35rem 0.6rem; font-size: 0.8rem;" onclick="toggleSchedule(${s.id}, ${!isActive})">
                        ${isActive ? ' Pause' : ' Reprendre'}
                    </button>
                    <button class="btn btn-danger" style="padding: 0.35rem 0.6rem; font-size: 0.8rem;" onclick="deleteSchedule(${s.id})"></button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading schedules:", e);
    }
}

async function createSchedule() {
    const input = document.getElementById('sched-url-input');
    const freqSelect = document.getElementById('sched-freq-select');
    const url = (input.value || '').trim();
    const freq = freqSelect.value;

    if (!url) {
        showToast("Veuillez saisir l'URL cible à surveiller", "error");
        return;
    }

    try {
        const res = await fetch(SEC + '/api/schedules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: url, frequency: freq })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message || "Surveillance activée avec succès !", "success");
            input.value = '';
            loadSchedules();
        } else {
            showToast(data.error || "Erreur lors de la programmation", "error");
        }
    } catch (e) {
        showToast("Erreur réseau: " + e.message, "error");
    }
}

async function toggleSchedule(id, activeState) {
    try {
        const res = await fetch(SEC + `/api/schedules/${id}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_active: activeState })
        });
        if (res.ok) {
            loadSchedules();
        }
    } catch (e) {
        showToast("Erreur: " + e.message, "error");
    }
}

async function deleteSchedule(id) {
    if (!confirm("Supprimer cette planification de surveillance ?")) return;
    try {
        const res = await fetch(SEC + `/api/schedules/${id}`, { method: 'DELETE' });
        if (res.ok) {
            showToast("Surveillance supprimée", "success");
            loadSchedules();
        }
    } catch (e) {
        showToast("Erreur: " + e.message, "error");
    }
}

// --- PATCH & AUTO-REMEDIATION MODAL CONTROLLER ---

async function openPatchModal() {
    if (!currentScanData || !currentScanData.id) {
        showToast("Aucun rapport d'analyse actif", "error");
        return;
    }
    const modal = document.getElementById('patch-modal');
    modal.style.display = 'flex';
    try {
        const res = await fetch(SEC + `/api/scans/${currentScanData.id}/patch`);
        const data = await res.json();
        document.getElementById('patch-code-nginx').textContent = data.nginx_conf || '# Aucun correctif Nginx requis';
        document.getElementById('patch-code-apache').textContent = data.apache_htaccess || '# Aucun correctif Apache requis';

        const codeContainer = document.getElementById('patch-code-snippets');
        codeContainer.innerHTML = '';
        const patches = data.code_patches || [];
        if (patches.length === 0) {
            codeContainer.innerHTML = '<div style="color: var(--green); padding: 1rem; text-align: center;"> Aucun correctif de code applicatif nécessaire pour ce scan.</div>';
        } else {
            patches.forEach(p => {
                const card = document.createElement('div');
                card.style.background = '#06080e';
                card.style.border = '1px solid var(--border-color)';
                card.style.borderRadius = '8px';
                card.style.padding = '1rem';
                card.style.marginBottom = '1rem';

                let langsHtml = '';
                Object.keys(p.languages).forEach(lang => {
                    const c = p.languages[lang];
                    langsHtml += `
                        <div style="margin-top: 0.5rem;">
                            <div style="font-size: 0.75rem; color: var(--cyan); font-weight: 700; margin-bottom: 0.2rem;">${escapeHtml(lang)} :</div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                                <pre style="background: #1e1010; border: 1px solid #7f1d1d; color: #fca5a5; padding: 0.5rem; font-size: 0.7rem; border-radius: 4px; overflow-x: auto; font-family: var(--font-mono);">${escapeHtml(c.vulnerable)}</pre>
                                <pre style="background: #0f2316; border: 1px solid #14532d; color: #86efac; padding: 0.5rem; font-size: 0.7rem; border-radius: 4px; overflow-x: auto; font-family: var(--font-mono);">${escapeHtml(c.secured)}</pre>
                            </div>
                        </div>
                    `;
                });

                card.innerHTML = `
                    <div style="font-weight: 700; color: #fff; margin-bottom: 0.5rem;"> ${escapeHtml(p.vuln_type)}</div>
                    ${langsHtml}
                `;
                codeContainer.appendChild(card);
            });
        }
    } catch (e) {
        console.error("Error loading patch:", e);
    }
}

function closePatchModal() {
    const modal = document.getElementById('patch-modal');
    if (modal) modal.style.display = 'none';
}

function switchPatchTab(tab) {
    ['nginx', 'apache', 'code'].forEach(t => {
        const btn = document.getElementById(`btn-tab-${t}`);
        const content = document.getElementById(`patch-content-${t}`);
        if (t === tab) {
            btn.className = 'btn btn-primary patch-tab-btn active';
            content.style.display = 'block';
        } else {
            btn.className = 'btn btn-secondary patch-tab-btn';
            content.style.display = 'none';
        }
    });
}

function copyPatchCode(id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent);
    showToast("Configuration copiée dans le presse-papier !", "success");
}

function openCurrentReport() {
    if (currentScanData && currentScanData.id) {
        window.open(SEC + `/api/scans/${currentScanData.id}/report`, '_blank');
    }
}

// --- CI/CD & API KEYS MODULE ---
let ciSnippetsData = { github_actions: '', gitlab_ci: '' };
let currentCiTab = 'github';

async function loadCicdTab() {
    await loadApiKeys();
    await updateCiSnippets();
}

async function loadApiKeys() {
    const tbody = document.getElementById('api-keys-table-body');
    if (!tbody) return;

    try {
        const res = await fetch(SEC + '/api/ci/keys');
        const data = await res.json();
        const keys = data.keys || [];

        if (keys.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                        Aucune clé d'API active. Cliquez sur "+ Générer une Clé d'API" pour connecter vos pipelines.
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = '';
        keys.forEach(k => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-color)';
            tr.innerHTML = `
                <td style="padding: 0.75rem; font-weight: 600; color: #fff;">${escapeHtml(k.name)}</td>
                <td style="padding: 0.75rem; font-family: var(--font-mono); color: var(--cyan);">${escapeHtml(k.prefix)}...</td>
                <td style="padding: 0.75rem; font-size: 0.8rem; color: var(--text-muted);">${k.created_at || 'N/A'}</td>
                <td style="padding: 0.75rem; text-align: right;">
                    <button class="btn btn-danger" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" onclick="revokeApiKey(${k.id}, '${escapeHtml(k.name)}')">
                        Révoquer
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading API keys:", e);
    }
}

async function openCreateApiKeyModal() {
    const name = prompt("Nom de la clé d'API (ex: GitHub Actions Main, GitLab Runner Staging) :");
    if (!name || !name.trim()) return;

    try {
        const res = await fetch(SEC + '/api/ci/keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name.trim() })
        });
        const data = await res.json();
        if (data.success && data.key) {
            const alertBox = document.getElementById('new-key-alert');
            const valEl = document.getElementById('new-api-key-value');
            if (alertBox && valEl) {
                valEl.textContent = data.key.api_key;
                alertBox.style.display = 'block';
            }
            showToast("Clé d'API créée avec succès !", "success");
            loadApiKeys();
        } else {
            showToast(data.error || "Erreur lors de la création de la clé", "error");
        }
    } catch (e) {
        showToast("Erreur réseau", "error");
    }
}

function copyNewApiKey() {
    const valEl = document.getElementById('new-api-key-value');
    if (!valEl || !valEl.textContent) return;
    navigator.clipboard.writeText(valEl.textContent);
    showToast("Clé d'API copiée dans le presse-papier !", "success");
}

async function revokeApiKey(keyId, keyName) {
    if (!confirm(`Confirmez-vous la révocation de la clé d'API "${keyName}" ? Tout pipeline l'utilisant sera immédiatement bloqué.`)) {
        return;
    }

    try {
        const res = await fetch(SEC + `/api/ci/keys/${keyId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showToast("Clé d'API révoquée", "info");
            loadApiKeys();
        }
    } catch (e) {
        showToast("Erreur lors de la révocation", "error");
    }
}

async function updateCiSnippets() {
    const targetInput = document.getElementById('ci-target-input');
    const minScoreInput = document.getElementById('ci-min-score');
    const target = (targetInput && targetInput.value.trim()) ? targetInput.value.trim() : 'https://app.monentreprise.com';
    const minScore = (minScoreInput && minScoreInput.value) ? parseInt(minScoreInput.value) : 75;

    try {
        const res = await fetch(SEC + `/api/ci/snippets?target=${encodeURIComponent(target)}`);
        const data = await res.json();
        ciSnippetsData = data;
        renderCurrentCiSnippet();
    } catch (e) {
        console.error("Error updating CI snippets:", e);
    }
}

function switchCiTab(tab) {
    currentCiTab = tab;
    ['github', 'gitlab', 'curl'].forEach(t => {
        const btn = document.getElementById(`btn-ci-${t}`);
        if (btn) {
            btn.className = (t === tab) ? 'btn btn-primary ci-tab-btn active' : 'btn btn-secondary ci-tab-btn';
        }
    });
    renderCurrentCiSnippet();
}

function renderCurrentCiSnippet() {
    const codeEl = document.getElementById('ci-snippet-code');
    if (!codeEl) return;

    const targetInput = document.getElementById('ci-target-input');
    const minScoreInput = document.getElementById('ci-min-score');
    const target = (targetInput && targetInput.value.trim()) ? targetInput.value.trim() : 'https://app.monentreprise.com';
    const minScore = (minScoreInput && minScoreInput.value) ? parseInt(minScoreInput.value) : 75;
    const apiBase = window.location.origin + SEC;

    if (currentCiTab === 'github') {
        codeEl.textContent = ciSnippetsData.github_actions || `name: CyberLab Security Gate
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: CyberLab DAST & SAST Gate
        run: |
          RESPONSE=$(curl -s -w "\\n%{http_code}" -X POST "${apiBase}/api/ci/scan" \\
            -H "Content-Type: application/json" \\
            -H "X-API-Key: \${{ secrets.CYBERLAB_API_KEY }}" \\
            -d '{"target_url": "${target}", "min_score": ${minScore}, "fail_on_critical": true}')
          HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
          BODY=$(echo "$RESPONSE" | sed '$d')
          echo "$BODY"
          [ "$HTTP_CODE" -eq 200 ] || exit 1`;
    } else if (currentCiTab === 'gitlab') {
        codeEl.textContent = ciSnippetsData.gitlab_ci || `cyberlab_security_gate:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      RES=$(curl -s -w "\\n%{http_code}" -X POST "${apiBase}/api/ci/scan" \\
        -H "Content-Type: application/json" \\
        -H "X-API-Key: $CYBERLAB_API_KEY" \\
        -d '{"target_url": "${target}", "min_score": ${minScore}, "fail_on_critical": true}')
      CODE=$(echo "$RES" | tail -n1)
      echo "$RES" | sed '$d'
      [ "$CODE" -eq 200 ] || exit 1`;
    } else if (currentCiTab === 'curl') {
        codeEl.textContent = `# Exécution manuelle ou via script bash de déploiement
curl -X POST "${apiBase}/api/ci/scan" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: sc_sec_VOTRE_CLE_ICI" \\
  -d '{
    "target_url": "${target}",
    "min_score": ${minScore},
    "fail_on_critical": true
  }'`;
    }
}

function copyCurrentCiSnippet() {
    const codeEl = document.getElementById('ci-snippet-code');
    if (!codeEl) return;
    navigator.clipboard.writeText(codeEl.textContent);
    showToast("Configuration CI/CD copiée !", "success");
}

async function executeCiGateTest() {
    const targetInput = document.getElementById('ci-target-input');
    const minScoreInput = document.getElementById('ci-min-score');
    const resultBox = document.getElementById('ci-gate-test-result');
    const btn = document.getElementById('btn-trigger-ci-gate');

    const target = (targetInput && targetInput.value.trim()) ? targetInput.value.trim() : (window.location.origin + SEC + '/lab');
    const minScore = (minScoreInput && minScoreInput.value) ? parseInt(minScoreInput.value) : 75;

    btn.disabled = true;
    btn.innerHTML = '<span>Test du Gate en cours...</span>';
    resultBox.style.display = 'block';
    resultBox.innerHTML = '<div style="color: var(--cyan);"> Déclenchement de la requête CI/CD Gate vers /api/ci/scan...</div>';

    try {
        // Create an active key for the test
        const keyCreateRes = await fetch(SEC + '/api/ci/keys', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ name: 'Simulateur Gate Console' })
        });
        const keyData = await keyCreateRes.json();
        const activeKey = keyData.key ? keyData.key.api_key : '';

        const res = await fetch(SEC + '/api/ci/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': activeKey
            },
            body: JSON.stringify({
                target_url: target,
                min_score: minScore,
                fail_on_critical: true
            })
        });

        const data = await res.json();
        loadApiKeys(); // Refresh key table

        const isPassed = res.status === 200 && data.status === 'PASSED';
        const badge = isPassed 
            ? '<span class="badge-tag badge-safe" style="font-size: 0.9rem;"> BUILD VALIDÉ (HTTP 200 - Exit Code 0)</span>'
            : `<span class="badge-tag badge-crit" style="font-size: 0.9rem;"> BUILD REJETÉ (HTTP ${res.status} - Exit Code 1)</span>`;

        resultBox.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                ${badge}
                <span style="font-size: 0.85rem; color: var(--text-muted);">Score obtenu : <strong style="color: #fff;">${data.risk_score !== undefined ? data.risk_score : 'N/A'}/100</strong> (Seuil requis : ${minScore}/100)</span>
            </div>
            <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">${escapeHtml(data.message || '')}</div>
            <pre style="background: #04060a; padding: 0.75rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.75rem; color: #94a3b8; overflow-x: auto; max-height: 160px; margin: 0;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
        `;

    } catch (e) {
        resultBox.innerHTML = `<div style="color: var(--red);">Erreur lors du test : ${escapeHtml(e.message)}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>Tester le Gate CI/CD</span>';
    }
}
