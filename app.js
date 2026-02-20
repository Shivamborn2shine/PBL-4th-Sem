/**
 * SentinelSphere – Frontend Application Logic
 *
 * Handles API communication, form submission, result rendering,
 * and dashboard state management.
 */

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════

const CONFIG = {
    // Update this to your API Gateway URL after deployment
    API_BASE_URL: '', // e.g., 'https://abc123.execute-api.us-east-1.amazonaws.com/prod'
    MOCK_MODE: true,  // Set to false when API is deployed
};

// ═══════════════════════════════════════════════════════════════════
// State Management
// ═══════════════════════════════════════════════════════════════════

const state = {
    history: JSON.parse(localStorage.getItem('sentinelsphere_history') || '[]'),
    graphData: JSON.parse(localStorage.getItem('sentinelsphere_graph') || '{"nodes":[],"edges":[]}'),
    stats: {
        totalScans: 0,
        threatsFound: 0,
        safeCount: 0,
    },
    currentQrBase64: null,
};

// ═══════════════════════════════════════════════════════════════════
// Tab Navigation
// ═══════════════════════════════════════════════════════════════════

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        // Update tabs
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        // Update panels
        const tabName = tab.dataset.tab;
        document.querySelectorAll('.scan-panel').forEach(p => p.classList.remove('active'));
        document.getElementById('panelGraphViz').style.display = 'none';
        document.getElementById('panelHistoryTable').style.display = 'none';
        document.getElementById('resultsPanel').style.display =
            document.getElementById('resultsPanel').classList.contains('visible') ? 'block' : 'none';
        document.getElementById('defaultEmpty').style.display = 'block';

        if (tabName === 'url') {
            document.getElementById('panelUrl').classList.add('active');
        } else if (tabName === 'email') {
            document.getElementById('panelEmail').classList.add('active');
        } else if (tabName === 'qr') {
            document.getElementById('panelQr').classList.add('active');
        } else if (tabName === 'graph') {
            document.getElementById('panelGraphInput').classList.add('active');
            document.getElementById('panelGraphViz').style.display = 'block';
            document.getElementById('defaultEmpty').style.display = 'none';
            document.getElementById('resultsPanel').style.display = 'none';
            if (typeof renderGraph === 'function') renderGraph(state.graphData);
        } else if (tabName === 'history') {
            document.getElementById('panelHistoryInput').classList.add('active');
            document.getElementById('panelHistoryTable').style.display = 'block';
            document.getElementById('defaultEmpty').style.display = 'none';
            document.getElementById('resultsPanel').style.display = 'none';
            renderHistory();
        }
    });
});

// ═══════════════════════════════════════════════════════════════════
// URL Scanning
// ═══════════════════════════════════════════════════════════════════

async function scanUrl() {
    const url = document.getElementById('urlInput').value.trim();
    const userId = document.getElementById('urlUserId').value.trim() || 'anonymous';

    if (!url) {
        shakeInput('urlInput');
        return;
    }

    const btn = document.getElementById('btnScanUrl');
    setLoading(btn, true);

    try {
        let result;
        if (CONFIG.MOCK_MODE) {
            result = await mockScanUrl(url, userId);
        } else {
            const response = await fetch(`${CONFIG.API_BASE_URL}/api/v1/scan-url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, url }),
            });
            result = await response.json();
        }

        displayResults(result);
        addToHistory('URL', url, result);
        updateGraphFromScan('URL', url, userId, result);

    } catch (error) {
        console.error('Scan URL error:', error);
        showError('Failed to scan URL. Check your connection and try again.');
    } finally {
        setLoading(btn, false);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Email Scanning
// ═══════════════════════════════════════════════════════════════════

async function scanEmail() {
    const emailText = document.getElementById('emailInput').value.trim();
    const userId = document.getElementById('emailUserId').value.trim() || 'anonymous';

    if (!emailText) {
        shakeInput('emailInput');
        return;
    }

    const btn = document.getElementById('btnScanEmail');
    setLoading(btn, true);

    try {
        let result;
        if (CONFIG.MOCK_MODE) {
            result = await mockScanEmail(emailText, userId);
        } else {
            const response = await fetch(`${CONFIG.API_BASE_URL}/api/v1/scan-email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, email_text: emailText }),
            });
            result = await response.json();
        }

        displayResults(result);
        addToHistory('EMAIL', emailText.substring(0, 80) + '...', result);

    } catch (error) {
        console.error('Scan email error:', error);
        showError('Failed to scan email. Check your connection and try again.');
    } finally {
        setLoading(btn, false);
    }
}

// ═══════════════════════════════════════════════════════════════════
// QR Code Scanning
// ═══════════════════════════════════════════════════════════════════

function handleQrUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        state.currentQrBase64 = e.target.result;

        // Show preview
        const preview = document.getElementById('qrPreview');
        preview.src = e.target.result;
        preview.classList.add('visible');

        // Enable scan button
        document.getElementById('btnScanQr').disabled = false;
    };
    reader.readAsDataURL(file);
}

// Drag and drop support
const dropZone = document.getElementById('qrDropZone');
if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) {
            const input = document.getElementById('qrFileInput');
            const dt = new DataTransfer();
            dt.items.add(file);
            input.files = dt.files;
            handleQrUpload({ target: input });
        }
    });
}

async function scanQr() {
    if (!state.currentQrBase64) return;

    const userId = document.getElementById('qrUserId').value.trim() || 'anonymous';
    const btn = document.getElementById('btnScanQr');
    setLoading(btn, true);

    try {
        let result;
        if (CONFIG.MOCK_MODE) {
            result = await mockScanQr(state.currentQrBase64, userId);
        } else {
            const response = await fetch(`${CONFIG.API_BASE_URL}/api/v1/scan-qr`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: userId,
                    image_base64: state.currentQrBase64,
                }),
            });
            result = await response.json();
        }

        displayResults(result);
        addToHistory('QR', result.extracted_url || 'QR Code', result);
        if (result.extracted_url) {
            updateGraphFromScan('QR', result.extracted_url, userId, result);
        }

    } catch (error) {
        console.error('Scan QR error:', error);
        showError('Failed to scan QR code. Check your connection and try again.');
    } finally {
        setLoading(btn, false);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Results Display
// ═══════════════════════════════════════════════════════════════════

function displayResults(result) {
    const panel = document.getElementById('resultsPanel');
    const defaultEmpty = document.getElementById('defaultEmpty');

    defaultEmpty.style.display = 'none';
    panel.classList.add('visible');

    // ── Risk Gauge ───────────────────────────────────────────────
    const score = result.risk_score || 0;
    const level = result.risk_level || 'SAFE';
    const percent = Math.round(score * 100);

    const gaugeCircle = document.getElementById('gaugeCircle');
    const gaugeColor = level === 'HIGH' ? '#ef4444' :
        level === 'SUSPICIOUS' ? '#f59e0b' : '#10b981';

    gaugeCircle.style.setProperty('--gauge-color', gaugeColor);
    gaugeCircle.style.setProperty('--gauge-percent', `${percent}%`);
    gaugeCircle.style.background = `radial-gradient(circle, ${gaugeColor}11, transparent 70%)`;

    // Animate score counter
    animateCounter('gaugeScore', score, 1.2);

    document.getElementById('gaugeLabel').textContent = 'RISK SCORE';

    // Risk badge
    const badge = document.getElementById('riskBadge');
    badge.className = 'risk-level-badge ' +
        (level === 'HIGH' ? 'risk-high' : level === 'SUSPICIOUS' ? 'risk-suspicious' : 'risk-safe');
    document.getElementById('riskIcon').textContent =
        level === 'HIGH' ? '🚨' : level === 'SUSPICIOUS' ? '⚠️' : '✅';
    document.getElementById('riskText').textContent = level;

    // ── Score Breakdown ──────────────────────────────────────────
    const breakdown = result.score_breakdown || {};
    const breakdownEl = document.getElementById('scoreBreakdown');
    breakdownEl.innerHTML = '';

    const scoreItems = [
        { key: 'ml_score', label: 'ML Score', color: '#8b5cf6' },
        { key: 'reputation_score', label: 'Reputation', color: '#f59e0b' },
        { key: 'graph_score', label: 'Graph Score', color: '#06b6d4' },
        { key: 'rule_based_score', label: 'Rule Based', color: '#3b82f6' },
    ];

    scoreItems.forEach(item => {
        const val = breakdown[item.key] || 0;
        const pct = Math.round(val * 100);
        const div = document.createElement('div');
        div.className = 'score-item';
        div.innerHTML = `
            <div class="score-item-label">${item.label}</div>
            <div class="score-item-value" style="color: ${item.color}">${val.toFixed(2)}</div>
            <div class="score-item-bar">
                <div class="score-item-fill" style="width: ${pct}%; background: ${item.color};"></div>
            </div>
        `;
        breakdownEl.appendChild(div);
    });

    // ── Explanations ─────────────────────────────────────────────
    const explanations = result.explanation || [];
    const listEl = document.getElementById('explanationsList');
    listEl.innerHTML = '';

    explanations.forEach(exp => {
        const div = document.createElement('div');
        div.className = 'explanation-item';
        div.innerHTML = `
            <span class="explanation-icon">${level === 'HIGH' ? '🔴' : level === 'SUSPICIOUS' ? '🟡' : '🟢'}</span>
            <span>${exp}</span>
        `;
        listEl.appendChild(div);
    });
}

// ═══════════════════════════════════════════════════════════════════
// Animation Helpers
// ═══════════════════════════════════════════════════════════════════

function animateCounter(elementId, targetValue, duration = 1) {
    const el = document.getElementById(elementId);
    const start = 0;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = (currentTime - startTime) / 1000;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const current = start + (targetValue - start) * eased;
        el.textContent = current.toFixed(2);
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

function setLoading(btn, loading) {
    if (loading) {
        btn.classList.add('loading');
        btn.disabled = true;
    } else {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
}

function shakeInput(inputId) {
    const input = document.getElementById(inputId);
    input.style.borderColor = '#ef4444';
    input.style.animation = 'shake 0.4s ease';
    setTimeout(() => {
        input.style.borderColor = '';
        input.style.animation = '';
    }, 500);
}

function showError(message) {
    const panel = document.getElementById('resultsPanel');
    const defaultEmpty = document.getElementById('defaultEmpty');
    defaultEmpty.style.display = 'none';
    panel.classList.add('visible');

    document.getElementById('gaugeScore').textContent = 'ERR';
    document.getElementById('gaugeLabel').textContent = message;
    document.getElementById('gaugeCircle').style.setProperty('--gauge-color', '#ef4444');
    document.getElementById('gaugeCircle').style.setProperty('--gauge-percent', '100%');
}

// ═══════════════════════════════════════════════════════════════════
// History Management
// ═══════════════════════════════════════════════════════════════════

function addToHistory(type, input, result) {
    const entry = {
        id: Date.now(),
        type,
        input: input.length > 60 ? input.substring(0, 60) + '...' : input,
        risk_score: result.risk_score,
        risk_level: result.risk_level,
        timestamp: new Date().toLocaleString(),
    };

    state.history.unshift(entry);
    if (state.history.length > 50) state.history = state.history.slice(0, 50);
    localStorage.setItem('sentinelsphere_history', JSON.stringify(state.history));

    updateStats();
}

function renderHistory() {
    const tbody = document.getElementById('historyBody');
    const empty = document.getElementById('historyEmpty');

    if (state.history.length === 0) {
        tbody.innerHTML = '';
        empty.style.display = 'block';
        return;
    }

    empty.style.display = 'none';
    tbody.innerHTML = state.history.map(entry => {
        const levelClass = entry.risk_level === 'HIGH' ? 'risk-high' :
            entry.risk_level === 'SUSPICIOUS' ? 'risk-suspicious' : 'risk-safe';
        const levelColor = entry.risk_level === 'HIGH' ? '#ef4444' :
            entry.risk_level === 'SUSPICIOUS' ? '#f59e0b' : '#10b981';
        return `
            <tr>
                <td><span class="history-type">${entry.type}</span></td>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--font-mono); font-size: 0.75rem;">${entry.input}</td>
                <td><span class="history-score" style="color: ${levelColor}">${(entry.risk_score || 0).toFixed(2)}</span></td>
                <td><span class="risk-level-badge ${levelClass}" style="font-size: 0.65rem; padding: 2px 8px;">${entry.risk_level}</span></td>
                <td style="font-size: 0.75rem; color: var(--text-muted);">${entry.timestamp}</td>
            </tr>
        `;
    }).join('');
}

function clearHistory() {
    state.history = [];
    state.graphData = { nodes: [], edges: [] };
    localStorage.setItem('sentinelsphere_history', '[]');
    localStorage.setItem('sentinelsphere_graph', JSON.stringify(state.graphData));
    updateStats();
    renderHistory();
    if (typeof renderGraph === 'function') renderGraph(state.graphData);
}

// ═══════════════════════════════════════════════════════════════════
// Stats Update
// ═══════════════════════════════════════════════════════════════════

function updateStats() {
    const total = state.history.length;
    const threats = state.history.filter(h => h.risk_level === 'HIGH').length;
    const safe = state.history.filter(h => h.risk_level === 'SAFE').length;
    const nodes = state.graphData.nodes ? state.graphData.nodes.length : 0;

    document.getElementById('totalScans').textContent = total;
    document.getElementById('threatsFound').textContent = threats;
    document.getElementById('safeCount').textContent = safe;
    document.getElementById('graphNodes').textContent = nodes;
}

// ═══════════════════════════════════════════════════════════════════
// Graph Data Management
// ═══════════════════════════════════════════════════════════════════

function updateGraphFromScan(type, input, userId, result) {
    const domain = result.domain || extractDomain(input);

    // Add nodes
    addGraphNode(`user:${userId}`, 'USER', userId);
    addGraphNode(`domain:${domain}`, 'DOMAIN', domain);

    // Add edges
    addGraphEdge(`user:${userId}`, `domain:${domain}`, 'scanned');

    // Simulated IP
    const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    addGraphNode(`ip:${ip}`, 'IP', ip);
    addGraphEdge(`domain:${domain}`, `ip:${ip}`, 'resolves_to');

    localStorage.setItem('sentinelsphere_graph', JSON.stringify(state.graphData));
    updateStats();
}

function addGraphNode(id, type, label) {
    if (!state.graphData.nodes.find(n => n.id === id)) {
        state.graphData.nodes.push({ id, type, label });
    }
}

function addGraphEdge(source, target, relation) {
    const exists = state.graphData.edges.find(e => e.source === source && e.target === target);
    if (!exists) {
        state.graphData.edges.push({ source, target, relation });
    }
}

function extractDomain(url) {
    try {
        const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
        return parsed.hostname;
    } catch {
        return url;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Mock API Functions (for local testing without backend)
// ═══════════════════════════════════════════════════════════════════

async function mockScanUrl(url, userId) {
    await delay(800 + Math.random() * 700);

    const urlLower = url.toLowerCase();
    const features = {
        hasHttps: url.startsWith('https'),
        urlLength: url.length,
        numDots: (url.match(/\./g) || []).length,
        hasAt: url.includes('@'),
        hasSuspiciousWords: /login|verify|secure|account|update|password|confirm|banking/.test(urlLower),
        hasSuspiciousTld: /\.(tk|ml|ga|cf|xyz|top|pw|click)/.test(urlLower),
        hasIpAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url),
    };

    // Calculate mock scores
    let mlScore = 0.1;
    let ruleScore = 0;

    if (!features.hasHttps) { mlScore += 0.15; ruleScore += 0.15; }
    if (features.urlLength > 100) { mlScore += 0.1; ruleScore += 0.1; }
    if (features.numDots > 4) { mlScore += 0.1; ruleScore += 0.1; }
    if (features.hasAt) { mlScore += 0.2; ruleScore += 0.15; }
    if (features.hasSuspiciousWords) { mlScore += 0.25; ruleScore += 0.2; }
    if (features.hasSuspiciousTld) { mlScore += 0.2; ruleScore += 0.15; }
    if (features.hasIpAddress) { mlScore += 0.2; ruleScore += 0.2; }

    mlScore = Math.min(mlScore + Math.random() * 0.05, 1.0);
    ruleScore = Math.min(ruleScore, 1.0);
    const repScore = Math.random() * 0.4;
    const graphScore = Math.random() * 0.3;

    const finalScore = (mlScore * 0.4) + (repScore * 0.2) + (graphScore * 0.2) + (ruleScore * 0.2);
    const riskLevel = finalScore < 0.3 ? 'SAFE' : finalScore < 0.6 ? 'SUSPICIOUS' : 'HIGH';

    const explanations = [];
    if (!features.hasHttps) explanations.push('Connection not secured with HTTPS');
    if (features.hasSuspiciousWords) explanations.push('Suspicious keyword detected in URL');
    if (features.hasAt) explanations.push('URL contains @ symbol (potential redirect)');
    if (features.hasIpAddress) explanations.push('URL uses IP address instead of domain name');
    if (features.hasSuspiciousTld) explanations.push('Domain uses suspicious top-level domain');
    if (features.urlLength > 100) explanations.push('Unusually long URL detected');
    if (features.numDots > 4) explanations.push('Excessive subdomains detected');
    if (explanations.length === 0) explanations.push('No specific threat indicators found');

    return {
        report_id: crypto.randomUUID(),
        risk_score: Math.round(finalScore * 100) / 100,
        risk_level: riskLevel,
        explanation: explanations,
        graph_suspicion: Math.round(graphScore * 100) / 100,
        score_breakdown: {
            ml_score: Math.round(mlScore * 100) / 100,
            reputation_score: Math.round(repScore * 100) / 100,
            graph_score: Math.round(graphScore * 100) / 100,
            rule_based_score: Math.round(ruleScore * 100) / 100,
        },
        confidence: 0.85,
        domain: extractDomain(url),
        timestamp: new Date().toISOString(),
    };
}

async function mockScanEmail(emailText, userId) {
    await delay(800 + Math.random() * 700);

    const textLower = emailText.toLowerCase();
    const urgencyWords = ['urgent', 'immediately', 'asap', 'act now', 'hurry', 'expires', 'deadline'];
    const financialWords = ['bank', 'account', 'credit card', 'payment', 'transfer', 'invoice'];

    let urgencyCount = urgencyWords.filter(w => textLower.includes(w)).length;
    let financialCount = financialWords.filter(w => textLower.includes(w)).length;
    let exclFreq = (emailText.match(/!/g) || []).length / Math.max(emailText.length, 1);
    let urlCount = (emailText.match(/https?:\/\/\S+/g) || []).length;

    let mlScore = 0.1;
    let ruleScore = 0;

    if (urgencyCount > 2) { mlScore += 0.3; ruleScore += 0.25; }
    else if (urgencyCount > 0) { mlScore += 0.15; ruleScore += 0.1; }

    if (financialCount > 2) { mlScore += 0.25; ruleScore += 0.2; }
    else if (financialCount > 0) { mlScore += 0.1; ruleScore += 0.1; }

    if (exclFreq > 0.02) { mlScore += 0.1; ruleScore += 0.1; }
    if (urlCount > 3) { mlScore += 0.15; ruleScore += 0.15; }

    mlScore = Math.min(mlScore + Math.random() * 0.05, 1.0);
    ruleScore = Math.min(ruleScore, 1.0);
    const repScore = Math.random() * 0.3;
    const graphScore = Math.random() * 0.2;

    const finalScore = (mlScore * 0.4) + (repScore * 0.2) + (graphScore * 0.2) + (ruleScore * 0.2);
    const riskLevel = finalScore < 0.3 ? 'SAFE' : finalScore < 0.6 ? 'SUSPICIOUS' : 'HIGH';

    const explanations = [];
    if (urgencyCount > 0) explanations.push('Urgency keyword detected');
    if (financialCount > 0) explanations.push('Financial terminology detected');
    if (exclFreq > 0.02) explanations.push('Excessive exclamation marks detected');
    if (urlCount > 3) explanations.push('Multiple URLs embedded in email');
    if (explanations.length === 0) explanations.push('No specific phishing indicators found');

    return {
        report_id: crypto.randomUUID(),
        risk_score: Math.round(finalScore * 100) / 100,
        risk_level: riskLevel,
        explanation: explanations,
        score_breakdown: {
            ml_score: Math.round(mlScore * 100) / 100,
            reputation_score: Math.round(repScore * 100) / 100,
            graph_score: Math.round(graphScore * 100) / 100,
            rule_based_score: Math.round(ruleScore * 100) / 100,
        },
        confidence: 0.78,
        timestamp: new Date().toISOString(),
    };
}

async function mockScanQr(imageBase64, userId) {
    await delay(1000 + Math.random() * 500);

    // Simulate extracted URL
    const mockUrls = [
        'http://free-prize.tk/claim?token=abc123',
        'https://secure-login.verify-account.xyz/auth',
        'https://google.com',
        'http://192.168.1.1/admin/login',
        'https://github.com/security',
    ];
    const extractedUrl = mockUrls[Math.floor(Math.random() * mockUrls.length)];

    // Delegate to URL scan mock
    const urlResult = await mockScanUrl(extractedUrl, userId);

    return {
        ...urlResult,
        extracted_url: extractedUrl,
        qr_raw_data: extractedUrl,
    };
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ═══════════════════════════════════════════════════════════════════
// CSS Animation for shake
// ═══════════════════════════════════════════════════════════════════

const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-6px); }
        75% { transform: translateX(6px); }
    }
`;
document.head.appendChild(style);

// ═══════════════════════════════════════════════════════════════════
// Initialize
// ═══════════════════════════════════════════════════════════════════

updateStats();
