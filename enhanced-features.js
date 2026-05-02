/**
 * Observe4U – Enhanced Features Module (v2.0)
 * Adds: particles, toasts, analytics, bulk scan, export, feed, shortcuts
 */

// ═══════════════════════════════════════════════════════════════
// Particle Background
// ═══════════════════════════════════════════════════════════════
(function initParticles() {
    const canvas = document.getElementById('particleCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let particles = [], w, h;
    function resize() { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight; }
    resize(); window.addEventListener('resize', resize);
    for (let i = 0; i < 60; i++) {
        particles.push({ x: Math.random()*w, y: Math.random()*h, vx: (Math.random()-0.5)*0.4, vy: (Math.random()-0.5)*0.4, r: Math.random()*2+1 });
    }
    function draw() {
        ctx.clearRect(0, 0, w, h);
        particles.forEach((p, i) => {
            p.x += p.vx; p.y += p.vy;
            if (p.x < 0 || p.x > w) p.vx *= -1;
            if (p.y < 0 || p.y > h) p.vy *= -1;
            ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
            ctx.fillStyle = 'rgba(6,182,212,0.4)'; ctx.fill();
            for (let j = i+1; j < particles.length; j++) {
                const dx = p.x - particles[j].x, dy = p.y - particles[j].y;
                const dist = Math.sqrt(dx*dx + dy*dy);
                if (dist < 150) {
                    ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(6,182,212,${0.15*(1-dist/150)})`; ctx.lineWidth = 0.5; ctx.stroke();
                }
            }
        });
        requestAnimationFrame(draw);
    }
    draw();
})();

// ═══════════════════════════════════════════════════════════════
// Real-Time Clock
// ═══════════════════════════════════════════════════════════════
setInterval(() => {
    const el = document.getElementById('headerClock');
    if (el) el.textContent = new Date().toLocaleTimeString();
}, 1000);

// ═══════════════════════════════════════════════════════════════
// Toast Notification System
// ═══════════════════════════════════════════════════════════════
function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span class="toast-icon">${icons[type]||'ℹ️'}</span><span>${message}</span><span class="toast-close" onclick="this.parentElement.classList.add('removing');setTimeout(()=>this.parentElement.remove(),300)">✕</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.classList.add('removing'); setTimeout(() => toast.remove(), 300); }, duration);
}

// ═══════════════════════════════════════════════════════════════
// Result Tab Switching
// ═══════════════════════════════════════════════════════════════
function switchResultTab(tab) {
    document.querySelectorAll('.result-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.result-pane').forEach(p => p.classList.remove('active'));
    document.querySelector(`.result-tab[onclick*="${tab}"]`)?.classList.add('active');
    const paneMap = { overview: 'resultOverview', signals: 'resultSignals', json: 'resultJson' };
    document.getElementById(paneMap[tab])?.classList.add('active');
}

// ═══════════════════════════════════════════════════════════════
// Export Functions
// ═══════════════════════════════════════════════════════════════
let _lastScanResult = null;

function exportReport(format) {
    if (!_lastScanResult) { showToast('No scan result to export', 'warning'); return; }
    if (format === 'json') {
        const blob = new Blob([JSON.stringify(_lastScanResult, null, 2)], { type: 'application/json' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
        a.download = `observe4u-report-${Date.now()}.json`; a.click();
        showToast('Report exported as JSON', 'success');
    } else {
        const r = _lastScanResult;
        const text = `Observe4U Threat Report\n${'='.repeat(40)}\nRisk Score: ${r.risk_score}\nRisk Level: ${r.risk_level}\nConfidence: ${r.confidence}\nTimestamp: ${r.timestamp}\n\nScore Breakdown:\n- ML Score: ${r.score_breakdown?.ml_score}\n- Reputation: ${r.score_breakdown?.reputation_score}\n- Graph: ${r.score_breakdown?.graph_score}\n- Rule Based: ${r.score_breakdown?.rule_based_score}\n\nExplanations:\n${(r.explanation||[]).map(e=>'• '+e).join('\n')}`;
        navigator.clipboard.writeText(text).then(() => showToast('Report copied to clipboard', 'success'));
    }
}

function exportHistory() {
    if (!state.history.length) { showToast('No history to export', 'warning'); return; }
    const blob = new Blob([JSON.stringify(state.history, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `observe4u-history-${Date.now()}.json`; a.click();
    showToast('History exported', 'success');
}

// ═══════════════════════════════════════════════════════════════
// History Search & Filter
// ═══════════════════════════════════════════════════════════════
let _historyFilter = 'all';

function setHistoryFilter(filter, btn) {
    _historyFilter = filter;
    document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
    btn?.classList.add('active');
    filterHistory();
}

function filterHistory() {
    const search = (document.getElementById('historySearch')?.value || '').toLowerCase();
    const filtered = state.history.filter(entry => {
        const matchesFilter = _historyFilter === 'all' || entry.type === _historyFilter;
        const matchesSearch = !search || entry.input.toLowerCase().includes(search) || entry.type.toLowerCase().includes(search);
        return matchesFilter && matchesSearch;
    });
    renderFilteredHistory(filtered);
}

function renderFilteredHistory(entries) {
    const tbody = document.getElementById('historyBody');
    const empty = document.getElementById('historyEmpty');
    if (!entries.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
    empty.style.display = 'none';
    tbody.innerHTML = entries.map(entry => {
        const lc = entry.risk_level === 'HIGH' ? 'risk-high' : entry.risk_level === 'SUSPICIOUS' ? 'risk-suspicious' : 'risk-safe';
        const color = entry.risk_level === 'HIGH' ? '#ef4444' : entry.risk_level === 'SUSPICIOUS' ? '#f59e0b' : '#10b981';
        return `<tr><td><span class="history-type">${entry.type}</span></td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono);font-size:0.75rem;">${entry.input}</td><td><span class="history-score" style="color:${color}">${(entry.risk_score||0).toFixed(2)}</span></td><td><span class="risk-level-badge ${lc}" style="font-size:0.65rem;padding:2px 8px;">${entry.risk_level}</span></td><td style="font-size:0.75rem;color:var(--text-muted);">${entry.timestamp}</td></tr>`;
    }).join('');
}

// ═══════════════════════════════════════════════════════════════
// Bulk URL Scanning
// ═══════════════════════════════════════════════════════════════
async function bulkScan() {
    const input = document.getElementById('bulkInput')?.value.trim();
    if (!input) { showToast('Enter URLs to scan', 'warning'); return; }
    const urls = input.split('\n').map(u => u.trim()).filter(u => u.length > 0);
    if (!urls.length) { showToast('No valid URLs found', 'warning'); return; }

    const btn = document.getElementById('btnBulkScan');
    const progress = document.getElementById('bulkProgress');
    const fill = document.getElementById('bulkProgressFill');
    const results = document.getElementById('bulkResults');
    setLoading(btn, true); progress.style.display = 'block'; results.innerHTML = '';
    showToast(`Scanning ${urls.length} URLs...`, 'info');

    for (let i = 0; i < urls.length; i++) {
        fill.style.width = `${((i+1)/urls.length)*100}%`;
        try {
            let result;
            if (CONFIG.MOCK_MODE) { result = await mockScanUrl(urls[i], 'bulk-user'); }
            else {
                const resp = await fetch(`${CONFIG.API_BASE_URL}/api/v1/scan-url`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({user_id:'bulk-user',url:urls[i]}) });
                result = await resp.json();
            }
            addToHistory('URL', urls[i], result);
            updateGraphFromScan('URL', urls[i], 'bulk-user', result);
            const lc = result.risk_level === 'HIGH' ? 'high' : result.risk_level === 'SUSPICIOUS' ? 'suspicious' : 'safe';
            const color = result.risk_level === 'HIGH' ? '#ef4444' : result.risk_level === 'SUSPICIOUS' ? '#f59e0b' : '#10b981';
            results.innerHTML += `<div class="bulk-item"><span class="bulk-item-url">${urls[i]}</span><span style="color:${color};font-family:var(--font-mono);font-weight:700;">${result.risk_score.toFixed(2)}</span><span class="risk-level-badge ${lc === 'high' ? 'risk-high' : lc === 'suspicious' ? 'risk-suspicious' : 'risk-safe'}" style="font-size:0.65rem;padding:2px 8px;">${result.risk_level}</span></div>`;
        } catch(e) {
            results.innerHTML += `<div class="bulk-item"><span class="bulk-item-url">${urls[i]}</span><span style="color:#ef4444;">Error</span></div>`;
        }
    }
    setLoading(btn, false);
    showToast(`Bulk scan complete: ${urls.length} URLs analyzed`, 'success');
    updateAnalytics();
}

// ═══════════════════════════════════════════════════════════════
// Analytics (Donut Chart + Trend Bars)
// ═══════════════════════════════════════════════════════════════
function updateAnalytics() {
    const safe = state.history.filter(h => h.risk_level === 'SAFE').length;
    const suspicious = state.history.filter(h => h.risk_level === 'SUSPICIOUS').length;
    const high = state.history.filter(h => h.risk_level === 'HIGH').length;
    const total = state.history.length || 1;

    // Update avg risk stat
    const avg = state.history.length ? state.history.reduce((s,h) => s + (h.risk_score||0), 0) / state.history.length : 0;
    const avgEl = document.getElementById('avgRisk');
    if (avgEl) avgEl.textContent = avg.toFixed(2);

    // Update last scan time
    const lastEl = document.getElementById('lastScanTime');
    if (lastEl && state.history.length) {
        const t = state.history[0].timestamp;
        lastEl.textContent = t ? t.split(',')[1]?.trim() || t.split(' ')[1] || t : '--';
    }

    // Donut chart (CSS conic-gradient)
    const donut = document.getElementById('donutChart');
    if (donut) {
        const sp = (safe/total)*100, sup = (suspicious/total)*100, hp = (high/total)*100;
        donut.style.background = total <= 1 && !state.history.length
            ? 'rgba(255,255,255,0.05)'
            : `conic-gradient(#10b981 0% ${sp}%, #f59e0b ${sp}% ${sp+sup}%, #ef4444 ${sp+sup}% 100%)`;
        donut.innerHTML = `<div class="donut-center"><div class="value" style="color:var(--text-primary)">${state.history.length}</div><div class="label">Total Scans</div></div>`;
    }

    // Trend bars
    const trendEl = document.getElementById('trendBars');
    if (trendEl) {
        const sessions = JSON.parse(localStorage.getItem('observe4u_sessions') || '[]');
        sessions.push(state.history.length);
        if (sessions.length > 7) sessions.splice(0, sessions.length - 7);
        localStorage.setItem('observe4u_sessions', JSON.stringify(sessions));
        const max = Math.max(...sessions, 1);
        trendEl.innerHTML = sessions.map((v, i) => {
            const pct = (v/max)*100;
            const color = v > max*0.7 ? '#ef4444' : v > max*0.4 ? '#f59e0b' : '#10b981';
            return `<div class="trend-bar-item"><div class="trend-bar-label">S${i+1}</div><div class="trend-bar-track"><div class="trend-bar-fill" style="width:${pct}%;background:${color}"></div></div><div class="trend-bar-value" style="color:${color}">${v}</div></div>`;
        }).join('');
    }
}

// ═══════════════════════════════════════════════════════════════
// Live Threat Feed
// ═══════════════════════════════════════════════════════════════
function initThreatFeed() {
    const feedEl = document.getElementById('feedScroll');
    if (!feedEl) return;
    const mockItems = [
        { domain: 'suspicious-login.tk', level: 'high' },
        { domain: 'google.com', level: 'safe' },
        { domain: 'verify-account.xyz', level: 'high' },
        { domain: 'github.com', level: 'safe' },
        { domain: 'free-prize.win', level: 'suspicious' },
        { domain: 'stackoverflow.com', level: 'safe' },
        { domain: 'paypal-secure.ga', level: 'high' },
        { domain: 'amazon.com', level: 'safe' },
        { domain: 'update-now.click', level: 'suspicious' },
        { domain: 'wikipedia.org', level: 'safe' },
    ];
    const items = [...mockItems, ...mockItems].map(item =>
        `<span class="feed-item"><span class="feed-badge ${item.level}">${item.level.toUpperCase()}</span>${item.domain}</span>`
    ).join('');
    feedEl.innerHTML = items;
}
initThreatFeed();

// ═══════════════════════════════════════════════════════════════
// Keyboard Shortcuts
// ═══════════════════════════════════════════════════════════════
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        const activeTab = document.querySelector('.tab.active')?.dataset.tab;
        if (activeTab === 'url') scanUrl();
        else if (activeTab === 'email') scanEmail();
        else if (activeTab === 'qr') scanQr();
        else if (activeTab === 'bulk') bulkScan();
    }
    if (e.ctrlKey && e.key === 'e') { e.preventDefault(); exportReport('json'); }
});

// ═══════════════════════════════════════════════════════════════
// Enhanced Tab Navigation (extend existing)
// ═══════════════════════════════════════════════════════════════
(function patchTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;
            if (tabName === 'bulk') {
                document.getElementById('panelBulk')?.classList.add('active');
            }
        });
    });
})();

// ═══════════════════════════════════════════════════════════════
// Patch existing functions to integrate enhancements
// ═══════════════════════════════════════════════════════════════

// Store original displayResults and wrap it
const _origDisplayResults = typeof displayResults === 'function' ? displayResults : null;

// Override to also store result + update JSON + analytics
const _patchDisplayResults = () => {
    if (!_origDisplayResults) return;
    const orig = _origDisplayResults;
    window.displayResults = function(result) {
        orig(result);
        _lastScanResult = result;
        const jsonEl = document.getElementById('rawJsonOutput');
        if (jsonEl) jsonEl.textContent = JSON.stringify(result, null, 2);
        updateAnalytics();
        const level = result.risk_level || 'SAFE';
        if (level === 'HIGH') showToast('⚠️ High risk threat detected!', 'error');
        else if (level === 'SUSPICIOUS') showToast('Suspicious indicators found', 'warning');
        else showToast('Scan complete — no threats found', 'success');
    };
};

// Wait for app.js to load then patch
if (typeof displayResults === 'function') _patchDisplayResults();
else window.addEventListener('load', () => setTimeout(_patchDisplayResults, 100));

// Initialize analytics on load
window.addEventListener('load', () => { updateAnalytics(); });
