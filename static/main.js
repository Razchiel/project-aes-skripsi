/* ============================================================
   DASHBOARD KEAMANAN — JavaScript Controller
   Auto-refresh setiap 10 detik, simulasi pengujian
   ============================================================ */

const REFRESH_INTERVAL = 10000; // 10 detik

// ===========================
// DOM ELEMENT REFERENCES
// ===========================
const $ = (id) => document.getElementById(id);

const els = {
    clock: $('clock'),
    banner: $('security-banner'),
    statusText: $('status-text'),
    statusDesc: $('status-desc'),
    bannerIcon: $('banner-icon'),
    suhu: $('suhu-terakhir'),
    kelembapan: $('kelembapan-terakhir'),
    totalVerified: $('total-verified'),
    totalAttacks: $('total-attacks'),
    sensorTbody: $('sensor-tbody'),
    attackTbody: $('attack-tbody'),
    avgDecrypt: $('avg-decrypt'),
    minDecrypt: $('min-decrypt'),
    maxDecrypt: $('max-decrypt'),
    totalProcessed: $('total-processed'),
    btnSimulate: $('btn-simulate'),
    btnAttack: $('btn-attack'),
    btnReplay: $('btn-replay'),
    btnReset: $('btn-reset'),
    simResult: $('sim-result'),
    attackBadge: $('attack-count-badge'),
    btnExportCSV: $('btn-export-csv'),
};

// Data caches for modal detail
let sensorDataCache = [];
let attackLogsCache = [];

let currentPageSensor = 1;
let currentPageAttack = 1;
const ROWS_PER_PAGE = 10;

// Chart instance (combined)
let chartSensor = null;

// ===========================
// UTILITY FUNCTIONS
// ===========================
function formatNum(val, decimals = 1) {
    if (val === null || val === undefined) return '--';
    return Number(val).toFixed(decimals);
}

function formatTimestamp(ts) {
    if (!ts) return '--';
    // Tampilkan apa adanya dari database: "YYYY-MM-DD HH:MM:SS"
    return ts;
}

// ===========================
// LIVE CLOCK
// ===========================
function updateClock() {
    const now = new Date();
    const opts = {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    };
    els.clock.textContent = now.toLocaleDateString('id-ID', opts);
}

// ===========================
// FETCH DATA FROM API
// ===========================
async function fetchSensorData() {
    try {
        const res = await fetch('/api/data');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        updateSensorTable(data);
        updateStatCards(data);
    } catch (err) {
        console.error('Gagal mengambil data sensor:', err);
    }
}

async function fetchChartData() {
    try {
        const res = await fetch('/api/chart-data');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        updateCharts(data.sensor, data.serangan);
    } catch (err) {
        console.error('Gagal mengambil data chart:', err);
    }
}

async function fetchAttackLogs() {
    try {
        const res = await fetch('/api/logs');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const logs = await res.json();
        updateAttackTable(logs);
    } catch (err) {
        console.error('Gagal mengambil log serangan:', err);
    }
}

async function fetchStats() {
    try {
        const res = await fetch('/api/stats');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const stats = await res.json();
        updateMetrics(stats);
        updateSecurityBanner(stats);
    } catch (err) {
        console.error('Gagal mengambil statistik:', err);
    }
}

// ===========================
// UPDATE UI — STAT CARDS
// ===========================
function updateStatCards(data) {
    if (data.length > 0) {
        const latest = data[0]; // Data terbaru (ORDER BY id DESC)
        els.suhu.textContent = formatNum(latest.suhu, 1);
        els.kelembapan.textContent = formatNum(latest.kelembapan, 1);
    }
}

// ===========================
// UPDATE UI — SENSOR TABLE
// ===========================
function renderSensorTable() {
    const data = sensorDataCache;
    const totalPages = Math.ceil(data.length / ROWS_PER_PAGE) || 1;
    if (currentPageSensor > totalPages) currentPageSensor = totalPages;

    const start = (currentPageSensor - 1) * ROWS_PER_PAGE;
    const end = start + ROWS_PER_PAGE;
    const displayData = data.slice(start, end);

    if (displayData.length === 0) {
        els.sensorTbody.innerHTML = '<tr class="empty-row"><td colspan="5">Belum ada data sensor — gunakan tombol simulasi di panel kanan</td></tr>';
        if ($('pagination-sensor')) $('pagination-sensor').innerHTML = '';
        return;
    }

    els.sensorTbody.innerHTML = displayData.map((row, i) => {
        const cacheIndex = start + i;
        return `
        <tr class="clickable-row ${cacheIndex === 0 && currentPageSensor === 1 ? 'new-row' : ''}" data-type="sensor" data-index="${cacheIndex}" title="Klik untuk lihat detail proses kriptografi">
            <td>${formatTimestamp(row.timestamp)}</td>
            <td class="mono">${formatNum(row.suhu, 1)}</td>
            <td class="mono">${formatNum(row.kelembapan, 1)}</td>
            <td class="mono">${formatNum(row.waktu_dekripsi_ms, 2)}</td>
            <td>${getStatusBadge(row.status)}</td>
        </tr>
    `}).join('');

    renderPagination(data.length, currentPageSensor, totalPages, 'pagination-sensor', (page) => {
        currentPageSensor = page;
        renderSensorTable();
    });
}

function updateSensorTable(data) {
    sensorDataCache = data || [];
    renderSensorTable();
}

// ===========================
// UPDATE UI — ATTACK TABLE
// ===========================
function renderAttackTable() {
    const logs = attackLogsCache;
    const totalPages = Math.ceil(logs.length / ROWS_PER_PAGE) || 1;
    if (currentPageAttack > totalPages) currentPageAttack = totalPages;

    const start = (currentPageAttack - 1) * ROWS_PER_PAGE;
    const end = start + ROWS_PER_PAGE;
    const displayLogs = logs.slice(start, end);

    if (displayLogs.length === 0) {
        els.attackTbody.innerHTML = '<tr class="empty-row"><td colspan="4">Tidak ada serangan terdeteksi — sistem aman</td></tr>';
        if ($('pagination-attack')) $('pagination-attack').innerHTML = '';
        return;
    }

    els.attackTbody.innerHTML = displayLogs.map((log, i) => {
        const cacheIndex = start + i;
        return `
        <tr class="attack-row clickable-row ${cacheIndex === 0 && currentPageAttack === 1 ? 'new-row' : ''}" data-type="attack" data-index="${cacheIndex}" title="Klik untuk lihat detail serangan dan pencegahan">
            <td>${formatTimestamp(log.timestamp)}</td>
            <td>${escapeHtml(log.jenis_serangan)}</td>
            <td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(log.detail)}</td>
            <td>${getAttackBadge(log.status)}</td>
        </tr>
    `}).join('');

    renderPagination(logs.length, currentPageAttack, totalPages, 'pagination-attack', (page) => {
        currentPageAttack = page;
        renderAttackTable();
    });
}

function updateAttackTable(logs) {
    attackLogsCache = logs || [];
    renderAttackTable();
}

function renderPagination(totalItems, currentPage, totalPages, containerId, onPageChange) {
    const container = $(containerId);
    if (!container) return;

    if (totalItems === 0 || totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    const prevDisabled = currentPage === 1 ? 'disabled' : '';
    const nextDisabled = currentPage === totalPages ? 'disabled' : '';

    container.innerHTML = `
        <button class="page-btn" id="${containerId}-prev" ${prevDisabled}>&laquo; Prev</button>
        <span class="page-info">Halaman ${currentPage} dari ${totalPages} (Total: ${totalItems})</span>
        <button class="page-btn" id="${containerId}-next" ${nextDisabled}>Next &raquo;</button>
    `;

    const btnPrev = $(`${containerId}-prev`);
    const btnNext = $(`${containerId}-next`);

    if (btnPrev && !prevDisabled) {
        btnPrev.addEventListener('click', () => onPageChange(currentPage - 1));
    }
    if (btnNext && !nextDisabled) {
        btnNext.addEventListener('click', () => onPageChange(currentPage + 1));
    }
}

// ===========================
// UPDATE UI — METRICS
// ===========================
function updateMetrics(stats) {
    els.totalVerified.textContent = stats.total_paket;
    els.totalAttacks.textContent = stats.total_serangan;
    els.avgDecrypt.textContent = formatNum(stats.rata_rata_dekripsi, 2) + ' ms';
    els.minDecrypt.textContent = formatNum(stats.min_dekripsi, 2) + ' ms';
    els.maxDecrypt.textContent = formatNum(stats.max_dekripsi, 2) + ' ms';
    els.totalProcessed.textContent = stats.total_paket;
    els.attackBadge.textContent = stats.total_serangan + ' insiden';
}

// ===========================
// UPDATE UI — SECURITY BANNER
// ===========================
function updateSecurityBanner(stats) {
    const banner = $('security-banner');
    if (stats.total_serangan > 0) {
        banner.className = 'security-bar danger';
        $('status-text').textContent = 'SERANGAN TERDETEKSI';
        $('status-desc').textContent = stats.total_serangan + ' insiden tercatat';
    } else {
        banner.className = 'security-bar safe';
        $('status-text').textContent = 'SISTEM AMAN';
        $('status-desc').textContent = 'Semua data sensor terverifikasi';
    }
}

// ===========================
// BADGE RENDERERS
// ===========================
function getStatusBadge(status) {
    if (status === 'Verified') {
        return '<span class="badge-verified">✓ Verified</span>';
    }
    return `<span class="badge-rejected">✗ ${escapeHtml(status)}</span>`;
}

function getAttackBadge(status) {
    return `<span class="badge-attack">${escapeHtml(status)}</span>`;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ===========================
// SIMULATION HANDLERS
// ===========================
async function simulateNormal() {
    els.btnSimulate.disabled = true;
    els.btnSimulate.textContent = 'Mengirim...';

    try {
        const res = await fetch('/api/simulate', { method: 'POST' });
        const data = await res.json();

        if (data.status === 'success') {
            showSimResult('success',
                `✓ Data berhasil dikirim — Suhu: ${data.suhu}°C, Kelembapan: ${data.kelembapan}% | Enkripsi: ${data.waktu_enkripsi_ms}ms, Dekripsi: ${data.waktu_dekripsi_ms}ms`);
        } else {
            showSimResult('error', `✗ Gagal: ${data.detail || 'Unknown error'}`);
        }

        // Refresh semua data
        fetchSensorData();
        fetchStats();
        fetchChartData();
    } catch (err) {
        showSimResult('error', '✗ Gagal menghubungi server');
    } finally {
        els.btnSimulate.disabled = false;
        els.btnSimulate.innerHTML = '🔐 Kirim Data Normal';
    }
}

async function simulateAttack() {
    els.btnAttack.disabled = true;
    els.btnAttack.textContent = 'Menyerang...';

    try {
        const res = await fetch('/api/simulate-attack', { method: 'POST' });
        const data = await res.json();

        if (data.status === 'rejected') {
            showSimResult('attack',
                `🚨 Serangan berhasil dideteksi — ${data.pesan}`);
        } else {
            showSimResult('error', '⚠ Hasil tidak terduga');
        }

        // Refresh attack logs dan statistik
        fetchAttackLogs();
        fetchStats();
        fetchChartData();
    } catch (err) {
        showSimResult('error', '✗ Gagal menghubungi server');
    } finally {
        els.btnAttack.disabled = false;
        els.btnAttack.innerHTML = '💥 Simulasi Serangan';
    }
}

async function simulateReplay() {
    els.btnReplay.disabled = true;
    els.btnReplay.textContent = 'Menyerang...';

    try {
        const res = await fetch('/api/simulate-replay', { method: 'POST' });
        const data = await res.json();

        if (data.status === 'rejected') {
            showSimResult('attack', `🚨 Serangan berhasil dideteksi — ${data.pesan}`);
        } else {
            showSimResult('error', '⚠ Hasil tidak terduga');
        }

        // Refresh attack logs dan statistik
        fetchAttackLogs();
        fetchStats();
        fetchChartData();
    } catch (err) {
        showSimResult('error', '✗ Gagal menghubungi server');
    } finally {
        els.btnReplay.disabled = false;
        els.btnReplay.innerHTML = '🔁 Simulasi Replay Attack';
    }
}

async function resetDatabase() {
    if (!confirm('Apakah Anda yakin ingin menghapus seluruh data sensor dan log serangan? Tindakan ini tidak dapat dibatalkan.')) {
        return;
    }

    els.btnReset.disabled = true;
    els.btnReset.textContent = 'Mereset...';

    try {
        const res = await fetch('/api/reset', { method: 'POST' });
        const data = await res.json();

        if (data.status === 'success') {
            showSimResult('success', `✓ ${data.pesan}`);
            fetchSensorData();
            fetchAttackLogs();
            fetchStats();
            fetchChartData();
        } else {
            showSimResult('error', `✗ Gagal mereset database: ${data.pesan || 'Unknown error'}`);
        }
    } catch (err) {
        showSimResult('error', '✗ Gagal menghubungi server');
    } finally {
        els.btnReset.disabled = false;
        els.btnReset.innerHTML = '🗑️ Reset Database';
    }
}

function showSimResult(type, message) {
    els.simResult.textContent = message;
    els.simResult.className = 'sim-result ' + type + ' visible';

    // Auto-hide setelah 6 detik
    clearTimeout(els.simResult._timeout);
    els.simResult._timeout = setTimeout(() => {
        els.simResult.classList.remove('visible');
    }, 6000);
}

// ===========================
// MODAL — DETAIL POPUP
// ===========================
const modalOverlay = $('modal-overlay');
const modalEl = $('modal');
const modalIcon = $('modal-icon');
const modalTitle = $('modal-title');
const modalBody = $('modal-body');
const modalClose = $('modal-close');

function openModal() {
    modalOverlay.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    modalOverlay.classList.remove('active');
    document.body.style.overflow = '';
}

// Close on overlay click, X button, Escape key
modalClose.addEventListener('click', closeModal);
modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) closeModal();
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// Event delegation for clickable rows
document.addEventListener('click', (e) => {
    const row = e.target.closest('.clickable-row');
    if (!row) return;

    const type = row.dataset.type;
    const index = parseInt(row.dataset.index, 10);

    if (type === 'sensor' && sensorDataCache[index]) {
        showVerifiedModal(sensorDataCache[index]);
    } else if (type === 'attack' && attackLogsCache[index]) {
        showAttackModal(attackLogsCache[index]);
    }
});

// --- Verified Detail Modal ---
function showVerifiedModal(data) {
    modalEl.className = 'modal modal-verified';
    modalIcon.textContent = '🔐';
    modalTitle.textContent = 'Detail Verifikasi & Dekripsi Data';

    const truncate = (s, n=64) => s && s.length > n ? s.slice(0, n) + '…' : (s || '(tidak tersedia)');
    const ptJson = data.plaintext_json
        ? (() => { try { return JSON.stringify(JSON.parse(data.plaintext_json), null, 2); } catch { return data.plaintext_json; } })()
        : '(tidak tersedia)';

    modalBody.innerHTML = `
        <div class="modal-section">
            <div class="modal-section-title">📋 Data Terverifikasi</div>
            <div class="detail-grid">
                <span class="detail-label">Waktu</span>
                <span class="detail-value mono">${formatTimestamp(data.timestamp)}</span>
                <span class="detail-label">Suhu</span>
                <span class="detail-value">${formatNum(data.suhu, 2)} °C</span>
                <span class="detail-label">Kelembapan</span>
                <span class="detail-value">${formatNum(data.kelembapan, 2)} %RH</span>
                <span class="detail-label">Status</span>
                <span class="detail-value success">✓ ${data.status}</span>
            </div>
        </div>

        <div class="modal-section">
            <div class="modal-section-title">📦 Payload Aktual (ESP32 → Server)</div>
            <div class="detail-grid">
                <span class="detail-label">IV (16 byte)</span>
                <span class="detail-value mono" style="font-size:0.7rem;color:var(--cyan)">${truncate(data.iv_hex, 32)}</span>
                <span class="detail-label">Ciphertext</span>
                <span class="detail-value mono" style="font-size:0.7rem">${truncate(data.ciphertext_hex, 48)}</span>
                <span class="detail-label">HMAC Tag (32 byte)</span>
                <span class="detail-value mono" style="font-size:0.7rem;color:var(--amber)">${truncate(data.hmac_tag_hex, 32)}</span>
                <span class="detail-label">Base64 Payload</span>
                <span class="detail-value mono" style="font-size:0.68rem;word-break:break-all">${truncate(data.payload_base64, 60)}</span>
            </div>
        </div>

        <div class="modal-section">
            <div class="modal-section-title">🔓 Hasil Dekripsi — Plaintext JSON</div>
            <pre style="font-family:var(--font-mono);font-size:0.78rem;color:var(--green);
                        background:rgba(0,245,147,0.04);border:1px solid var(--border-green);
                        border-radius:var(--radius-sm);padding:var(--space-md);
                        white-space:pre-wrap;word-break:break-word;margin:0">${escapeHtml(ptJson)}</pre>
        </div>

        <div class="modal-section">
            <div class="modal-section-title">🛡️ Verifikasi Integritas</div>
            <div class="detail-grid">
                <span class="detail-label">Metode</span>
                <span class="detail-value highlight">HMAC-SHA256</span>
                <span class="detail-label">Skema</span>
                <span class="detail-value">Encrypt-then-MAC</span>
                <span class="detail-label">Input HMAC</span>
                <span class="detail-value mono">IV + Ciphertext</span>
                <span class="detail-label">Panjang Tag</span>
                <span class="detail-value mono">256 bit (32 byte)</span>
                <span class="detail-label">HMAC Dikirim ESP32</span>
                <span class="detail-value mono success" style="font-size:0.68rem;word-break:break-all">${data.hmac_tag_hex || '(tidak tersedia)'}</span>
                <span class="detail-label">HMAC Dihitung Server</span>
                <span class="detail-value mono success" style="font-size:0.68rem;word-break:break-all">${data.hmac_tag_hex || '(tidak tersedia)'}</span>
                <span class="detail-label">Kesimpulan</span>
                <span class="detail-value success">Kedua nilai identik — data tidak dimanipulasi selama transmisi</span>
                <span class="detail-label">Status HMAC</span>
                <span class="detail-value success">✓ Valid — Tag cocok, data asli</span>
            </div>
        </div>

        <div class="modal-section">
            <div class="modal-section-title">⏱️ Performa</div>
            <div class="detail-grid">
                <span class="detail-label">Waktu Dekripsi</span>
                <span class="detail-value highlight">${formatNum(data.waktu_dekripsi_ms, 4)} ms</span>
            </div>
        </div>
    `;
    openModal();
}

// --- Attack Detail Modal ---
function showAttackModal(data) {
    modalEl.className = 'modal modal-attack';
    modalIcon.textContent = '🚨';
    modalTitle.textContent = 'Detail Serangan Terdeteksi';

    const isReplay = data.status === 'Replay/Rejected';
    const truncate = (s, n=64) => s && s.length > n ? s.slice(0, n) + '...' : (s || '(tidak tersedia)');

    const ptJson = data.plaintext_json
        ? (() => { try { return JSON.stringify(JSON.parse(data.plaintext_json), null, 2); } catch { return data.plaintext_json; } })()
        : null;

    // Hitung persentase bit berbeda antara dua HMAC (hanya untuk Tampering)
    let bitDiffHtml = '';
    if (!isReplay && data.hmac_tag_hex && data.hmac_dihitung_hex) {
        let diff = 0;
        const a = data.hmac_tag_hex;
        const b = data.hmac_dihitung_hex;
        if (a.length === b.length) {
            for (let i = 0; i < a.length; i += 2) {
                const xor = parseInt(a.slice(i, i+2), 16) ^ parseInt(b.slice(i, i+2), 16);
                diff += xor.toString(2).split('1').length - 1;
            }
            const totalBits = (a.length / 2) * 8;
            const pct = ((diff / totalBits) * 100).toFixed(2);
            bitDiffHtml = `
                <span class="detail-label">Perbedaan Bit</span>
                <span class="detail-value highlight">${pct}% bit berbeda — avalanche effect terbukti</span>
            `;
        }
    }

    const sectionPayload = `
        <div class="modal-section">
            <div class="modal-section-title">Payload yang Diterima Server</div>
            <div class="detail-grid">
                <span class="detail-label">IV (16 byte)</span>
                <span class="detail-value mono" style="font-size:0.7rem;color:var(--cyan)">${truncate(data.iv_hex, 32)}</span>
                <span class="detail-label">Ciphertext</span>
                <span class="detail-value mono" style="font-size:0.7rem">${truncate(data.ciphertext_hex, 48)}</span>
                <span class="detail-label">HMAC Tag (32 byte)</span>
                <span class="detail-value mono" style="font-size:0.7rem;color:var(--red)">${truncate(data.hmac_tag_hex, 32)}</span>
            </div>
        </div>
    `;

    const sectionTamper = `
        <div class="modal-section">
            <div class="modal-section-title">Perbandingan HMAC — Bukti Manipulasi</div>
            <div class="detail-grid">
                <span class="detail-label">HMAC Dikirim</span>
                <span class="detail-value mono danger" style="font-size:0.68rem;word-break:break-all">${data.hmac_tag_hex || '(tidak tersedia)'}</span>
                <span class="detail-label">HMAC Dihitung Server</span>
                <span class="detail-value mono success" style="font-size:0.68rem;word-break:break-all">${data.hmac_dihitung_hex || '(tidak tersedia)'}</span>
                ${bitDiffHtml}
                <span class="detail-label">Kesimpulan</span>
                <span class="detail-value danger">Kedua nilai tidak sama — data telah dimanipulasi</span>
            </div>
        </div>

        <div class="modal-section">
            <div class="modal-section-title">Detail Teknis — Data Tampering</div>
            <div class="detail-grid">
                <span class="detail-label">Error</span>
                <span class="detail-value mono danger">${escapeHtml(data.detail)}</span>
                <span class="detail-label">Penjelasan</span>
                <span class="detail-value">Satu byte pada ciphertext dibalik (XOR 0xFF). HMAC yang dihitung server dari ciphertext yang sudah berubah menghasilkan nilai yang sama sekali berbeda dari tag yang dikirim — inilah avalanche effect pada SHA-256.</span>
            </div>
        </div>

        <div class="modal-section">
            <div class="modal-section-title">Dicegah Oleh</div>
            <div class="detail-grid">
                <span class="detail-label">Mekanisme</span>
                <span class="detail-value highlight">HMAC-SHA256 (Encrypt-then-MAC)</span>
                <span class="detail-label">Cara Kerja</span>
                <span class="detail-value">Server menghitung ulang HMAC dari IV + Ciphertext. Satu bit berubah di ciphertext menghasilkan HMAC yang sama sekali berbeda — avalanche effect.</span>
                <span class="detail-label">Keputusan</span>
                <span class="detail-value danger">Tag tidak cocok → Dekripsi dibatalkan → Data DITOLAK</span>
            </div>
        </div>
    `;

    const sectionReplay = `
        <div class="modal-section">
            <div class="modal-section-title">Detail Teknis — Replay Attack</div>
            <div class="detail-grid">
                <span class="detail-label">Error</span>
                <span class="detail-value mono danger">${escapeHtml(data.detail)}</span>
                <span class="detail-label">Delta Timestamp</span>
                <span class="detail-value danger">${data.delta_ms != null ? data.delta_ms + ' ms' : '(tidak tersedia)'}</span>
                <span class="detail-label">Window Maksimal</span>
                <span class="detail-value mono">60.000 ms (60 detik)</span>
                <span class="detail-label">Penjelasan</span>
                <span class="detail-value">Paket memiliki HMAC <strong>valid</strong> — data tidak diubah. Namun field <code>ts</code> di plaintext menunjukkan paket dibuat lebih dari 60 detik lalu. Server menolak paket lama yang di-replay.</span>
            </div>
        </div>

        ${ptJson ? `
        <div class="modal-section">
            <div class="modal-section-title">Plaintext Terdekripsi (ditolak karena ts kadaluarsa)</div>
            <pre style="font-family:var(--font-mono);font-size:0.78rem;color:var(--amber);
                        background:rgba(245,158,11,0.04);border:1px solid rgba(245,158,11,0.25);
                        border-radius:var(--radius-sm);padding:var(--space-md);
                        white-space:pre-wrap;word-break:break-word;margin:0">${escapeHtml(ptJson)}</pre>
            <p style="font-size:0.72rem;color:var(--text-muted);margin-top:var(--space-sm)">
                Dekripsi berhasil — ditolak karena timestamp kadaluarsa
            </p>
        </div>` : ''}

        <div class="modal-section">
            <div class="modal-section-title">Dicegah Oleh</div>
            <div class="detail-grid">
                <span class="detail-label">Mekanisme</span>
                <span class="detail-value highlight">Anti-Replay Timestamp Window</span>
                <span class="detail-label">Cara Kerja</span>
                <span class="detail-value">Field <code>ts</code> di plaintext JSON berisi Unix timestamp saat paket dibuat. Server membandingkan dengan waktu sekarang — jika selisih lebih dari 60.000 ms, paket ditolak meski HMAC valid.</span>
                <span class="detail-label">Keputusan</span>
                <span class="detail-value danger">Delta melebihi window → Paket DITOLAK</span>
            </div>
        </div>
    `;

    modalBody.innerHTML = `
        <div class="modal-section">
            <div class="modal-section-title">Informasi Serangan</div>
            <div class="detail-grid">
                <span class="detail-label">Waktu</span>
                <span class="detail-value mono">${formatTimestamp(data.timestamp)}</span>
                <span class="detail-label">Jenis Serangan</span>
                <span class="detail-value danger">${escapeHtml(data.jenis_serangan)}</span>
                <span class="detail-label">Status</span>
                <span class="detail-value danger">Ditolak (${escapeHtml(data.status)})</span>
            </div>
        </div>

        ${sectionPayload}
        ${isReplay ? sectionReplay : sectionTamper}
    `;

    openModal();
}

// ===========================
// CHART — Combined Suhu & Kelembapan
// ===========================
function initCharts() {
    const ctx = $('chart-sensor').getContext('2d');

    chartSensor = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Suhu (C)',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'transparent',
                    pointBackgroundColor: [],
                    pointBorderColor: [],
                    pointRadius: [],
                    tension: 0,
                    borderWidth: 2,
                    fill: false,
                    spanGaps: true,
                    segment: {
                        borderColor: ctx => {
                            const chart = ctx.chart;
                            const statuses = chart._segmentStatuses || [];
                            const i = ctx.p1DataIndex;  // p1 bukan p0
                            return statuses[i] === 'Attack' ? '#ef4444' : '#3b82f6';
                        }
                    }
                },
                {
                    label: 'Kelembapan (%RH)',
                    data: [],
                    borderColor: '#22c55e',
                    backgroundColor: 'transparent',
                    pointBackgroundColor: [],
                    pointBorderColor: [],
                    pointRadius: [],
                    tension: 0,
                    borderWidth: 2,
                    fill: false,
                    spanGaps: true,
                    segment: {
                        borderColor: ctx => {
                            const chart = ctx.chart;
                            const statuses = chart._segmentStatuses || [];
                            const i = ctx.p1DataIndex;  // p1 bukan p0
                            return statuses[i] === 'Attack' ? '#ef4444' : '#22c55e';
                        }
                    }
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: {
                    labels: {
                        color: '#8899aa',
                        font: { family: 'Consolas, monospace', size: 11 }
                    }
                },
                tooltip: {
                    backgroundColor: '#0f1729',
                    borderColor: '#1e2d47',
                    borderWidth: 1,
                    titleColor: '#e2e8f0',
                    bodyColor: '#8899aa',
                    padding: 12,
                    cornerRadius: 4,
                    callbacks: {
                        label: function(context) {
                            const statuses = context.chart._segmentStatuses || [];
                            if (statuses[context.dataIndex] === 'Attack') {
                                return 'Serangan terdeteksi -- paket ditolak';
                            }
                            const unit = context.datasetIndex === 0 ? ' C' : ' %RH';
                            return context.dataset.label + ': ' + context.parsed.y + unit;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#526070',
                        font: { family: 'Consolas, monospace', size: 10 },
                        maxRotation: 45,
                        maxTicksLimit: 12
                    },
                    grid: { display: false }
                },
                y: {
                    ticks: {
                        color: '#526070',
                        font: { family: 'Consolas, monospace', size: 10 }
                    },
                    grid: { display: false }
                }
            }
        }
    });
}

function updateCharts(sensorData, seranganData) {
    if (!chartSensor) return;

    const sensor   = [...(sensorData   || [])].reverse().slice(-30);
    const serangan = [...(seranganData || [])];

    const sensorMap   = {};
    const seranganSet = new Set();

    sensor.forEach(d => {
        if (!d.timestamp) return;
        const t = d.timestamp.split(' ')[1];
        if (t) sensorMap[t] = d;
    });

    serangan.forEach(log => {
        if (!log.timestamp) return;
        const t = log.timestamp.split(' ')[1];
        if (t) seranganSet.add(t);
    });

    const labels = Array.from(
        new Set([...Object.keys(sensorMap), ...seranganSet])
    ).sort().slice(-30);

    // Hitung rata-rata suhu untuk posisi titik serangan
    const validSuhu = sensor.map(d => d.suhu).filter(v => v !== null);
    const avgSuhu   = validSuhu.length > 0
        ? validSuhu.reduce((a, b) => a + b, 0) / validSuhu.length
        : 25;
    const attackSuhuY = avgSuhu * 0.75; // 75% dari rata-rata — di bawah garis suhu

    const validHum  = sensor.map(d => d.kelembapan).filter(v => v !== null);
    const avgHum    = validHum.length > 0
        ? validHum.reduce((a, b) => a + b, 0) / validHum.length
        : 60;
    const attackHumY = avgHum * 0.75;

    // Build nilai dan status per label
    const statuses   = labels.map(t => seranganSet.has(t) ? 'Attack' : 'Verified');
    const suhuValues = labels.map((t, i) =>
        seranganSet.has(t)
            ? attackSuhuY
            : (sensorMap[t] ? sensorMap[t].suhu : null)
    );
    const humValues  = labels.map((t, i) =>
        seranganSet.has(t)
            ? attackHumY
            : (sensorMap[t] ? sensorMap[t].kelembapan : null)
    );

    // Warna titik: merah untuk serangan, normal untuk verified
    const suhuPtBg  = statuses.map(s => s === 'Attack' ? '#ef4444' : '#3b82f6');
    const humPtBg   = statuses.map(s => s === 'Attack' ? '#ef4444' : '#22c55e');
    const ptRadii   = statuses.map(s => s === 'Attack' ? 7 : 3);

    // Simpan statuses ke chart instance untuk segment coloring
    chartSensor._segmentStatuses = statuses;

    chartSensor.data.labels = labels;

    chartSensor.data.datasets[0].data               = suhuValues;
    chartSensor.data.datasets[0].pointBackgroundColor = suhuPtBg;
    chartSensor.data.datasets[0].pointBorderColor    = suhuPtBg;
    chartSensor.data.datasets[0].pointRadius         = ptRadii;

    chartSensor.data.datasets[1].data               = humValues;
    chartSensor.data.datasets[1].pointBackgroundColor = humPtBg;
    chartSensor.data.datasets[1].pointBorderColor    = humPtBg;
    chartSensor.data.datasets[1].pointRadius         = ptRadii;

    chartSensor.update('none');
}

// ===========================
// CSV EXPORT HANDLER
// ===========================
function exportCSV() {
    const btn = els.btnExportCSV;
    btn.disabled = true;
    btn.textContent = 'Mengunduh...';

    const link = document.createElement('a');
    link.href = '/api/export/csv';
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = '📥 Export CSV';
    }, 1500);
}

// ===========================
// INITIALIZATION
// ===========================
function init() {
    // Start clock
    updateClock();
    setInterval(updateClock, 1000);

    // Init charts
    initCharts();

    // Initial fetch
    fetchSensorData();
    fetchAttackLogs();
    fetchStats();
    fetchChartData();

    // Periodic refresh
    setInterval(fetchSensorData, REFRESH_INTERVAL);
    setInterval(fetchAttackLogs, REFRESH_INTERVAL);
    setInterval(fetchStats, REFRESH_INTERVAL);
    setInterval(fetchChartData, REFRESH_INTERVAL);

    // Simulation button handlers
    els.btnSimulate.addEventListener('click', simulateNormal);
    els.btnAttack.addEventListener('click', simulateAttack);
    els.btnReplay.addEventListener('click', simulateReplay);
    els.btnReset.addEventListener('click', resetDatabase);

    // Export CSV handler
    els.btnExportCSV.addEventListener('click', exportCSV);
}

document.addEventListener('DOMContentLoaded', init);
