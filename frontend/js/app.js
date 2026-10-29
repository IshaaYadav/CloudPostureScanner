/**
 * Cloud Posture Scanner - Frontend Dashboard Controller
 * Handles live REST API calls, dynamic UI rendering, filters, and configuration.
 */

let currentReport = null;
let cisStatusFilter = 'ALL';
let scoreChart = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  setupEventListeners();
  loadDashboardData();
  loadHistoryData();
});

function setupEventListeners() {
  const scanBtn = document.getElementById('btn-run-scan');
  if (scanBtn) scanBtn.addEventListener('click', runScan);

  const openConfigBtn = document.getElementById('btn-open-config');
  if (openConfigBtn) openConfigBtn.addEventListener('click', openConfigModal);

  const closeBannerBtn = document.getElementById('btn-close-banner');
  if (closeBannerBtn) {
    closeBannerBtn.addEventListener('click', () => {
      document.getElementById('status-banner').classList.add('hidden');
    });
  }
}

/**
 * Loads latest scan report and system health from REST API.
 */
async function loadDashboardData() {
  try {
    showBanner('Connecting to scanner backend...', 'info');

    // 1. Fetch Health Status
    const healthRes = await fetch('/health');
    let healthData = null;
    if (healthRes.ok) {
      healthData = await healthRes.json();
      updateHealthUI(healthData);
    }

    // 2. Fetch Latest Scan Report
    const reportRes = await fetch('/report/latest');
    if (reportRes.ok) {
      currentReport = await reportRes.json();
      renderAll(currentReport);
      
      // If report had scan errors (e.g. permission issues), display in banner
      if (currentReport.scan_errors && currentReport.scan_errors.length > 0) {
        showBanner(`Partial scan completed with API warnings: ${currentReport.scan_errors.join('; ')}`, 'warning');
      } else {
        document.getElementById('status-banner').classList.add('hidden');
      }
    } else {
      showBanner('No previous scan report found. Click "Run Scan" to execute discovery.', 'info');
    }
  } catch (err) {
    console.error('Error fetching dashboard data:', err);
    showBanner('Could not reach backend API. Ensure python run.py is active.', 'error');
  }
}

/**
 * Loads historical scan executions from Amazon S3 / Local storage.
 */
async function loadHistoryData() {
  try {
    const res = await fetch('/scans');
    if (res.ok) {
      const history = await res.json();
      renderHistoryTable(history);
    }
  } catch (err) {
    console.debug('Error loading scan history:', err);
  }
}

/**
 * Triggers a new on-demand cloud posture scan.
 */
async function runScan() {
  const scanBtn = document.getElementById('btn-run-scan');
  const scanIcon = document.getElementById('scan-icon');
  const scanLabel = document.getElementById('scan-btn-label');

  try {
    scanBtn.disabled = true;
    scanIcon.classList.add('animate-spin');
    scanLabel.textContent = 'Scanning...';
    showBanner('Running full cloud posture discovery and CIS benchmark checks...', 'info');

    const res = await fetch('/scan', { method: 'POST' });
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || res.statusText);
    }

    currentReport = await res.json();
    renderAll(currentReport);
    loadHistoryData();

    // Check if cloud storage succeeded or failed
    const storageStatus = currentReport.storage?.status;
    const storageDest = currentReport.storage?.destination;
    if (storageDest === 'AWS-S3' && storageStatus === 'FAILED') {
      showToast(`Scan complete, but Amazon S3 upload failed: ${currentReport.storage?.error_message}`, 'error');
      showBanner(`S3 Upload Warning: ${currentReport.storage?.error_message}`, 'error');
    } else {
      showToast(`Scan completed successfully (${currentReport.status})!`, 'success');
      if (currentReport.scan_errors && currentReport.scan_errors.length > 0) {
        showBanner(`Scan completed with warnings: ${currentReport.scan_errors.join('; ')}`, 'warning');
      } else {
        document.getElementById('status-banner').classList.add('hidden');
      }
    }
  } catch (err) {
    console.error('Scan error:', err);
    showBanner(`Scan failed: ${err.message}`, 'error');
    showToast('Scan execution failed.', 'error');
  } finally {
    scanBtn.disabled = false;
    scanIcon.classList.remove('animate-spin');
    scanLabel.textContent = 'Run Scan';
    lucide.createIcons();
  }
}

/**
 * Updates UI elements based on health endpoint.
 */
function updateHealthUI(health) {
  const modeBadge = document.getElementById('mode-badge');
  const accountLabel = document.getElementById('account-id-label');
  const lastScanLabel = document.getElementById('lbl-last-scan-time');
  const regionsLabel = document.getElementById('lbl-regions-scanned');

  if (accountLabel && health.account_id) {
    accountLabel.textContent = health.account_id;
  }

  if (lastScanLabel && health.last_successful_scan_time) {
    lastScanLabel.textContent = new Date(health.last_successful_scan_time).toLocaleTimeString();
  }

  if (regionsLabel && health.scan_regions) {
    regionsLabel.textContent = health.scan_regions.join(', ');
  }

  if (health.mode === 'LIVE_AWS') {
    modeBadge.className = 'flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/60';
    modeBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400"></span><span>Live AWS Account</span>';
  } else {
    modeBadge.className = 'flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-medium bg-amber-950/60 text-amber-300 border border-amber-800/60';
    modeBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span><span>Simulation Mode</span>';
  }

  // Prepopulate modal values
  const profileInput = document.getElementById('cfg-profile');
  const regionInput = document.getElementById('cfg-region');
  const scanRegionsInput = document.getElementById('cfg-scan-regions');
  const bucketInput = document.getElementById('cfg-s3-bucket');
  const mockCheckbox = document.getElementById('cfg-use-mock');

  if (profileInput && health.active_profile) profileInput.value = health.active_profile;
  if (regionInput && health.default_region) regionInput.value = health.default_region;
  if (scanRegionsInput && health.scan_regions) scanRegionsInput.value = health.scan_regions.join(', ');
  if (bucketInput && health.storage_bucket) bucketInput.value = health.storage_bucket;
  if (mockCheckbox) mockCheckbox.checked = health.mode === 'DEMO_SIMULATION';
}

/**
 * Main render function updating all tabs and metric counters.
 */
function renderAll(report) {
  if (!report) return;

  // 1. Metrics & Overview
  renderSummaryMetrics(report.summary, report.instances, report.buckets);

  // 2. Badges in Tab Headers
  document.getElementById('badge-cis-count').textContent = report.cis_results?.length || 0;
  document.getElementById('badge-ec2-count').textContent = report.instances?.length || 0;
  document.getElementById('badge-s3-count').textContent = report.buckets?.length || 0;

  // 3. Scan Timestamps and Regions
  const ts = report.completion_time || report.timestamp;
  if (ts) {
    document.getElementById('lbl-last-scan-time').textContent = new Date(ts).toLocaleString();
  }
  if (report.target_regions) {
    document.getElementById('lbl-regions-scanned').textContent = report.target_regions.join(', ');
  }

  const headerPill = document.getElementById('lbl-header-storage-pill');
  if (headerPill && report.storage) {
    headerPill.textContent = report.storage.destination;
    headerPill.className = report.storage.destination === 'AWS-S3'
      ? 'px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-sky-950 text-sky-400 border border-sky-800'
      : 'px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-950 text-emerald-400 border border-emerald-800';
  }

  // 4. Render Views
  renderCISResults();
  renderEC2Table();
  renderS3Table();
  renderStorageInfo(report.storage, report.completion_time || report.timestamp);

  lucide.createIcons();
}

/**
 * Updates top cards: Score, Vulnerabilities, EC2, S3.
 */
function renderSummaryMetrics(summary, instances, buckets) {
  if (!summary) return;

  // Score
  const score = summary.compliance_score_percent ?? 0;
  document.getElementById('metric-score').textContent = `${score}%`;

  const statusPill = document.getElementById('score-status-pill');
  if (score >= 80) {
    statusPill.className = 'px-2 py-0.5 rounded-md font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800';
    statusPill.textContent = 'Good Posture';
  } else if (score >= 60) {
    statusPill.className = 'px-2 py-0.5 rounded-md font-semibold bg-amber-950 text-amber-400 border border-amber-800';
    statusPill.textContent = 'Medium Risk';
  } else {
    statusPill.className = 'px-2 py-0.5 rounded-md font-semibold bg-rose-950 text-rose-400 border border-rose-800';
    statusPill.textContent = 'High Exposure';
  }

  const errCount = summary.error_checks || 0;
  const passFailText = errCount > 0
    ? `${summary.passed_checks} Pass / ${summary.failed_checks} Fail (${errCount} Errors)`
    : `${summary.passed_checks} Pass / ${summary.failed_checks} Fail`;
  document.getElementById('metric-pass-fail-counts').textContent = passFailText;

  // Circular Score Chart
  renderScoreGauge(score);

  // Critical & High
  const critCount = summary.critical_failures || 0;
  const highCount = summary.high_failures || 0;
  document.getElementById('metric-critical-high').textContent = critCount + highCount;
  document.getElementById('critical-badge').textContent = `${critCount} Critical`;
  document.getElementById('high-badge').textContent = `${highCount} High`;

  // EC2 Count
  const ec2List = instances || [];
  document.getElementById('metric-ec2-count').textContent = ec2List.length;
  const publicEc2 = ec2List.filter(i => !!i.public_ip).length;
  document.getElementById('metric-public-ec2').textContent = `${publicEc2} with Public IP`;

  // S3 Count
  const s3List = buckets || [];
  document.getElementById('metric-s3-count').textContent = s3List.length;
  const publicS3 = s3List.filter(b => b.access_policy === 'Public').length;
  document.getElementById('metric-public-s3').textContent = `${publicS3} Publicly Accessible`;
}

/**
 * Renders circular doughnut score gauge using Chart.js.
 */
function renderScoreGauge(score) {
  const canvas = document.getElementById('scoreGaugeChart');
  if (!canvas) return;

  const color = score >= 80 ? '#10b981' : (score >= 60 ? '#f59e0b' : '#ef4444');

  if (scoreChart) {
    scoreChart.destroy();
  }

  scoreChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, Math.max(0, 100 - score)],
        backgroundColor: [color, '#1e293b'],
        borderWidth: 0,
        circumference: 360,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '75%',
      plugins: {
        tooltip: { enabled: false }
      }
    }
  });
}

/**
 * Filter handlers for CIS Checks.
 */
function setCISStatusFilter(filter) {
  cisStatusFilter = filter;
  ['all', 'fail', 'pass', 'warn', 'err'].forEach(k => {
    const btn = document.getElementById(`cis-filter-${k}`);
    if (btn) {
      btn.className = 'cis-pill px-3 py-1 rounded-lg font-semibold text-slate-400 hover:text-white';
    }
  });

  const activeMap = {
    'ALL': 'cis-filter-all',
    'FAIL': 'cis-filter-fail',
    'PASS': 'cis-filter-pass',
    'WARNING': 'cis-filter-warn',
    'ERROR': 'cis-filter-err',
  };

  const activeBtn = document.getElementById(activeMap[filter]);
  if (activeBtn) {
    activeBtn.className = 'cis-pill px-3 py-1 rounded-lg font-semibold bg-sky-500 text-white';
  }

  renderCISResults();
}

/**
 * Renders the list of CIS benchmark cards with technical evidence and remediation.
 */
function renderCISResults() {
  const container = document.getElementById('cis-results-list');
  if (!container || !currentReport) return;

  const categorySelect = document.getElementById('cis-category-select').value;
  const searchTerm = (document.getElementById('cis-search-input').value || '').toLowerCase();

  let results = currentReport.cis_results || [];

  // Filter by status
  if (cisStatusFilter !== 'ALL') {
    results = results.filter(r => r.status.toUpperCase() === cisStatusFilter.toUpperCase());
  }

  // Filter by category
  if (categorySelect !== 'ALL') {
    results = results.filter(r => r.category.toLowerCase().includes(categorySelect.toLowerCase()));
  }

  // Search filter
  if (searchTerm) {
    results = results.filter(r =>
      r.title.toLowerCase().includes(searchTerm) ||
      r.check_id.toLowerCase().includes(searchTerm) ||
      r.resource_id.toLowerCase().includes(searchTerm) ||
      r.evidence.toLowerCase().includes(searchTerm)
    );
  }

  if (results.length === 0) {
    container.innerHTML = `
      <div class="text-center py-8 text-slate-500 text-xs">
        <i data-lucide="check-check" class="w-8 h-8 mx-auto mb-2 text-slate-600"></i>
        No matching CIS checks found for the selected filters.
      </div>
    `;
    lucide.createIcons();
    return;
  }

  container.innerHTML = results.map(item => {
    const isPass = item.status === 'PASS';
    const isFail = item.status === 'FAIL';
    const isWarn = item.status === 'WARNING';
    const isError = item.status === 'ERROR' || item.status === 'UNKNOWN';

    const statusBadge = isPass
      ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center space-x-1"><i data-lucide="check" class="w-3 h-3"></i><span>PASS</span></span>`
      : isFail
      ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-950 text-rose-400 border border-rose-800 flex items-center space-x-1"><i data-lucide="x" class="w-3 h-3"></i><span>FAIL</span></span>`
      : isWarn
      ? `<span class="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-950 text-amber-400 border border-amber-800 flex items-center space-x-1"><i data-lucide="alert-circle" class="w-3 h-3"></i><span>WARNING</span></span>`
      : `<span class="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-950 text-purple-400 border border-purple-800 flex items-center space-x-1"><i data-lucide="alert-triangle" class="w-3 h-3"></i><span>${item.status}</span></span>`;

    const severityColor = {
      'CRITICAL': 'text-rose-400 bg-rose-950/60 border-rose-800',
      'HIGH': 'text-orange-400 bg-orange-950/60 border-orange-800',
      'MEDIUM': 'text-amber-400 bg-amber-950/60 border-amber-800',
      'LOW': 'text-sky-400 bg-sky-950/60 border-sky-800'
    }[item.severity] || 'text-slate-400 bg-slate-900 border-slate-700';

    const escapedRemediation = (item.remediation || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');

    return `
      <div class="p-4 rounded-xl border ${isFail ? 'border-rose-900/40 bg-rose-950/10' : (isError ? 'border-purple-900/40 bg-purple-950/10' : 'border-slate-800 bg-slate-900/40')} hover:border-slate-700 transition">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div class="flex items-center space-x-3">
            <span class="px-2 py-0.5 rounded font-mono text-[11px] font-bold ${severityColor} border">
              ${item.check_id}
            </span>
            <span class="text-xs font-semibold text-white tracking-wide">${item.title}</span>
          </div>
          <div class="flex items-center space-x-2">
            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-semibold bg-slate-800 text-slate-300 border border-slate-700">
              ${item.category}
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-semibold ${severityColor} border">
              ${item.severity}
            </span>
            ${statusBadge}
          </div>
        </div>

        <!-- Resource Information -->
        <div class="mt-2 text-[11px] text-slate-400 flex items-center space-x-2">
          <span class="font-semibold text-slate-300">Target:</span>
          <span class="font-mono text-slate-200 bg-slate-800/80 px-1.5 py-0.5 rounded">${item.resource_id}</span>
          <span class="text-slate-500">(${item.resource_type})</span>
          ${item.reference ? `<span class="text-slate-500">• ${item.reference}</span>` : ''}
        </div>

        <!-- Technical Evidence Card -->
        <div class="mt-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs">
          <div class="flex items-center space-x-1.5 text-slate-300 font-medium mb-1">
            <i data-lucide="file-search" class="w-3.5 h-3.5 text-sky-400"></i>
            <span>Audit Evidence & Technical Finding:</span>
          </div>
          <p class="${isFail ? 'text-rose-300' : (isError ? 'text-purple-300' : 'text-slate-300')} font-sans leading-relaxed">
            ${item.evidence}
          </p>
          ${item.error_details ? `<p class="text-purple-400 font-mono text-[11px] mt-1">Error details: ${item.error_details}</p>` : ''}
        </div>

        <!-- Remediation Action -->
        ${item.remediation && item.remediation !== 'No remediation necessary.' ? `
          <div class="mt-2.5 p-3 rounded-lg bg-sky-950/30 border border-sky-900/40 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div class="flex items-start space-x-2">
              <i data-lucide="terminal" class="w-4 h-4 text-sky-400 flex-shrink-0 mt-0.5"></i>
              <div>
                <span class="text-[11px] font-semibold text-sky-300 block">Recommended AWS Remediation:</span>
                <code class="text-[11px] text-sky-200 break-all select-all">${item.remediation}</code>
              </div>
            </div>
            <button onclick="copyToClipboard('${escapedRemediation}')" class="flex-shrink-0 px-2.5 py-1 rounded-md text-[11px] font-medium bg-sky-900/60 hover:bg-sky-800 text-sky-200 border border-sky-700/50 transition flex items-center space-x-1">
              <i data-lucide="copy" class="w-3 h-3"></i>
              <span>Copy CLI</span>
            </button>
          </div>
        ` : ''}
      </div>
    `;
  }).join('');

  lucide.createIcons();
}

/**
 * Renders EC2 Instances Table.
 */
function renderEC2Table() {
  const tbody = document.getElementById('ec2-table-body');
  if (!tbody || !currentReport) return;

  const searchTerm = (document.getElementById('ec2-search-input')?.value || '').toLowerCase();
  let instances = currentReport.instances || [];

  if (searchTerm) {
    instances = instances.filter(i =>
      i.instance_id.toLowerCase().includes(searchTerm) ||
      (i.name && i.name.toLowerCase().includes(searchTerm)) ||
      (i.public_ip && i.public_ip.toLowerCase().includes(searchTerm)) ||
      (i.region && i.region.toLowerCase().includes(searchTerm))
    );
  }

  if (instances.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="py-6 text-center text-slate-500">No EC2 instances discovered in scanned regions.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = instances.map(inst => {
    const isRunning = inst.state.toLowerCase() === 'running';
    const stateBadge = isRunning
      ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">running</span>`
      : `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">${inst.state}</span>`;

    const publicIpBadge = inst.public_ip
      ? `<span class="px-2 py-0.5 rounded font-mono text-[11px] bg-rose-950/60 text-rose-300 border border-rose-800/60 flex items-center space-x-1 inline-flex">
           <i data-lucide="globe" class="w-3 h-3"></i><span>${inst.public_ip}</span>
         </span>`
      : `<span class="text-slate-500 italic">None (Private)</span>`;

    const sgsBadges = (inst.security_groups || []).map(sg => {
      const riskClass = (sg.allows_all_ssh || sg.allows_all_rdp)
        ? 'bg-rose-950/80 text-rose-300 border-rose-800'
        : 'bg-slate-800 text-slate-300 border-slate-700';

      const flag = sg.allows_all_ssh ? ' [SSH: 0.0.0.0/0]' : (sg.allows_all_rdp ? ' [RDP: 0.0.0.0/0]' : '');

      return `
        <span class="inline-block px-2 py-0.5 rounded text-[10px] font-mono border ${riskClass} mb-1 mr-1">
          ${sg.group_name} (${sg.group_id})${flag}
        </span>
      `;
    }).join('');

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-3 px-4">
          <div class="font-semibold text-white">${inst.name || 'Unnamed'}</div>
          <div class="text-[10px] font-mono text-slate-400">${inst.instance_id}</div>
        </td>
        <td class="py-3 px-4 font-mono text-slate-300">${inst.instance_type}</td>
        <td class="py-3 px-4">${inst.region}</td>
        <td class="py-3 px-4">${stateBadge}</td>
        <td class="py-3 px-4">${publicIpBadge}</td>
        <td class="py-3 px-4 font-mono text-slate-400">${inst.private_ip || 'None'}</td>
        <td class="py-3 px-4">${sgsBadges || '<span class="text-slate-500">None</span>'}</td>
      </tr>
    `;
  }).join('');

  lucide.createIcons();
}

/**
 * Renders S3 Buckets Table.
 */
function renderS3Table() {
  const tbody = document.getElementById('s3-table-body');
  if (!tbody || !currentReport) return;

  const searchTerm = (document.getElementById('s3-search-input')?.value || '').toLowerCase();
  let buckets = currentReport.buckets || [];

  if (searchTerm) {
    buckets = buckets.filter(b =>
      b.bucket_name.toLowerCase().includes(searchTerm) ||
      b.region.toLowerCase().includes(searchTerm)
    );
  }

  if (buckets.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="py-6 text-center text-slate-500">No S3 buckets discovered in this AWS account.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = buckets.map(b => {
    const isEncrypted = b.encryption_status !== 'Unencrypted' && !b.encryption_status.includes('Unknown');
    const encBadge = isEncrypted
      ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center space-x-1 inline-flex">
           <i data-lucide="lock" class="w-3 h-3"></i><span>${b.encryption_status}</span>
         </span>`
      : `<span class="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-950 text-rose-400 border border-rose-800 flex items-center space-x-1 inline-flex">
           <i data-lucide="unlock" class="w-3 h-3"></i><span>${b.encryption_status}</span>
         </span>`;

    const isPublic = b.access_policy === 'Public';
    const accessBadge = isPublic
      ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 flex items-center space-x-1 inline-flex">
           <i data-lucide="alert-octagon" class="w-3 h-3"></i><span>PUBLIC</span>
         </span>`
      : `<span class="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1 inline-flex">
           <i data-lucide="shield" class="w-3 h-3"></i><span>Private</span>
         </span>`;

    const pab = b.public_access_block || {};
    const pabIndicators = `
      <div class="flex items-center space-x-1 font-mono text-[10px]">
        <span title="BlockPublicAcls" class="px-1.5 py-0.5 rounded ${pab.block_public_acls ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}">ACL</span>
        <span title="BlockPublicPolicy" class="px-1.5 py-0.5 rounded ${pab.block_public_policy ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}">Pol</span>
        <span title="IgnorePublicAcls" class="px-1.5 py-0.5 rounded ${pab.ignore_public_acls ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}">Ign</span>
        <span title="RestrictPublicBuckets" class="px-1.5 py-0.5 rounded ${pab.restrict_public_buckets ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}">Res</span>
      </div>
    `;

    const verClass = b.versioning_status === 'Enabled'
      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
      : 'bg-slate-800 text-slate-400 border-slate-700';

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-3 px-4 font-mono font-medium text-white">${b.bucket_name}</td>
        <td class="py-3 px-4 text-slate-300">${b.region}</td>
        <td class="py-3 px-4">${encBadge}</td>
        <td class="py-3 px-4">${accessBadge}</td>
        <td class="py-3 px-4">${pabIndicators}</td>
        <td class="py-3 px-4">
          <span class="px-2 py-0.5 rounded text-[10px] font-semibold border ${verClass}">
            ${b.versioning_status}
          </span>
        </td>
      </tr>
    `;
  }).join('');

  lucide.createIcons();
}

/**
 * Updates Storage tab information.
 */
function renderStorageInfo(storage, timestamp) {
  if (!storage) return;

  const destBadge = document.getElementById('storage-dest-badge');
  const locationLabel = document.getElementById('storage-location-label');
  const tsLabel = document.getElementById('scan-timestamp-label');

  if (destBadge) {
    destBadge.textContent = storage.destination;
    destBadge.className = storage.destination === 'AWS-S3'
      ? 'px-2 py-0.5 rounded text-xs font-semibold bg-sky-950 text-sky-400 border border-sky-800'
      : 'px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800';
  }

  if (locationLabel && storage.location) {
    locationLabel.textContent = storage.location;
  }

  if (tsLabel && timestamp) {
    tsLabel.textContent = `Timestamp: ${new Date(timestamp).toLocaleString()}`;
  }
}

/**
 * Renders the Historical scans table from /scans.
 */
function renderHistoryTable(historyList) {
  const tbody = document.getElementById('history-table-body');
  if (!tbody) return;

  if (!historyList || historyList.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="py-4 text-center text-slate-500">No previous scan history found.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = historyList.map(h => {
    const score = h.compliance_score ?? 0;
    const scoreColor = score >= 80 ? 'text-emerald-400' : (score >= 60 ? 'text-amber-400' : 'text-rose-400');
    const isS3 = h.storage_destination === 'AWS-S3';

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-2.5 px-4 font-mono text-sky-300 font-semibold">${h.scan_id}</td>
        <td class="py-2.5 px-4 text-slate-300">${new Date(h.timestamp).toLocaleString()}</td>
        <td class="py-2.5 px-4 text-slate-400">${h.mode}</td>
        <td class="py-2.5 px-4">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${h.status === 'COMPLETED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}">
            ${h.status || 'COMPLETED'}
          </span>
        </td>
        <td class="py-2.5 px-4 font-bold ${scoreColor}">${score}%</td>
        <td class="py-2.5 px-4 text-slate-300">${h.instances_count} EC2 / ${h.buckets_count} S3</td>
        <td class="py-2.5 px-4 font-mono text-[11px] ${isS3 ? 'text-sky-300' : 'text-slate-400'}">
          ${h.storage_destination || 'Local-Storage'}
        </td>
      </tr>
    `;
  }).join('');
}

/**
 * Tab switcher.
 */
function switchTab(tabId) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.remove('bg-sky-500/10', 'text-sky-400', 'border', 'border-sky-500/30');
    b.classList.add('text-slate-400');
  });

  const panel = document.getElementById(`tab-content-${tabId}`);
  const btn = document.getElementById(`tab-btn-${tabId}`);

  if (panel) panel.classList.remove('hidden');
  if (btn) {
    btn.classList.add('bg-sky-500/10', 'text-sky-400', 'border', 'border-sky-500/30');
    btn.classList.remove('text-slate-400');
  }

  lucide.createIcons();
}

/**
 * Modals & Helpers.
 */
function openConfigModal() {
  document.getElementById('config-modal').classList.remove('hidden');
}

function closeConfigModal() {
  document.getElementById('config-modal').classList.add('hidden');
}

async function handleConfigSubmit(e) {
  e.preventDefault();
  const btn = document.getElementById('btn-save-config');
  btn.disabled = true;
  btn.textContent = 'Testing connection...';

  const scanRegionsRaw = document.getElementById('cfg-scan-regions').value.trim();
  const scanRegions = scanRegionsRaw
    ? scanRegionsRaw.split(',').map(r => r.trim()).filter(Boolean)
    : ['ap-south-1'];

  const payload = {
    aws_profile: document.getElementById('cfg-profile').value.trim() || null,
    aws_region: document.getElementById('cfg-region').value.trim() || 'ap-south-1',
    scan_regions: scanRegions,
    s3_storage_bucket: document.getElementById('cfg-s3-bucket').value.trim() || null,
    use_mock: document.getElementById('cfg-use-mock').checked,
  };

  try {
    const res = await fetch('/configure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    closeConfigModal();
    showToast(data.message || 'AWS Configuration updated!', data.connected ? 'success' : 'info');

    // Run new scan with newly configured settings
    runScan();
  } catch (err) {
    showToast(`Error saving configuration: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Test Connection & Save';
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('AWS CLI command copied to clipboard!', 'success');
  }).catch(() => {
    showToast('Failed to copy command.', 'error');
  });
}

function showBanner(message, type = 'info') {
  const banner = document.getElementById('status-banner');
  const icon = document.getElementById('banner-icon');
  const text = document.getElementById('banner-text');

  text.textContent = message;
  banner.classList.remove('hidden');

  if (type === 'error') {
    banner.className = 'rounded-xl border border-rose-800 bg-rose-950/60 text-rose-300 p-4 transition-all duration-300 flex items-start justify-between';
  } else if (type === 'warning') {
    banner.className = 'rounded-xl border border-amber-800 bg-amber-950/60 text-amber-300 p-4 transition-all duration-300 flex items-start justify-between';
  } else {
    banner.className = 'rounded-xl border border-sky-800 bg-sky-950/60 text-sky-300 p-4 transition-all duration-300 flex items-start justify-between';
  }
  lucide.createIcons();
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toast-message');
  const toastIcon = document.getElementById('toast-icon');

  toastMsg.textContent = message;

  if (type === 'success') {
    toastIcon.setAttribute('data-lucide', 'check-circle');
    toastIcon.className = 'w-4 h-4 text-emerald-400';
  } else if (type === 'error') {
    toastIcon.setAttribute('data-lucide', 'alert-circle');
    toastIcon.className = 'w-4 h-4 text-rose-400';
  } else {
    toastIcon.setAttribute('data-lucide', 'info');
    toastIcon.className = 'w-4 h-4 text-sky-400';
  }

  lucide.createIcons();
  toast.classList.remove('translate-y-24', 'opacity-0');

  setTimeout(() => {
    toast.classList.add('translate-y-24', 'opacity-0');
  }, 3500);
}
