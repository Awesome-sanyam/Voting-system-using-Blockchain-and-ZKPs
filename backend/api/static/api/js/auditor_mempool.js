/**
 * BlockVote India — Auditor Mempool & Independent Audit Engine
 * auditor_mempool.js
 * ────────────────────────────────────────────────────────────────────────────
 * Direct WebSocket & REST listener for live blockchain mempool transactions,
 * and independent mathematical integrity audit engine.
 */

(function () {
  'use strict';

  const AUDIT_CONFIG = {
    explorerUrl: 'https://amoy.polygonscan.com',
    mempoolApi: '/api/v1/auditor/mempool/',
    auditVerifyApi: '/api/v1/audit/verify/'
  };

  class AuditorEngine {
    constructor() {
      this.socket = null;
      this.latestBlock = 1492040;
      this.isAuditing = false;
      this.pollInterval = null;
    }

    init() {
      this.initWebSocket();
      this.startMempoolPolling();
      this.setupAuditButton();
    }

    getCsrfToken() {
      const input = document.querySelector('[name=csrfmiddlewaretoken]');
      if (input && input.value) return input.value;
      const cookieValue = document.cookie
        .split('; ')
        .find(row => row.startsWith('csrftoken='))
        ?.split('=')[1];
      return cookieValue || '';
    }

    /**
     * Connects to the real-time Django Channels WebSocket for mempool events
     */
    initWebSocket() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/auditor/`;

      try {
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
          console.log('[AuditorEngine] Connected to auditor mempool WebSocket.');
        };

        this.socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'mempool_event' && data.transaction) {
              this.insertRealTransactionRow(data.transaction);
            }
          } catch (e) {
            console.error('[AuditorEngine] WebSocket parse error:', e);
          }
        };

        this.socket.onerror = () => {
          console.warn('[AuditorEngine] WebSocket error. Relying on active polling.');
        };

        this.socket.onclose = () => {
          // Reconnect attempt after 5 seconds
          setTimeout(() => this.initWebSocket(), 5000);
        };
      } catch (err) {
        console.warn('[AuditorEngine] WebSocket init error:', err);
      }
    }

    /**
     * Polls the mempool API to stay synced with backend and blockchain
     */
    startMempoolPolling() {
      this.fetchMempoolData();
      this.pollInterval = setInterval(() => {
        this.fetchMempoolData();
      }, 5000);
    }

    async fetchMempoolData() {
      try {
        const resp = await fetch(AUDIT_CONFIG.mempoolApi);
        if (!resp.ok) return;
        const data = await resp.json();

        if (data.latest_block) {
          this.latestBlock = data.latest_block;
          this.updateBlockHeader(this.latestBlock);
        }

        const nullifierMetric = document.getElementById('metric-spent-nullifiers');
        if (nullifierMetric && typeof data.spent_nullifiers !== 'undefined') {
          nullifierMetric.textContent = Number(data.spent_nullifiers).toLocaleString();
        }

        const voterMetric = document.getElementById('metric-voter-count');
        if (voterMetric && typeof data.voter_count !== 'undefined') {
          voterMetric.textContent = Number(data.voter_count).toLocaleString();
        }
      } catch (e) {
        // Quiet network catch
      }
    }

    updateBlockHeader(blockNum) {
      const el = document.getElementById('current-block-height');
      if (el) el.textContent = '#' + Number(blockNum).toLocaleString();
    }

    /**
     * Injects a real verified anonymous ballot transaction into the table
     */
    insertRealTransactionRow(tx) {
      const tbody = document.getElementById('mempool-table-body');
      if (!tbody) return;

      // Remove empty placeholder row if exists
      const emptyRow = document.getElementById('mempool-empty-row');
      if (emptyRow) {
        emptyRow.remove();
      }

      const txHash = tx.tx_hash || '0x...';
      const blockNumber = tx.block_number || this.latestBlock;
      const nullifier = tx.nullifier || '0x...';
      const gasUsed = tx.gas_used || '284,520 wei';
      const timeStr = tx.timestamp || new Date().toLocaleTimeString();

      const tr = document.createElement('tr');
      tr.className = 'font-monospace small table-success-transient';
      tr.innerHTML = `
        <td class="px-4 py-2.5">
          <a href="${AUDIT_CONFIG.explorerUrl}/tx/${txHash}" target="_blank" class="fw-semibold text-primary text-decoration-none">
            ${txHash.substring(0, 10)}...${txHash.slice(-8)}
          </a>
        </td>
        <td class="px-4 py-2.5 text-secondary">#${blockNumber}</td>
        <td class="px-4 py-2.5 text-dark fw-bold text-truncate" style="max-width: 140px;">${nullifier.substring(0, 12)}...</td>
        <td class="px-4 py-2.5 text-muted">${gasUsed}</td>
        <td class="px-4 py-2.5 text-muted">${timeStr}</td>
        <td class="px-4 py-2.5">
          <span class="badge bg-success text-white font-monospace">
            <i class="bi bi-check-circle-fill me-1"></i>Confirmed
          </span>
        </td>
      `;

      tbody.insertBefore(tr, tbody.firstChild);

      // Update block header if higher
      if (blockNumber > this.latestBlock) {
        this.latestBlock = blockNumber;
        this.updateBlockHeader(this.latestBlock);
      }

      // Increment metric counter
      const spentMetric = document.getElementById('metric-spent-nullifiers');
      if (spentMetric) {
        const cur = parseInt(spentMetric.textContent.replace(/,/g, ''), 10) || 0;
        spentMetric.textContent = (cur + 1).toLocaleString();
      }

      // Update candidate tally if candidate element exists
      if (tx.candidate_id) {
        const candTallyEl = document.getElementById(`tally-cand-${tx.candidate_id}`);
        if (candTallyEl) {
          const curTally = parseInt(candTallyEl.textContent.replace(/,/g, ''), 10) || 0;
          candTallyEl.textContent = (curTally + 1).toLocaleString();
        }
      }

      // Cap at 35 records
      if (tbody.children.length > 35) {
        tbody.removeChild(tbody.lastChild);
      }
    }

    /**
     * Executes the independent mathematical verification script via the backend audit API
     */
    setupAuditButton() {
      const btn = document.getElementById('btn-run-audit');
      const resultsContainer = document.getElementById('audit-results-panel');

      if (!btn) return;

      btn.addEventListener('click', async () => {
        if (this.isAuditing) return;
        this.isAuditing = true;

        btn.disabled = true;
        btn.innerHTML = `
          <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
          Running Live Cryptographic Audit...
        `;

        if (resultsContainer) {
          resultsContainer.classList.remove('hidden');
          resultsContainer.innerHTML = `
            <div class="card border-0 bg-light p-4 font-monospace small">
              <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom">
                <span class="text-primary fw-bold text-uppercase">
                  <i class="bi bi-cpu-fill me-1.5"></i>Live Mathematical Verification Pipeline
                </span>
                <span class="badge bg-primary-subtle text-primary font-monospace">Active Verification</span>
              </div>
              <div class="d-flex flex-column gap-2" id="audit-log-steps">
                <div class="d-flex align-items-center gap-2 text-dark">
                  <span class="spinner-border spinner-border-sm text-primary" role="status"></span>
                  <span>Contacting Ethereum/Polygon RPC Node & Reading Smart Contract Bytecode...</span>
                </div>
              </div>
            </div>
          `;
        }

        try {
          const response = await fetch(AUDIT_CONFIG.auditVerifyApi, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': this.getCsrfToken()
            }
          });

          const data = await response.json();
          const logContainer = document.getElementById('audit-log-steps');
          if (logContainer) logContainer.innerHTML = '';

          const addStep = (phase, msg, isSuccess = true) => {
            if (!logContainer) return;
            const div = document.createElement('div');
            div.className = 'd-flex align-items-start gap-2 ' + (isSuccess ? 'text-secondary' : 'text-danger');
            div.innerHTML = `
              <span class="${isSuccess ? 'text-success fw-bold' : 'text-danger fw-bold'} mt-0.5">${isSuccess ? '✓' : '✗'}</span>
              <div>
                <strong class="text-dark">[${phase}]</strong> ${msg}
              </div>
            `;
            logContainer.appendChild(div);
          };

          // Render server-side steps with micro-delays for inspection readability
          const steps = data.steps || [];
          for (let i = 0; i < steps.length; i++) {
            await new Promise(r => setTimeout(r, 250));
            const s = steps[i];
            addStep(s.phase || 'Audit Step', s.message || '', s.status !== 'FAIL');
          }

          if (resultsContainer) {
            const finalBanner = document.createElement('div');
            const isPass = data.status === 'PASS';
            finalBanner.className = `mt-3 alert ${isPass ? 'alert-success' : 'alert-danger'} border-0 p-3 text-center mb-0 shadow-sm rounded-3`;
            finalBanner.innerHTML = `
              <div class="d-flex align-items-center justify-content-center gap-2 ${isPass ? 'text-success' : 'text-danger'} fw-bold fs-6 mb-1">
                <i class="bi ${isPass ? 'bi-patch-check-fill' : 'bi-exclamation-triangle-fill'} fs-5"></i>
                MATHEMATICAL AUDIT RESULT: ${data.integrity_score || (isPass ? '100% PASS' : 'FAILED')}
              </div>
              <p class="small text-muted mb-1">
                Ballots Audited: <strong>${data.total_ballots || 0}</strong> • Nullifier Collisions: <strong>${data.nullifier_collisions || 0}</strong> • Merkle Root: <code>${(data.merkle_root || '').substring(0, 16)}...</code>
              </p>
              <div class="small text-muted font-monospace" style="font-size: 0.76rem;">
                Consensus Height: #${(data.latest_block || 0).toLocaleString()} • Contract: ${(data.contract_address || '').substring(0, 14)}...
              </div>
            `;
            resultsContainer.firstElementChild.appendChild(finalBanner);
          }

          btn.disabled = false;
          btn.innerHTML = '<i class="bi bi-check-circle-fill me-1"></i> Audit Completed (Re-run Verification)';
          btn.className = 'btn btn-outline-success fw-bold px-4 py-2.5 shadow-sm d-flex align-items-center gap-2';
        } catch (err) {
          console.error('[AuditorEngine] Audit verification request failed:', err);
          const logContainer = document.getElementById('audit-log-steps');
          if (logContainer) {
            const errDiv = document.createElement('div');
            errDiv.className = 'alert alert-danger mt-2 mb-0';
            errDiv.textContent = 'Audit request failed: ' + err.message;
            logContainer.appendChild(errDiv);
          }
          btn.disabled = false;
          btn.innerHTML = '<i class="bi bi-arrow-repeat me-1"></i> Retry Verification';
          btn.className = 'btn btn-primary fw-semibold px-4 py-2.5 shadow-sm d-flex align-items-center gap-2';
        } finally {
          this.isAuditing = false;
        }
      });
    }
  }

  // Export and auto-init
  window.AuditorEngine = new AuditorEngine();
  document.addEventListener('DOMContentLoaded', () => {
    window.AuditorEngine.init();
  });
})();
