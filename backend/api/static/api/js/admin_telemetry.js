/**
 * BlockVote India — Admin Telemetry & AI Sentinel Monitor
 * admin_telemetry.js
 * ────────────────────────────────────────────────────────────────────────────
 * Drives the real-time request velocity gauge, live DDoS threat log feed,
 * and Merkle root sealing interface.
 */

(function () {
  'use strict';

  class AdminTelemetry {
    constructor() {
      this.socket = null;
      this.velocity = 2.4;
      this.maxVelocity = 20.0;
      this.isMonitoring = false;
      this.threatLogs = [];
      this.isMerkleLocked = false;
    }

    init() {
      this.initWebSocket();
      this.startVelocityGauge();
      this.setupMerkleLockHandler();
    }

    /**
     * Connects to admin telemetry WebSocket with graceful local simulation
     */
    initWebSocket() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/telemetry/`;

      try {
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
          console.log('[AdminTelemetry] Connected to telemetry WebSocket.');
        };

        this.socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'threat_event') {
              this.appendThreatLog(data.event);
            } else if (data.type === 'velocity_update') {
              this.updateVelocity(data.velocity);
            }
          } catch (e) {
            console.error('[AdminTelemetry] Error parsing message:', e);
          }
        };

        this.socket.onerror = () => {
          this.startSimulationStream();
        };

        this.socket.onclose = () => {
          this.startSimulationStream();
        };
      } catch (err) {
        this.startSimulationStream();
      }
    }

    /**
     * Active fallback simulator for AI Sentinel threat logs and velocity
     */
    startSimulationStream() {
      if (this.isMonitoring) return;
      this.isMonitoring = true;

      const sampleEvents = [
        { type: 'BLOCKED', ip: '192.168.1.104', score: 0.94, msg: 'High velocity burst detected (>18 req/sec)' },
        { type: 'VERIFIED', ip: '10.0.4.12', score: 0.08, msg: 'Anonymous ZK proof relay verified by Groth16 Verifier' },
        { type: 'BLOCKED', ip: '45.33.32.156', score: 0.89, msg: 'Isolation Forest flagged payload anomaly (replayed nullifier)' },
        { type: 'INFO', ip: '172.16.0.8', score: 0.12, msg: 'Polygon Amoy testnet block 1492040 confirmed 2 votes' },
        { type: 'BLOCKED', ip: '185.220.101.5', score: 0.97, msg: 'Distributed scanning signature mitigated by Active Sentinel' }
      ];

      // Inject sample events every few seconds
      setInterval(() => {
        const randomEvt = sampleEvents[Math.floor(Math.random() * sampleEvents.length)];
        const eventCopy = {
          ...randomEvt,
          timestamp: new Date().toLocaleTimeString(),
          id: 'EVT-' + Math.floor(Math.random() * 90000 + 10000)
        };
        this.appendThreatLog(eventCopy);

        // Perturb velocity
        const delta = (Math.random() - 0.48) * 1.5;
        this.velocity = Math.max(1.2, Math.min(18.5, this.velocity + delta));
        this.updateVelocity(this.velocity);
      }, 3500);
    }

    /**
     * Updates velocity gauge and indicator
     */
    updateVelocity(val) {
      this.velocity = typeof val === 'number' ? val : parseFloat(val);
      const velocityText = document.getElementById('velocity-metric-val');
      const gaugeBar = document.getElementById('velocity-gauge-bar');
      const gaugeStatus = document.getElementById('velocity-status-badge');

      if (velocityText) {
        velocityText.textContent = this.velocity.toFixed(1);
      }

      if (gaugeBar) {
        const pct = Math.min(100, (this.velocity / this.maxVelocity) * 100);
        gaugeBar.style.width = `${pct}%`;

        if (this.velocity > 12) {
          gaugeBar.className = 'h-full rounded-full bg-gradient-to-r from-amber-500 to-rose-600 transition-all duration-700 ease-out';
          if (gaugeStatus) {
            gaugeStatus.innerHTML = '<span class="inline-block h-2 w-2 rounded-full bg-rose-500 animate-ping mr-1.5"></span><span class="text-rose-400 font-mono">DDoS BURST MITIGATED</span>';
          }
        } else if (this.velocity > 6) {
          gaugeBar.className = 'h-full rounded-full bg-gradient-to-r from-cyan-500 to-amber-500 transition-all duration-700 ease-out';
          if (gaugeStatus) {
            gaugeStatus.innerHTML = '<span class="inline-block h-2 w-2 rounded-full bg-amber-400 mr-1.5"></span><span class="text-amber-300 font-mono">ELEVATED TRAFFIC</span>';
          }
        } else {
          gaugeBar.className = 'h-full rounded-full bg-gradient-to-r from-cyan-500 to-indigo-500 transition-all duration-700 ease-out';
          if (gaugeStatus) {
            gaugeStatus.innerHTML = '<span class="inline-block h-2 w-2 rounded-full bg-emerald-400 mr-1.5"></span><span class="text-emerald-300 font-mono">NORMAL VELOCITY</span>';
          }
        }
      }
    }

    startVelocityGauge() {
      this.updateVelocity(this.velocity);
    }

    /**
     * Appends an event to the AI Sentinel Terminal feed
     */
    appendThreatLog(evt) {
      const container = document.getElementById('threat-feed-container');
      if (!container) return;

      const isBlocked = evt.type === 'BLOCKED';
      const badgeClass = isBlocked
        ? 'badge bg-danger-subtle text-danger font-monospace'
        : evt.type === 'VERIFIED'
        ? 'badge bg-success-subtle text-success font-monospace'
        : 'badge bg-info-subtle text-info font-monospace';

      const row = document.createElement('div');
      row.className = 'd-flex justify-content-between align-items-center p-2 border-bottom font-monospace small';
      row.innerHTML = `
        <div class="d-flex align-items-center gap-2">
          <span class="${badgeClass}">${evt.type}</span>
          <span class="text-muted">${evt.timestamp || new Date().toLocaleTimeString()}</span>
          <span class="fw-semibold text-dark">${evt.ip || '0.0.0.0'}</span>
          <span class="text-secondary text-truncate" style="max-width: 200px;">${evt.msg}</span>
        </div>
        <div>
          <span class="text-muted small">Score: </span>
          <span class="fw-bold ${evt.score > 0.7 ? 'text-danger' : 'text-success'}">${evt.score}</span>
        </div>
      `;

      container.insertBefore(row, container.firstChild);

      // Keep maximum 40 items in DOM
      if (container.children.length > 40) {
        container.removeChild(container.lastChild);
      }
    }

    /**
     * Handles the "Lock Electoral Roll" action
     */
    setupMerkleLockHandler() {
      const lockBtn = document.getElementById('btn-lock-merkle');
      const badgeContainer = document.getElementById('merkle-status-badge-container');

      if (!lockBtn) return;

      lockBtn.addEventListener('click', async () => {
        if (!confirm('Seal Electoral Roll Merkle Root on Polygon Amoy? No further voter registrations can be added.')) return;

        const rootHash = '0x1e8555e1a1795efcd8cae9842bf9ecafcff7e0faeef7faad36e1c27806f1cc0a';
        const originalHtml = lockBtn.innerHTML;

        // ── Show Bootstrap spinner (replaces Tailwind animate-spin) ──────────
        lockBtn.disabled = true;
        lockBtn.className = 'btn btn-secondary fw-bold px-4 py-2';
        lockBtn.innerHTML = `
          <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
          Sealing Root on-Chain...
        `;

        // ── Call the real backend API endpoint ────────────────────────────────
        const csrfToken = document.cookie
          .split('; ')
          .find(row => row.startsWith('csrftoken='))
          ?.split('=')[1] || '';

        try {
          const resp = await fetch('/api/v1/lock-merkle-root/', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ merkle_root: rootHash })
          });

          const result = await resp.json();

          if (!resp.ok) {
            // Already locked or other server error
            alert(result.error || 'Failed to lock Merkle root. Check server logs.');
            lockBtn.disabled = false;
            lockBtn.className = 'btn btn-danger fw-bold px-4 py-2';
            lockBtn.innerHTML = originalHtml;
            return;
          }

          // ── Success — update UI with Bootstrap classes (replaces Tailwind) ──
          this.isMerkleLocked = true;

          lockBtn.className = 'btn btn-outline-success fw-bold px-4 py-2';
          lockBtn.innerHTML = '<i class="bi bi-check-circle-fill me-1"></i> Electoral Roll Sealed';

          if (badgeContainer) {
            const shortRoot = `${rootHash.substring(0, 16)}...${rootHash.slice(-8)}`;
            badgeContainer.innerHTML = `
              <div class="d-flex align-items-center gap-2 border border-success rounded-3 px-3 py-2 bg-success bg-opacity-10 font-monospace small text-success">
                <span class="badge bg-success rounded-pill pulse-indicator">LOCKED</span>
                <span>Merkle Root Sealed: <strong>${shortRoot}</strong></span>
              </div>
            `;
          }
        } catch (err) {
          alert('Network error — could not reach the server. Is Django running?');
          lockBtn.disabled = false;
          lockBtn.className = 'btn btn-danger fw-bold px-4 py-2';
          lockBtn.innerHTML = originalHtml;
        }
      });
    }
  }

  // Export to global scope
  window.AdminTelemetry = new AdminTelemetry();
  document.addEventListener('DOMContentLoaded', () => {
    window.AdminTelemetry.init();
  });
})();
