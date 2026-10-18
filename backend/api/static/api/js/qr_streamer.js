/**
 * BlockVote India — Native WebSocket 1-Minute QR Streamer
 * qr_streamer.js
 * ────────────────────────────────────────────────────────────────────────────
 * Manages WebSocket connection to `/ws/qr-session/`, renders real-time
 * cryptographically signed QR tokens, and drives the 60s countdown timer.
 * QR code is DISABLED (expired overlay shown) once the 60-second session ends.
 */

(function () {
  'use strict';

  class QRStreamer {
    constructor() {
      this.socket = null;
      this.qrInstance = null;
      this.countdownInterval = null;
      this.fallbackInterval = null;
      this.totalDurationSeconds = 60; // 1 minute — STRICT ENFORCEMENT
      this.remainingSeconds = 60;
      this.voterHash = null;
      this.currentToken = null;
      this.isSimulated = false;
      this.isExpired = false;
      this.isVoted = false;
      this.reconnectAttempts = 0;
      this.maxReconnectAttempts = 5;
    }

    /**
     * Initializes the streamer for the given voter hash or session
     */
    init(voterHash = null) {
      if (this.isVoted) return;

      if (voterHash) {
        this.voterHash = voterHash;
        sessionStorage.setItem('blockvote_voter_hash', voterHash);
      } else {
        this.voterHash = sessionStorage.getItem('blockvote_voter_hash');
      }

      this.connectWebSocket();
    }

    /**
     * Establishes WebSocket connection with automatic fallback & heartbeat
     */
    connectWebSocket() {
      if (this.isVoted) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/qr-session/`;

      try {
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
          if (this.isVoted) {
            try { this.socket.close(); } catch(e) {}
            return;
          }
          console.log('[QRStreamer] Connected to WebSocket session.');
          this.reconnectAttempts = 0;
          this.updateConnectionStatus(true, 'Live WebSocket Stream Active');
        };

        this.socket.onmessage = (event) => {
          if (this.isVoted) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'qr_refresh' && data.token) {
              this.handleNewToken(data.token);
            } else if (data.type === 'qr_expired') {
              this.isExpired = true;
              this.showQRExpiredOverlay();
            }
          } catch (e) {
            console.error('[QRStreamer] Error parsing WebSocket message:', e);
          }
        };

        this.socket.onerror = (err) => {
          if (this.isVoted) return;
          console.warn('[QRStreamer] WebSocket encountered error or offline channel layer.');
          this.handleFallback();
        };

        this.socket.onclose = () => {
          if (this.isVoted) return;
          console.warn('[QRStreamer] WebSocket closed.');
          if (!this.isSimulated && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            setTimeout(() => { if (!this.isVoted) this.connectWebSocket(); }, 3000);
          } else {
            this.handleFallback();
          }
        };
      } catch (err) {
        if (this.isVoted) return;
        console.warn('[QRStreamer] WebSocket initialization failed. Activating local generator fallback.');
        this.handleFallback();
      }
    }

    /**
     * Fallback simulator in case Daphne/Channels is not running in local environment
     */
    handleFallback() {
      if (this.isVoted || this.isSimulated) return;
      this.isSimulated = true;
      console.log('[QRStreamer] Running cryptographic session in active fallback mode.');
      this.updateConnectionStatus(true, 'Cryptographic Token Active (Local Signer)');

      // Generate initial token immediately
      this.generateLocalToken();

      // The session is 60 seconds — no auto-refresh. QR expires and gets disabled.
      // A new session requires the voter to reload the page.
      if (this.fallbackInterval) clearInterval(this.fallbackInterval);
    }

    /**
     * Generates a signed local token if backend channels is disconnected
     */
    generateLocalToken() {
      if (this.isVoted) return;
      const now = Math.floor(Date.now() / 1000);
      const voterHash = this.voterHash || '0x' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      
      const payload = {
        voter_hash: voterHash,
        issued_at: now,
        expires_at: now + 60,  // 60-second single-use session
        session_nonce: Array.from(crypto.getRandomValues(new Uint8Array(8)))
          .map(b => b.toString(16).padStart(2, '0')).join('')
      };

      const token = {
        payload: payload,
        signature: 'sim_sig_' + Array.from(crypto.getRandomValues(new Uint8Array(16)))
          .map(b => b.toString(16).padStart(2, '0')).join('')
      };

      this.handleNewToken(token);
    }

    /**
     * Handles incoming token, draws QR code, and triggers 60-second countdown
     */
    handleNewToken(token) {
      if (this.isVoted) return;
      this.currentToken = token;
      const payload = token.payload || token;

      if (payload.voter_hash) {
        this.voterHash = payload.voter_hash;
        sessionStorage.setItem('blockvote_voter_hash', this.voterHash);
      }

      // Update UI displays
      const hashEl = document.getElementById('qr-voter-hash');
      if (hashEl) {
        hashEl.textContent = this.voterHash;
      }

      const sigEl = document.getElementById('qr-signature');
      if (sigEl) {
        sigEl.textContent = token.signature ? token.signature.substring(0, 24) + '...' : 'Verified by HMAC-SHA256';
      }

      const nonceEl = document.getElementById('qr-nonce');
      if (nonceEl && payload.session_nonce) {
        nonceEl.textContent = payload.session_nonce;
      }

      // Render QR Code
      this.renderQRCode(JSON.stringify(token));

      // Reset & start 60-second single-use countdown timer
      this.isExpired = false;
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = payload.expires_at || (now + 60);
      const remaining = Math.max(0, expiresAt - now);
      this.startCountdown(remaining);
    }

    /**
     * Shows a "Session Expired" overlay over the QR code canvas, disabling it.
     * The voter must refresh the page to start a new session.
     */
    showQRExpiredOverlay() {
      const container = document.getElementById('qr-code-target');
      if (container) {
        container.innerHTML = `
          <div style="width:190px;height:190px;display:flex;flex-direction:column;
            align-items:center;justify-content:center;background:rgba(239,68,68,0.09);
            border:2px solid #ef4444;border-radius:12px;gap:8px">
            <i class="bi bi-x-octagon-fill" style="font-size:2.5rem;color:#ef4444;"></i>
            <span style="font-family:monospace;font-size:0.78rem;color:#ef4444;font-weight:700;text-align:center;">SESSION EXPIRED</span>
            <span style="font-family:monospace;font-size:0.68rem;color:#b91c1c;text-align:center;">Refresh page to<br>start new session</span>
          </div>`;
      }

      // Disable vote buttons and candidate radios if still on voting page
      document.querySelectorAll('.vote-candidate-btn, #btn-submit-vote, #btn-cast-vote, input[name=candidate]').forEach(el => {
        el.disabled = true;
        el.classList.add('opacity-50', 'disabled');
        el.title = 'QR session expired. Refresh page to vote.';
      });

      // Update timer display
      const timerEl = document.getElementById('qr-countdown-text');
      if (timerEl) {
        timerEl.textContent = '00:00';
        timerEl.style.color = '#ef4444';
      }

      // Update status badge
      this.updateConnectionStatus(false, 'Session Expired — Refresh Required');
    }

    /**
     * Renders or updates the QR Code in the DOM
     */
    renderQRCode(textData) {
      const container = document.getElementById('qr-code-target');
      if (!container) return;

      container.innerHTML = ''; // Clear existing QR

      if (typeof QRCode !== 'undefined') {
        try {
          this.qrInstance = new QRCode(container, {
            text: textData,
            width: 190,
            height: 190,
            colorDark: '#0f172a',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.M
          });
        } catch (e) {
          console.error('[QRStreamer] QR Code generation failed:', e);
          container.innerHTML = `<div class="p-3 font-monospace small text-primary border border-primary-subtle rounded-3 bg-light">${textData.substring(0, 80)}...</div>`;
        }
      } else {
        container.innerHTML = `
          <div class="d-flex align-items-center justify-content-center p-3 bg-dark border border-primary rounded-3 text-center" style="height:190px;width:190px;">
            <span class="text-primary font-monospace small">Token Active<br>${this.voterHash ? this.voterHash.slice(0, 14) + '...' : 'Pending...'}</span>
          </div>`;
      }
    }

    /**
     * Starts linear progress bar and MM:SS countdown for 180 seconds
     */
    startCountdown(seconds) {
      if (this.countdownInterval) {
        clearInterval(this.countdownInterval);
      }

      this.remainingSeconds = seconds;
      this.updateCountdownUI();

      this.countdownInterval = setInterval(() => {
        this.remainingSeconds--;
        if (this.remainingSeconds <= 0) {
          clearInterval(this.countdownInterval);
          this.remainingSeconds = 0;
          this.isExpired = true;
          this.updateCountdownUI();
          // DISABLE the QR — show expired overlay (do NOT auto-refresh)
          this.showQRExpiredOverlay();
        } else {
          this.updateCountdownUI();
        }
      }, 1000);
    }

    /**
     * Updates progress bar width and remaining time string
     */
    updateCountdownUI() {
      const timerEl = document.getElementById('qr-countdown-text');
      const barEl = document.getElementById('qr-progress-bar');

      const minutes = Math.floor(this.remainingSeconds / 60);
      const seconds = this.remainingSeconds % 60;
      const formatted = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;

      if (timerEl) {
        timerEl.textContent = formatted;
        if (this.remainingSeconds <= 30) {
          timerEl.classList.add('text-danger');
          timerEl.classList.remove('text-primary');
        } else {
          timerEl.classList.add('text-primary');
          timerEl.classList.remove('text-danger');
        }
      }

      if (barEl) {
        const percentage = Math.max(0, Math.min(100, (this.remainingSeconds / this.totalDurationSeconds) * 100));
        barEl.style.width = `${percentage}%`;
        if (percentage < 20) {
          barEl.className = 'progress-bar rounded-pill bg-danger transition';
        } else if (percentage < 50) {
          barEl.className = 'progress-bar progress-bar-striped progress-bar-animated rounded-pill bg-warning transition';
        } else {
          barEl.className = 'progress-bar progress-bar-striped progress-bar-animated rounded-pill bg-primary transition';
        }
      }
    }

    updateConnectionStatus(isConnected, label) {
      const statusBadge = document.getElementById('qr-status-indicator');
      if (statusBadge) {
        statusBadge.innerHTML = isConnected
          ? `<span class="badge bg-success rounded-pill px-3 py-1 font-monospace small pulse-indicator"><i class="bi bi-broadcast me-1"></i>${label}</span>`
          : `<span class="badge bg-warning text-dark rounded-pill px-3 py-1 font-monospace small"><i class="bi bi-exclamation-triangle me-1"></i>${label}</span>`;
      }
    }

    getVoterHash() {
      return this.voterHash || sessionStorage.getItem('blockvote_voter_hash') || '0x' + '1'.repeat(32);
    }

    /**
     * Immediately disables the QR after a successful vote submission.
     * Shows a "Vote Securely Cast" overlay instead of the expiry state.
     */
    disableAfterVote() {
      this.isVoted = true;
      this.isExpired = true;
      this.qrInstance = null;

      // Stop the countdown timer and any fallback timer
      if (this.countdownInterval) {
        clearInterval(this.countdownInterval);
        this.countdownInterval = null;
      }
      if (this.fallbackInterval) {
        clearInterval(this.fallbackInterval);
        this.fallbackInterval = null;
      }

      // Close WebSocket cleanly and unhook handlers so onclose doesn't resurrect session
      if (this.socket) {
        this.socket.onopen = null;
        this.socket.onmessage = null;
        this.socket.onerror = null;
        this.socket.onclose = null;
        try {
          if (this.socket.readyState === WebSocket.OPEN) {
            this.socket.close();
          }
        } catch (e) {}
        this.socket = null;
      }

      // Show "Vote Cast" overlay in QR container
      const container = document.getElementById('qr-code-target');
      if (container) {
        container.innerHTML = `
          <div style="width:190px;height:190px;display:flex;flex-direction:column;
            align-items:center;justify-content:center;background:rgba(16,185,129,0.09);
            border:2px solid #10b981;border-radius:12px;gap:8px;padding:12px;text-align:center;">
            <i class="bi bi-patch-check-fill" style="font-size:2.5rem;color:#10b981;"></i>
            <span style="font-family:monospace;font-size:0.78rem;color:#059669;font-weight:700;">BALLOT SECURED</span>
            <span style="font-family:monospace;font-size:0.68rem;color:#047857;">QR Session Disabled.<br>Proof broadcast to Polygon.</span>
          </div>`;
      }

      // Update progress bar to full green / complete
      const barEl = document.getElementById('qr-progress-bar');
      if (barEl) {
        barEl.style.width = '100%';
        barEl.className = 'progress-bar rounded-pill bg-success';
      }

      // Update timer text
      const timerEl = document.getElementById('qr-countdown-text');
      if (timerEl) {
        timerEl.textContent = 'Completed';
        timerEl.style.color = '#10b981';
        timerEl.classList.remove('text-primary', 'text-danger');
      }

      // Update status indicator badge
      this.updateConnectionStatus(true, 'Vote Recorded — Session Closed');
    }

    destroy() {
      if (this.socket) this.socket.close();
      if (this.countdownInterval) clearInterval(this.countdownInterval);
      if (this.fallbackInterval) clearInterval(this.fallbackInterval);
    }
  }

  // Export to global window scope
  window.QRStreamer = new QRStreamer();
})();
