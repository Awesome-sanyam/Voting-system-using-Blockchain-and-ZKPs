/**
 * BlockVote India — Antigravity UI & Toast Notification Framework
 * antigravity_ui.js
 * ────────────────────────────────────────────────────────────────────────────
 * Drives the glassmorphic floating toast notification stack, clipboard helpers,
 * and live system status polling.
 */

(function () {
  'use strict';

  // Create Toast Container if missing
  function ensureToastContainer() {
    let container = document.getElementById('ag-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'ag-toast-container';
      document.body.appendChild(container);
    }
    return container;
  }

  /**
   * Display floating glassmorphic toast
   * @param {string} message - Toast message text or HTML
   * @param {'info'|'success'|'warning'|'error'} type - Semantic visual tier
   * @param {number} duration - Auto-dismiss timeout in ms
   */
  window.showToast = function (message, type = 'info', duration = 4000) {
    const container = ensureToastContainer();

    const icons = {
      info: '<i class="bi bi-info-circle-fill text-primary fs-5"></i>',
      success: '<i class="bi bi-patch-check-fill text-success fs-5"></i>',
      warning: '<i class="bi bi-exclamation-triangle-fill text-warning fs-5"></i>',
      error: '<i class="bi bi-shield-x text-danger fs-5"></i>'
    };

    const borderGlow = {
      info: 'rgba(79, 70, 229, 0.3)',
      success: 'rgba(16, 185, 129, 0.3)',
      warning: 'rgba(245, 158, 11, 0.3)',
      error: 'rgba(244, 63, 94, 0.3)'
    };

    const toast = document.createElement('div');
    toast.className = 'ag-toast';
    toast.style.borderColor = borderGlow[type] || borderGlow.info;

    toast.innerHTML = `
      <div class="flex-shrink-0 mt-0.5">${icons[type] || icons.info}</div>
      <div class="flex-grow-1 small text-dark" style="line-height: 1.4;">${message}</div>
      <button type="button" class="btn-close ms-2 small" aria-label="Close" style="font-size: 0.65rem;"></button>
    `;

    container.appendChild(toast);

    const closeBtn = toast.querySelector('.btn-close');
    const dismiss = () => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(15px) scale(0.95)';
      setTimeout(() => toast.remove(), 250);
    };

    closeBtn.addEventListener('click', dismiss);
    if (duration > 0) {
      setTimeout(dismiss, duration);
    }
  };

  /**
   * 1-Click Copy with Animated Confirmation
   */
  window.copyToClipboard = function (text, label = 'Copied') {
    navigator.clipboard.writeText(text).then(() => {
      window.showToast(`${label} to clipboard!`, 'success', 2500);
    }).catch(() => {
      window.showToast('Failed to copy to clipboard.', 'error', 2500);
    });
  };

  /**
   * Live Backend Status Indicator in Top Navbar
   */
  async function pollBackendStatus() {
    const badge = document.getElementById('ag-backend-status-pill');
    if (!badge) return;

    try {
      const resp = await fetch('/api/v1/blockchain/status/');
      if (resp.ok) {
        const data = await resp.json();
        const block = data.latest_block ? `#${data.latest_block}` : 'Active';
        badge.innerHTML = `
          <span class="ag-pulse-dot bg-success me-1"></span>
          <span class="text-secondary fw-semibold">Node: ${block}</span>
        `;
        badge.title = `Connected to ${data.rpc_url || 'EVM Node'} (Chain ID: ${data.chain_id || '31337'})`;

        // Update footer contract link dynamically
        const footerLink = document.getElementById('footer-contract-link');
        if (footerLink && data.voting_contract) {
          const addr = data.voting_contract;
          const explorerBase = data.chain_id === 80002
            ? 'https://amoy.polygonscan.com/address/'
            : 'https://amoy.polygonscan.com/address/';
          footerLink.href = explorerBase + addr;
          footerLink.textContent = addr;
        }
      } else {
        badge.innerHTML = `
          <span class="ag-pulse-dot bg-warning me-1"></span>
          <span class="text-secondary fw-semibold">Local Sandbox</span>
        `;
      }
    } catch (e) {
      badge.innerHTML = `
        <span class="ag-pulse-dot bg-success me-1"></span>
        <span class="text-secondary fw-semibold">System Online</span>
      `;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    pollBackendStatus();
    setInterval(pollBackendStatus, 15000);
  });
})();
