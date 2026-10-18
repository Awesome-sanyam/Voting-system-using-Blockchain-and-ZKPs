/**
 * BlockVote India — Web3 Wallet Manager & Transaction Lifecycle Controller
 * web3_wallet.js
 * ────────────────────────────────────────────────────────────────────────────
 * Connects with MetaMask / EIP-1193 providers, displays network badges,
 * balance, truncated copyable address pill, and manages transaction lifecycle feedback.
 */

(function () {
  'use strict';

  const NETWORKS = {
    80002: {
      name: 'Polygon Amoy',
      chainIdHex: '0x13882',
      symbol: 'POL',
      rpcUrl: 'https://rpc-amoy.polygon.technology',
      explorer: 'https://amoy.polygonscan.com'
    },
    31337: {
      name: 'Hardhat Local',
      chainIdHex: '0x7a69',
      symbol: 'ETH',
      rpcUrl: 'http://127.0.0.1:8545',
      explorer: '#'
    }
  };

  class Web3WalletManager {
    constructor() {
      this.provider = window.ethereum || null;
      this.account = null;
      this.chainId = null;
      this.balance = '0.00';
      this.isConnecting = false;
    }

    init() {
      this.renderWalletPill();
      if (this.provider) {
        this.setupEventListeners();
        // Check if already authorized
        this.checkExistingConnection();
      }
    }

    setupEventListeners() {
      if (!this.provider) return;

      this.provider.on('accountsChanged', (accounts) => {
        if (accounts.length > 0) {
          this.account = accounts[0];
          this.updateBalance();
        } else {
          this.account = null;
          this.balance = '0.00';
        }
        this.renderWalletPill();
        if (window.showToast) {
          window.showToast(this.account ? `Wallet connected: ${this.truncateAddress(this.account)}` : 'Wallet disconnected.', 'info');
        }
      });

      this.provider.on('chainChanged', (chainIdHex) => {
        this.chainId = parseInt(chainIdHex, 16);
        this.renderWalletPill();
        this.updateBalance();
      });
    }

    async checkExistingConnection() {
      try {
        const accounts = await this.provider.request({ method: 'eth_accounts' });
        if (accounts && accounts.length > 0) {
          this.account = accounts[0];
          const chainIdHex = await this.provider.request({ method: 'eth_chainId' });
          this.chainId = parseInt(chainIdHex, 16);
          await this.updateBalance();
          this.renderWalletPill();
        }
      } catch (err) {
        console.warn('[Web3Wallet] Silent connection check failed:', err);
      }
    }

    async connect() {
      if (!this.provider) {
        this.showNoWalletModal();
        return;
      }

      try {
        this.isConnecting = true;
        this.renderWalletPill();

        const accounts = await this.provider.request({ method: 'eth_requestAccounts' });
        this.account = accounts[0];
        const chainIdHex = await this.provider.request({ method: 'eth_chainId' });
        this.chainId = parseInt(chainIdHex, 16);
        await this.updateBalance();

        this.renderWalletPill();
        if (window.showToast) {
          window.showToast(`Connected: ${this.truncateAddress(this.account)}`, 'success');
        }
      } catch (err) {
        console.error('[Web3Wallet] Connection error:', err);
        if (window.showToast) {
          window.showToast(err.message || 'User rejected wallet connection.', 'error');
        }
      } finally {
        this.isConnecting = false;
        this.renderWalletPill();
      }
    }

    async updateBalance() {
      if (!this.provider || !this.account) return;
      try {
        const balHex = await this.provider.request({
          method: 'eth_getBalance',
          params: [this.account, 'latest']
        });
        const wei = BigInt(balHex);
        const eth = Number(wei) / 1e18;
        this.balance = eth.toFixed(3);
      } catch (e) {
        this.balance = '0.00';
      }
    }

    async switchNetwork(targetChainId = 80002) {
      if (!this.provider) return;
      const target = NETWORKS[targetChainId];
      if (!target) return;

      try {
        await this.provider.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: target.chainIdHex }]
        });
      } catch (switchError) {
        if (switchError.code === 4902) {
          try {
            await this.provider.request({
              method: 'wallet_addEthereumChain',
              params: [{
                chainId: target.chainIdHex,
                chainName: target.name,
                rpcUrls: [target.rpcUrl],
                nativeCurrency: { name: target.symbol, symbol: target.symbol, decimals: 18 },
                blockExplorerUrls: [target.explorer]
              }]
            });
          } catch (addError) {
            console.error('[Web3Wallet] Add network failed:', addError);
          }
        }
      }
    }

    truncateAddress(addr) {
      if (!addr) return '';
      return addr.substring(0, 6) + '...' + addr.slice(-4);
    }

    copyAddress() {
      if (!this.account) return;
      navigator.clipboard.writeText(this.account);
      if (window.showToast) {
        window.showToast('Wallet address copied to clipboard!', 'success');
      }
    }

    renderWalletPill() {
      const container = document.getElementById('ag-wallet-pill-container');
      if (!container) return;

      if (!this.account) {
        container.innerHTML = `
          <button type="button" id="btn-connect-wallet" class="ag-pill ag-pill-primary cursor-pointer border-0 py-1.5 px-3">
            <i class="bi bi-wallet2 text-indigo"></i>
            <span class="fw-semibold">${this.isConnecting ? 'Connecting...' : 'Connect Wallet'}</span>
          </button>
        `;
        document.getElementById('btn-connect-wallet')?.addEventListener('click', () => this.connect());
        return;
      }

      const netInfo = NETWORKS[this.chainId] || { name: `Chain ${this.chainId}`, symbol: 'ETH' };
      const isKnown = Boolean(NETWORKS[this.chainId]);

      container.innerHTML = `
        <div class="d-flex align-items-center gap-1.5 bg-white border rounded-pill p-1 shadow-sm font-monospace small">
          <!-- Network Badge -->
          <span class="badge ${isKnown ? 'bg-success-subtle text-success' : 'bg-warning-subtle text-warning'} rounded-pill px-2.5 py-1" 
                title="Active Chain: ${netInfo.name}" style="cursor: pointer;" id="btn-switch-network">
            <span class="ag-pulse-dot ${isKnown ? 'bg-success' : 'bg-warning'} me-1"></span>
            ${netInfo.name}
          </span>

          <!-- Truncated Address with 1-Click Copy -->
          <button type="button" class="btn btn-sm btn-link text-decoration-none text-dark fw-bold px-2 py-0 font-monospace" id="btn-copy-address" title="Click to copy address">
            ${this.truncateAddress(this.account)}
            <i class="bi bi-copy text-muted small ms-1"></i>
          </button>

          <!-- Balance Indicator -->
          <span class="text-muted pe-2" style="font-size: 0.75rem;">
            ${this.balance} ${netInfo.symbol}
          </span>
        </div>
      `;

      document.getElementById('btn-copy-address')?.addEventListener('click', () => this.copyAddress());
      document.getElementById('btn-switch-network')?.addEventListener('click', () => this.switchNetwork(80002));
    }

    showNoWalletModal() {
      if (window.showToast) {
        window.showToast('Gasless Relayer Active — Citizens can cast anonymous ZK ballots without installing crypto wallets!', 'info');
      }
    }

    /**
     * Surface user-friendly transaction lifecycle feedback
     */
    notifyTxLifecycle(stage, data = {}) {
      const messages = {
        SIGNING: {
          title: 'Awaiting Signature',
          body: 'Please approve the transaction in your Web3 wallet provider...',
          type: 'info'
        },
        PENDING: {
          title: 'Transaction Broadcast',
          body: `Transaction submitted to mempool: ${data.txHash ? data.txHash.substring(0, 12) + '...' : ''}`,
          type: 'warning'
        },
        CONFIRMED: {
          title: 'Confirmed On-Chain',
          body: `Secured in Block #${data.blockNumber || 'Recent'}. Verified by Groth16.`,
          type: 'success'
        },
        REVERTED: {
          title: 'Transaction Error',
          body: data.error || 'The contract execution reverted.',
          type: 'error'
        }
      };

      const msg = messages[stage] || { title: stage, body: '', type: 'info' };
      if (window.showToast) {
        window.showToast(`${msg.title}: ${msg.body}`, msg.type);
      }
    }
  }

  // Export globally
  window.web3Wallet = new Web3WalletManager();
  document.addEventListener('DOMContentLoaded', () => {
    window.web3Wallet.init();
  });
})();
