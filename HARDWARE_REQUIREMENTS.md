# BlockVote-India: Hardware Requirements

To successfully run the full BlockVote-India stack locally (Flutter Frontend, Django Backend, FastAPI ML Service, PostgreSQL, Redis, and Hardhat Node), your system must meet the following hardware requirements.

## 🍎 macOS Requirements

### Minimum Specifications
*   **Processor (CPU):** Intel Core i5 (8th Gen or newer) or Apple Silicon M1
*   **Memory (RAM):** 8 GB Unified Memory / RAM
*   **Storage:** 25 GB of free SSD space (required for Docker images, Xcode, and npm modules)
*   **OS Version:** macOS 12 (Monterey) or later

### Recommended Specifications (For Smooth Development)
*   **Processor (CPU):** Apple Silicon M1 Pro / M2 / M3 or Intel Core i7/i9
*   **Memory (RAM):** 16 GB or 32 GB Unified Memory (Heavy IDEs + Docker + Emulators will easily consume 10GB+)
*   **Storage:** 50 GB of free SSD space
*   **Extras:** An iOS physical device or iOS Simulator for testing the mobile application.

---

## 🪟 Windows Requirements

### Minimum Specifications
*   **Processor (CPU):** Intel Core i5 (8th Gen or newer) or AMD Ryzen 5 (2000 series or newer)
*   **Memory (RAM):** 8 GB RAM
*   **Storage:** 30 GB of free SSD space 
*   **OS Version:** Windows 10 (64-bit) or Windows 11
*   **Subsystem:** Windows Subsystem for Linux 2 (WSL 2) is highly recommended for running Docker and Redis smoothly on Windows.

### Recommended Specifications (For Smooth Development)
*   **Processor (CPU):** Intel Core i7 (10th Gen+) or AMD Ryzen 7 (3000 series+)
*   **Memory (RAM):** 16 GB or 32 GB RAM (Android Studio + WSL2 Docker Backend consumes significant memory)
*   **Storage:** 50 GB of free NVMe/SSD space
*   **Extras:** Android Emulator with Hardware Acceleration (HAXM or AMD Hypervisor) enabled via BIOS.

---

## 💡 Developer Notes for Both OS
1.  **Docker Desktop:** Running PostgreSQL and Redis via Docker Compose is the most straightforward setup. Ensure Docker Desktop is allocated at least 4GB of RAM and 2 CPU cores in its settings.
2.  **Machine Learning Training:** The Scikit-Learn Isolation Forest model is relatively lightweight. A dedicated GPU is **not** required for this specific ML microservice; a modern multi-core CPU handles the inference efficiently.
3.  **ZKP Proving:** Generating zk-SNARK proofs locally on the frontend is CPU intensive. Modern processors (M1/M2/Ryzen 5+) will generate the proof in under 2 seconds, while older CPUs may take 5-10 seconds.
