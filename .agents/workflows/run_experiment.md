---
description: How to run the eBPF comparative experiment
---

To run the comparative experiment and evaluate the different compression strategies (Baseline, HeaderComp, Delta, Incremental), follow these steps:

1. **Navigate to the project directory**:
   ```bash
   cd /home/vboxuser/Documents/EBPF_proj
   ```

2. **Run the experiment with sudo** (pick one topology):
   ```bash
   # Single-MB (3 namespaces) — measures sojourn time
   // turbo
   sudo bash scripts/run_comparative.sh --topology single

   # Dual-MB (4 namespaces) — measures e2e latency, transparent compression
   // turbo
   sudo bash scripts/run_comparative.sh --topology dual
   ```

3. **Wait for completion**:
   The script will compile the C components, set up the network namespaces, and run each of the four phases sequentially. Each phase takes about 45-60 seconds.

4. **Review Results (in `results/` directory)**:
   - Summary table printed to terminal and saved in `results/sink_summary.csv`.
   - Comparative plot generated as `results/comparative_plot.png`.
   - Phase-specific sojourn metrics: `results/*_sojourn.csv`.
   - Dual-MB only: E2E latency CSVs (`results/e2e_latency_*.csv`) and plots (`results/dual_mb_comparison.png`, `results/dual_mb_e2e_latency.png`).

5. **Visualize Sojourn Times** (Optional):
   ```bash
   python3 scripts/plot_sojourn.py
   ```
