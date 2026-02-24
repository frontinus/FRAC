---
description: How to run the eBPF comparative experiment
---

To run the comparative experiment and evaluate the different compression strategies (Baseline, HeaderComp, Delta, Incremental), follow these steps:

1. **Navigate to the project directory**:
   ```bash
   cd /home/vboxuser/Documents/EBPF_proj
   ```

2. **Make the experiment script executable** (if not already):
   ```bash
   chmod +x run_clean_comparative.sh
   ```

3. **Run the experiment with sudo**:
   ```bash
   sudo ./run_clean_comparative.sh
   ```

4. **Enter your password** when prompted:
   `likikokin10`

5. **Wait for completion**:
   The script will compile the C components, set up the network namespaces, and run each of the four phases sequentially. Each phase takes about 45-60 seconds.

6. **Review Results**:
   - The summary table will be printed to the terminal and saved in `sink_summary.csv`.
   - A comparative plot will be generated as `comparative_plot.png`.
   - Phase-specific sojourn metrics are saved as `*_sojourn.csv`.

7. **Visualize Sojourn Times** (Optional):
   You can run the separate plotting script to see detailed latency trends:
   ```bash
   python3 plot_sojourn.py
   ```
