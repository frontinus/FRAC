import matplotlib.pyplot as plt
import pandas as pd
import sys

try:
    # Read CSV
    df = pd.read_csv('tradeoff_results.csv')

    # Convert Bandwidth to numeric for sorting (1mbit -> 1, 10mbit -> 10, etc.)
    # We will just use the index for X-axis and label with the string
    labels = df['Bandwidth_Mbps'].unique()
    
    # Filter Data
    baseline = df[df['Mode'] == 'Baseline']['Throughput_Mbps'].values
    schc = df[df['Mode'] == 'SCHC']['Throughput_Mbps'].values
    
    x = range(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 6))
    rects1 = ax.bar([i - width/2 for i in x], baseline, width, label='Baseline (No Comp)', color='#d62728')
    rects2 = ax.bar([i + width/2 for i in x], schc, width, label='SCHC (Compression)', color='#2ca02c')

    ax.set_ylabel('Throughput (Mbps)')
    ax.set_title('Throughput Trade-off: Compression Cost vs Bandwidth Savings')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()

    # Add labels on top
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.1f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')

    autolabel(rects1)
    autolabel(rects2)

    plt.tight_layout()
    plt.savefig('tradeoff_plot.png')
    print("Plot saved to tradeoff_plot.png")

except Exception as e:
    print(f"Error plotting: {e}")
