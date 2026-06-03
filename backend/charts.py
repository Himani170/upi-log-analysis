import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

def generate_charts(result):
    safe = result["score"]
    risk = 100 - safe

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(5, 5))
    fig.patch.set_facecolor('#0a0a0f')
    ax.set_facecolor('#0a0a0f')

    colors = ['#00f5ff', '#ff003c']
    wedges, texts, autotexts = ax.pie(
        [safe, risk],
        labels=["SAFE", "RISK"],
        autopct="%1.1f%%",
        colors=colors,
        startangle=90,
        wedgeprops=dict(edgecolor='#0a0a0f', linewidth=2)
    )
    for t in texts:
        t.set_color('#00f5ff')
        t.set_fontsize(12)
    for at in autotexts:
        at.set_color('white')
        at.set_fontsize(11)

    ax.set_title("UPI Safety Score", color='#00f5ff', fontsize=14, pad=14)

    path = os.path.join("static", "pie.png")
    plt.savefig(path, facecolor='#0a0a0f', bbox_inches='tight')
    plt.close()
