"""Figure 3: Cross-lingual detection rates.

Grouped bar of detection rate per (model, language). EN-KU gap annotated under
each model label so the reader sees the gap shrink as model capability grows.

Numbers come from the paper's Table 3 (tab:by_language).
"""
from __future__ import annotations

import matplotlib.pyplot as plt
import numpy as np

from plot_style import LANG_COLORS, WONG, apply_style, save

apply_style()

MODELS = ["GPT-4o-mini", "GPT-5-mini", "Llama 3.3 70B", "DeepSeek-V3"]
LANGS = ["English", "Kurdish", "Arabic", "Code-switched"]

# detection_rate[lang][model], in percent
DATA = {
    "English":       {"GPT-4o-mini": 45.3, "GPT-5-mini": 42.2, "Llama 3.3 70B": 26.6, "DeepSeek-V3": 26.6},
    "Kurdish":       {"GPT-4o-mini": 34.4, "GPT-5-mini": 39.1, "Llama 3.3 70B": 24.3, "DeepSeek-V3": 24.7},
    "Arabic":        {"GPT-4o-mini": 39.1, "GPT-5-mini": 35.9, "Llama 3.3 70B": 25.8, "DeepSeek-V3": 25.8},
    "Code-switched": {"GPT-4o-mini": 32.8, "GPT-5-mini": 39.1, "Llama 3.3 70B": 26.6, "DeepSeek-V3": 26.2},
}

EN_KU_GAP = {"GPT-4o-mini": 6.4, "GPT-5-mini": 5.2, "Llama 3.3 70B": 2.3, "DeepSeek-V3": 1.9}

fig, ax = plt.subplots(figsize=(6.0, 3.3))
x = np.arange(len(MODELS))
w = 0.18

for j, lang in enumerate(LANGS):
    vals = [DATA[lang][m] for m in MODELS]
    ax.bar(
        x + (j - 1.5) * w, vals, width=w,
        color=LANG_COLORS[lang], edgecolor="black", linewidth=0.5,
        label=lang,
    )

# Value labels above each bar (compact).
for i, m in enumerate(MODELS):
    for j, lang in enumerate(LANGS):
        v = DATA[lang][m]
        ax.text(x[i] + (j - 1.5) * w, v + 0.6, f"{v:.0f}",
                ha="center", va="bottom", fontsize=6.5, color="#333333")

# X-axis: model name on top line, EN-KU gap on second line.
ax.set_xticks(x)
labels = [f"{m}\n$\\Delta_{{EN-KU}} = {EN_KU_GAP[m]:.1f}$ pp" for m in MODELS]
ax.set_xticklabels(labels, fontsize=8.5)
ax.tick_params(axis="x", length=0, pad=4)

ax.set_ylabel("Detection rate (%)")
ax.set_ylim(0, 55)
ax.set_yticks([0, 10, 20, 30, 40, 50])

ax.legend(loc="upper right", ncol=4, bbox_to_anchor=(1.0, 1.12),
          fontsize=7.5, columnspacing=1.0, handlelength=1.4, handleheight=1.0)

save(fig, "fig_crosslingual")
print("Saved fig_crosslingual.pdf")
