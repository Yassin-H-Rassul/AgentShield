"""Figure 4: Adaptive attack outcomes.

Per model: how many of the 1,728 systematic adaptive attempts actually
succeeded, and of those, how many were caught vs. how many evaded the defense.
GPT-5-mini's bar is zero because the model refused every attack before it
could act, so we annotate that case explicitly rather than draw an empty bar.

Numbers come from the paper's Table 4 (tab:adaptive).
"""
from __future__ import annotations

import matplotlib.pyplot as plt
import numpy as np

from plot_style import MODEL_COLORS, WONG, apply_style, save

apply_style()

MODELS = ["GPT-4o-mini", "GPT-5-mini", "Llama 3.3 70B", "DeepSeek-V3"]
RUNS = {"GPT-4o-mini": 429, "GPT-5-mini": 429, "Llama 3.3 70B": 432, "DeepSeek-V3": 432}
SUCCESS = {"GPT-4o-mini": 43, "GPT-5-mini": 0, "Llama 3.3 70B": 17, "DeepSeek-V3": 24}
DETECTED = {"GPT-4o-mini": 43, "GPT-5-mini": 0, "Llama 3.3 70B": 12, "DeepSeek-V3": 22}
EVADED = {m: SUCCESS[m] - DETECTED[m] for m in MODELS}

DETECTED_COLOR = WONG["green"]
EVADED_COLOR = WONG["vermillion"]

fig, ax = plt.subplots(figsize=(5.8, 3.3))
x = np.arange(len(MODELS))
w = 0.55

det_vals = [DETECTED[m] for m in MODELS]
ev_vals = [EVADED[m] for m in MODELS]

ax.bar(x, det_vals, width=w, color=DETECTED_COLOR,
       edgecolor="black", linewidth=0.6, label="Detected")
ax.bar(x, ev_vals, width=w, bottom=det_vals, color=EVADED_COLOR,
       edgecolor="black", linewidth=0.6, label="Evaded")

# Inside-bar segment counts (only when the segment is tall enough).
for i, m in enumerate(MODELS):
    if det_vals[i] >= 4:
        ax.text(x[i], det_vals[i] / 2, str(det_vals[i]),
                ha="center", va="center", fontsize=8, color="white", fontweight="bold")
    if ev_vals[i] >= 3:
        ax.text(x[i], det_vals[i] + ev_vals[i] / 2, str(ev_vals[i]),
                ha="center", va="center", fontsize=8, color="white", fontweight="bold")

# Above-bar summary: total successful and evasion percentage.
for i, m in enumerate(MODELS):
    total = SUCCESS[m]
    if total == 0:
        ax.text(x[i], 1.5, "0 / 429\nrefused\nbefore action",
                ha="center", va="bottom", fontsize=7.5, color=WONG["gray"], style="italic")
        continue
    evasion_pct = 100 * EVADED[m] / total
    label = f"{total}/{RUNS[m]} succeeded\n{evasion_pct:.1f}% evaded"
    ax.text(x[i], total + 1.2, label, ha="center", va="bottom", fontsize=7.5)

ax.set_xticks(x)
ax.set_xticklabels(MODELS, fontsize=8.5)
ax.tick_params(axis="x", length=0)
ax.set_ylabel("Successful attacks (count)")
ax.set_ylim(0, max(SUCCESS.values()) * 1.45)

ax.legend(loc="upper right", fontsize=8, handlelength=1.4, handleheight=1.0)

save(fig, "fig_adaptive")
print("Saved fig_adaptive.pdf")
