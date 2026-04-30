"""Figure 2: Detection headline.

Shows the raw detection rate (all attempts) alongside the conditional rate on
attacks the agent actually obeyed. The conditional rate is only reliable on
the two commercial models because the open-source baseline ASR (1.8% Llama,
7.2% DeepSeek) gives too few successful attacks for a meaningful conditional
estimate, so those slots are left empty with an n/a label.

Numbers come from the paper's Table 2 and the prose around it (Section 5.1).
"""
from __future__ import annotations

import matplotlib.pyplot as plt
import numpy as np

from plot_style import MODEL_COLORS, WONG, apply_style, save, wilson_ci

apply_style()

MODELS = ["GPT-4o-mini", "GPT-5-mini", "Llama 3.3 70B", "DeepSeek-V3"]

# Paper-reported raw detection percentages on 128 attacks x 4 suites = 512 trials.
# Use the rounded percentage shown in the paper as the point estimate; derive
# the integer hit count to match for Wilson CI computation.
RAW_PCT = {"GPT-4o-mini": 35.6, "GPT-5-mini": 36.5, "Llama 3.3 70B": 25.8, "DeepSeek-V3": 25.8}
N_RAW = 512
RAW_HITS = {m: int(round(RAW_PCT[m] / 100 * N_RAW)) for m in MODELS}

# Conditional: detections on attacks that succeeded. Reported in paper for commercial only.
COND_HITS = {"GPT-4o-mini": 117, "GPT-5-mini": 125}
COND_N    = {"GPT-4o-mini": 129, "GPT-5-mini": 125}

raw_pct = [RAW_PCT[m] for m in MODELS]
raw_lo, raw_hi = zip(*[wilson_ci(RAW_HITS[m], N_RAW) for m in MODELS])
raw_err_lo = [raw_pct[i] - 100 * raw_lo[i] for i in range(4)]
raw_err_hi = [100 * raw_hi[i] - raw_pct[i] for i in range(4)]

cond_pct, cond_err_lo, cond_err_hi = [], [], []
for m in MODELS:
    if m in COND_HITS:
        p = 100 * COND_HITS[m] / COND_N[m]
        lo, hi = wilson_ci(COND_HITS[m], COND_N[m])
        cond_pct.append(p)
        cond_err_lo.append(p - 100 * lo)
        cond_err_hi.append(100 * hi - p)
    else:
        cond_pct.append(np.nan)
        cond_err_lo.append(0.0)
        cond_err_hi.append(0.0)

fig, ax = plt.subplots(figsize=(5.6, 3.2))
x = np.arange(len(MODELS))
w = 0.36

# Raw bars (solid, model color).
for i, m in enumerate(MODELS):
    ax.bar(
        x[i] - w / 2, raw_pct[i], width=w,
        yerr=[[raw_err_lo[i]], [raw_err_hi[i]]],
        color=MODEL_COLORS[m], edgecolor="black", linewidth=0.6,
        error_kw={"elinewidth": 0.7, "capsize": 2.5, "ecolor": "black"},
    )

# Conditional bars: solid lighter for commercial, blank slot with n/a label for open-source.
for i, m in enumerate(MODELS):
    if not np.isnan(cond_pct[i]):
        ax.bar(
            x[i] + w / 2, cond_pct[i], width=w,
            yerr=[[cond_err_lo[i]], [cond_err_hi[i]]],
            color=MODEL_COLORS[m], edgecolor="black", linewidth=0.6,
            alpha=0.55,
            error_kw={"elinewidth": 0.7, "capsize": 2.5, "ecolor": "black"},
        )
    else:
        ax.text(
            x[i] + w / 2, 4.5, "n/a$^\\dagger$",
            ha="center", va="bottom", fontsize=8,
            color=WONG["gray"], style="italic",
        )

# Value labels above each bar.
for i, m in enumerate(MODELS):
    ax.text(x[i] - w / 2, raw_pct[i] + raw_err_hi[i] + 1.6,
            f"{raw_pct[i]:.1f}%", ha="center", va="bottom", fontsize=7.8)
    if not np.isnan(cond_pct[i]):
        ax.text(x[i] + w / 2, cond_pct[i] + cond_err_hi[i] + 1.6,
                f"{cond_pct[i]:.1f}%", ha="center", va="bottom",
                fontsize=7.8, fontweight="bold")

# Legend with neutral-color proxies so the legend swatches do not clash with model colors.
legend_handles = [
    plt.Rectangle((0, 0), 1, 1, facecolor=WONG["gray"], edgecolor="black",
                  linewidth=0.6, label="All attack attempts (n = 512)"),
    plt.Rectangle((0, 0), 1, 1, facecolor=WONG["gray"], edgecolor="black",
                  linewidth=0.6, alpha=0.55,
                  label="Successful attacks only (commercial models)"),
]
ax.legend(handles=legend_handles, loc="lower center", bbox_to_anchor=(0.5, 1.01),
          ncol=2, fontsize=7.5, handlelength=1.6, handleheight=1.0,
          borderaxespad=0.0, columnspacing=2.0)

ax.set_xticks(x)
ax.set_xticklabels(MODELS, fontsize=8.5)
ax.set_ylabel("Detection rate (%)")
ax.set_ylim(0, 115)
ax.set_yticks([0, 20, 40, 60, 80, 100])
ax.tick_params(axis="x", length=0)

# Footnote line for n/a daggers (under the axis labels).
fig.text(0.5, -0.05,
         "$^\\dagger$Conditional rate is not estimable on open-source models "
         "(baseline ASR 1.8% Llama, 7.2% DeepSeek; too few successful attacks).",
         ha="center", va="top", fontsize=7, color=WONG["gray"], style="italic")

save(fig, "fig_detection")
print("Saved fig_detection.pdf")
