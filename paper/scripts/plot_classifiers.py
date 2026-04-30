"""Figure 5: Input-level injection classifiers vs AgentShield.

Two heatmap panels: Recall on the left (high = good), FPR on the right
(low = good). Color is sequential and oriented so dark = bad in both panels,
making the visual pattern easy to read at a glance: ProtectAI's row is dark in
the FPR panel (Kurdish 97.5%, Arabic 75.0%); Prompt-Guard's row is dark in the
Recall panel (~1% across the board); AgentShield's FPR row is solid white (0%
everywhere) and the recall cells are hatched because it is a behavioural
detector that does not classify the input string.

Numbers come from the paper's Table 6 (tab:classifiers).
"""
from __future__ import annotations

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from plot_style import WONG, apply_style, save

apply_style()

SYSTEMS = ["ProtectAI DeBERTa v2", "Prompt-Guard-2", "AgentShield"]
LANGS = ["EN", "KU", "AR"]

# np.nan marks AgentShield's recall row (behavioural; not directly comparable).
RECALL = np.array([
    [44.6, 97.6, 74.4],
    [1.1, 1.2, 1.2],
    [np.nan, np.nan, np.nan],
])
FPR = np.array([
    [2.1, 97.5, 75.0],
    [0.0, 0.0, 0.0],
    [0.0, 0.0, 0.0],
])

fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.7),
                         gridspec_kw={"wspace": 0.55})

def draw(ax, mat, *, title, bad_is_high: bool):
    """bad_is_high=True → dark when value is large (e.g., FPR).
    bad_is_high=False → dark when value is small (e.g., Recall)."""
    plot = mat.copy()
    if not bad_is_high:
        # Invert so the same Reds colormap colors low-recall cells dark.
        plot = 100.0 - plot
    masked = np.ma.masked_invalid(plot)
    cmap = plt.get_cmap("Reds").copy()
    cmap.set_bad(color="#f0f0f0")
    ax.imshow(masked, cmap=cmap, vmin=0, vmax=100, aspect="auto")

    ax.set_xticks(range(len(LANGS)))
    ax.set_xticklabels(LANGS, fontsize=9)
    ax.set_yticks(range(len(SYSTEMS)))
    ax.set_yticklabels(SYSTEMS, fontsize=8.2)
    ax.set_title(title, fontsize=9.5, pad=6)
    ax.tick_params(axis="both", length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    # White separator grid lines between cells.
    ax.set_xticks(np.arange(-0.5, len(LANGS), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(SYSTEMS), 1), minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=1.2)
    ax.tick_params(which="minor", length=0)

    # Cell text + hatched overlay for n/a recall cells.
    for r in range(mat.shape[0]):
        for c in range(mat.shape[1]):
            v = mat[r, c]
            if np.isnan(v):
                ax.add_patch(mpatches.Rectangle(
                    (c - 0.5, r - 0.5), 1, 1,
                    facecolor="#f0f0f0", edgecolor="none", hatch="////",
                ))
                ax.text(c, r, "n/a", ha="center", va="center",
                        fontsize=8.5, color=WONG["gray"], style="italic")
            else:
                shade_value = (100 - v) if not bad_is_high else v
                txt_color = "white" if shade_value > 55 else "black"
                ax.text(c, r, f"{v:.1f}", ha="center", va="center",
                        fontsize=9, color=txt_color)

draw(axes[0], RECALL, title="Recall on attacks (higher is better)",
     bad_is_high=False)
draw(axes[1], FPR, title="False positive rate on benign (lower is better)",
     bad_is_high=True)

fig.text(0.5, -0.02, "Darker shading indicates worse performance.",
         ha="center", va="top", fontsize=7.5, color=WONG["gray"], style="italic")

save(fig, "fig_classifiers")
print("Saved fig_classifiers.pdf")
