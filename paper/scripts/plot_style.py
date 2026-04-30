"""Shared style and helpers for AgentShield paper figures.

Design decisions:
- Serif fonts (Times-like) to match Elsevier elsarticle body text.
- Wong color-blind-safe palette so figures survive print and B&W printing.
- TrueType font embedding (pdf.fonttype = 42) so reviewers can copy text from PDFs.
- Minimal axes (no top/right spines, light horizontal grid only).
- Wilson 95% confidence interval helper for binomial proportions.
"""
from __future__ import annotations

import math
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt

FIG_DIR = Path(__file__).resolve().parent.parent / "figures"
FIG_DIR.mkdir(exist_ok=True)

# Wong color-blind-safe palette (Nature Methods 2011)
WONG = {
    "black":   "#000000",
    "orange":  "#E69F00",
    "skyblue": "#56B4E9",
    "green":   "#009E73",
    "yellow":  "#F0E442",
    "blue":    "#0072B2",
    "vermillion": "#D55E00",
    "purple":  "#CC79A7",
    "gray":    "#999999",
}

# Consistent model and language colors across all figures.
MODEL_COLORS = {
    "GPT-4o-mini":   WONG["blue"],
    "GPT-5-mini":    WONG["skyblue"],
    "Llama 3.3 70B": WONG["orange"],
    "DeepSeek-V3":   WONG["vermillion"],
}

LANG_COLORS = {
    "English":       WONG["blue"],
    "Kurdish":       WONG["orange"],
    "Arabic":        WONG["green"],
    "Code-switched": WONG["purple"],
}


def apply_style() -> None:
    mpl.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "Liberation Serif", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 9,
        "axes.titlesize": 10,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "legend.frameon": False,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.linewidth": 0.7,
        "xtick.major.width": 0.7,
        "ytick.major.width": 0.7,
        "xtick.major.size": 3.0,
        "ytick.major.size": 3.0,
        "lines.linewidth": 1.0,
        "patch.linewidth": 0.5,
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.linewidth": 0.4,
        "grid.color": "#d0d0d0",
        "grid.alpha": 0.8,
        "axes.axisbelow": True,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% CI for k successes out of n trials, returned as (lo, hi) in [0, 1]."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def save(fig, name: str) -> Path:
    """Save figure as both PDF (vector for LaTeX) and PNG (preview)."""
    pdf_path = FIG_DIR / f"{name}.pdf"
    png_path = FIG_DIR / f"{name}.png"
    fig.savefig(pdf_path)
    fig.savefig(png_path, dpi=200)
    plt.close(fig)
    return pdf_path
