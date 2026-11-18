"""Fig. 2 of the paper from the result tables.

    python audit/make_figures.py --results results --out figures
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402


def fig_dp(results: Path, out: Path):
    pop = pd.read_csv(results / "monday_population.csv")
    cats = ["0", "+1", "+2", "+3", "+4", "+5", "≥+6"]

    def shares(s):
        v = s.clip(upper=6).value_counts()
        return np.array([v.get(k, 0) for k in range(7)]) / max(len(s), 1) * 100

    fin, rst = (pop.loc[pop.end_reason == e, "dp"] for e in ("fin", "rst"))
    x, w = np.arange(7), 0.38
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    ax.bar(x - w / 2, shares(fin), w, label=f"FIN (n={len(fin):,})", color="#1f77b4")
    ax.bar(x + w / 2, shares(rst), w, label=f"RST (n={len(rst):,})", color="#ff7f0e")
    ax.axvspan(-0.5, 2.5, color="0.92", zorder=0)
    ax.text(1, 72, "|ΔP| ≤ 2", ha="center", fontsize=8, color="0.35")
    ax.set_xticks(x, cats)
    ax.set_xlabel("ΔP = P$_{CSV,1}$+P$_{CSV,2}$ − P$_{EarlyNIDS}$ (packets)", fontsize=8)
    ax.set_ylabel("Share of pairs (%)", fontsize=8)
    ax.set_ylim(0, 78)
    ax.tick_params(labelsize=8)
    ax.legend(fontsize=7, frameon=False)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(out / "fig_monday_dp.pdf")


def fig_multiplicity(results: Path, out: Path):
    d = pd.read_csv(results / "fig2b_tuesday_multiplicity.csv").set_index("end_reason")
    order = [e for e in ["fin", "rst", "eof", "idle_timeout", "restart"] if e in d.index]
    names = {"fin": "FIN", "rst": "RST", "eof": "EOF", "idle_timeout": "Idle timeout", "restart": "Restart"}
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    bars = ax.bar([names[e] for e in order], d.loc[order, "multiple_pct"],
                  color=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"][:len(order)])
    for b, e in zip(bars, order):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1,
                f"{d.loc[e, 'multiple_pct']:.1f}%\n(n={d.loc[e, 'flows']:,})", ha="center", fontsize=6)
    ax.set_ylabel("Multiple CSV candidates (%)", fontsize=8)
    ax.tick_params(labelsize=8)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(out / "fig_tuesday_multiplicity.pdf")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results", type=Path, default=Path("results"))
    p.add_argument("--out", type=Path, default=Path("figures"))
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    fig_dp(a.results, a.out)
    fig_multiplicity(a.results, a.out)
    print("figures written to", a.out)


if __name__ == "__main__":
    main()
