"""
System architecture:
  Log collection → Entity extraction → [Prune? yes→discard | no→build graph]
  → Pattern matching → Stream → Alert
"""
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrow, Polygon
import numpy as np

fig, ax = plt.subplots(figsize=(22, 10))
ax.set_xlim(0, 22)
ax.set_ylim(0, 10)
ax.axis('off')
fig.patch.set_facecolor('white')

# ── helpers ──────────────────────────────────────────────────────────────────
def rbox(ax, x, y, w, h, label, sublabel="", fc="#2E86AB", ec=None,
         tc="white", fs=9, ls='-', alpha=1.0, bold=True):
    ec = ec or fc
    rect = FancyBboxPatch((x - w/2, y - h/2), w, h,
                          boxstyle="round,pad=0.08,rounding_size=0.2",
                          linewidth=1.6, edgecolor=ec, linestyle=ls,
                          facecolor=fc, alpha=alpha, zorder=3)
    ax.add_patch(rect)
    fw = 'bold' if bold else 'normal'
    if sublabel:
        ax.text(x, y + 0.22, label, ha='center', va='center',
                fontsize=fs, fontweight=fw, color=tc, zorder=4)
        ax.text(x, y - 0.25, sublabel, ha='center', va='center',
                fontsize=fs - 1.5, color=tc, zorder=4, style='italic')
    else:
        ax.text(x, y, label, ha='center', va='center',
                fontsize=fs, fontweight=fw, color=tc, zorder=4)

def dbox(ax, x, y, w, h, label, ec="#888", fc="#F8F9FA", fs=8.5):
    rect = FancyBboxPatch((x - w/2, y - h/2), w, h,
                          boxstyle="round,pad=0.1,rounding_size=0.25",
                          linewidth=1.5, edgecolor=ec, linestyle='--',
                          facecolor=fc, alpha=0.55, zorder=2)
    ax.add_patch(rect)
    ax.text(x, y + h/2 - 0.28, label, ha='center', va='center',
            fontsize=fs, color=ec, fontstyle='italic', zorder=3)

def arr(ax, x1, y1, x2, y2, color="#444", lw=1.8, style="-|>"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color,
                                lw=lw, mutation_scale=15), zorder=5)

def label(ax, x, y, txt, fs=8.5, color="#333", va='bottom', ha='center', bold=False):
    fw = 'bold' if bold else 'normal'
    ax.text(x, y, txt, ha=ha, va=va, fontsize=fs, color=color,
            fontweight=fw, zorder=6)

def diamond(ax, x, y, w, h, text, fc="#F4A261", ec="#E76F51", tc="#1a1a1a", fs=8.5):
    dx, dy = w/2, h/2
    pts = np.array([[x, y+dy],[x+dx, y],[x, y-dy],[x-dx, y]])
    poly = Polygon(pts, closed=True, facecolor=fc, edgecolor=ec,
                   linewidth=1.8, zorder=3)
    ax.add_patch(poly)
    ax.text(x, y, text, ha='center', va='center',
            fontsize=fs, fontweight='bold', color=tc, zorder=4)

def warn_triangle(ax, x, y, size=0.5, color='red'):
    h = size * np.sqrt(3) / 2
    pts = np.array([[x, y+h*2/3],[x+size/2, y-h/3],[x-size/2, y-h/3]])
    poly = Polygon(pts, closed=True, facecolor=color, edgecolor='black',
                   linewidth=1, zorder=4)
    ax.add_patch(poly)
    ax.text(x, y+0.04, '!', ha='center', va='center',
            fontsize=size*16, fontweight='bold', color='white', zorder=5)

def draw_network_blob(ax, cx, cy, n=40, seed=42):
    """Draw a provenance-graph blob of small nodes and edges."""
    rng = np.random.default_rng(seed)
    xs = cx + rng.uniform(-1.1, 1.1, n)
    ys = cy + rng.uniform(-0.8, 0.8, n)
    # edges
    for _ in range(n * 2):
        i, j = rng.integers(0, n, 2)
        ax.plot([xs[i], xs[j]], [ys[i], ys[j]],
                color='#aaa', lw=0.6, zorder=2)
    # nodes — alternate square/circle
    for k, (x, y) in enumerate(zip(xs, ys)):
        if k % 3 == 0:
            sq = FancyBboxPatch((x-0.08, y-0.08), 0.16, 0.16,
                                boxstyle="square,pad=0",
                                facecolor='white', edgecolor='#555',
                                linewidth=0.8, zorder=3)
            ax.add_patch(sq)
        else:
            circ = plt.Circle((x, y), 0.09, facecolor='white',
                               edgecolor='#555', linewidth=0.8, zorder=3)
            ax.add_patch(circ)

# ═══════════════════════════════════════════════════════════════════════
# LAYOUT  (left → right, main y = 5.0)
# ═══════════════════════════════════════════════════════════════════════
Y = 5.0   # main horizontal axis

# ── 1. Log Sources ────────────────────────────────────────────────────
# Linux penguin + Windows logo (represented as colored boxes)
rbox(ax, 1.2, 6.2, 1.6, 0.75, "Audit Stream\n(Linux)",   fc="#2A9D8F", fs=8)
rbox(ax, 1.2, 3.8, 1.6, 0.75, "Audit Stream\n(Windows)", fc="#457B9D", fs=8)
label(ax, 1.2, 1.8, "Log Collection", fs=9, bold=True, color="#333", va='center')

# arrows into stream processor
arr(ax, 2.0, 6.2, 3.0, Y+0.25)
arr(ax, 2.0, 3.8, 3.0, Y-0.25)

# ── 2. Stream Processor ───────────────────────────────────────────────
rbox(ax, 3.5, Y, 1.8, 1.1, "Stream\nProcessor", fc="#264653", fs=9)
arr(ax, 4.4, Y, 5.2, Y)

# ── 3. Entity Extraction ──────────────────────────────────────────────
dbox(ax, 6.5, Y, 2.4, 3.8, "Entity Extraction", ec="#6A4C93")
rbox(ax, 6.5, 6.0, 1.9, 0.65, "File Entity",    fc="#6A4C93", fs=8)
rbox(ax, 6.5, 5.0, 1.9, 0.65, "Process Entity", fc="#8B5CF6", fs=8)
rbox(ax, 6.5, 4.0, 1.9, 0.65, "Network Entity", fc="#A78BFA", fs=8)
arr(ax, 5.2, Y+0.25, 5.6, 6.0)
arr(ax, 5.2, Y,      5.6, 5.0)
arr(ax, 5.2, Y-0.25, 5.6, 4.0)
arr(ax, 7.45, 5.5, 8.0, 5.5)   # → pruning check

# ── 4. Pruning decision ───────────────────────────────────────────────
diamond(ax, 9.0, Y, 1.9, 1.5, "Prunable?",
        fc="#FEF3C7", ec="#D97706", tc="#92400E", fs=8.5)
label(ax, 9.0, 3.85, "Condition:\nwhitelist / noise", fs=7.5,
      color="#92400E", va='top')

# YES branch → discard (down)
arr(ax, 9.0, 4.25, 9.0, 3.3, color="#E63946")
rbox(ax, 9.0, 2.9, 1.7, 0.65, "Pruned / Skip",
     fc="#E63946", ec="#C1121F", fs=8)
label(ax, 9.8, 4.75, "Yes", fs=8.5, color="#E63946", ha='left')
label(ax, 9.8, 3.6,  "(discard)", fs=7.5, color="#999", ha='left')

# NO branch → build graph (right)
arr(ax, 9.95, Y, 10.7, Y, color="#2A9D8F")
label(ax, 10.3, Y+0.25, "No", fs=8.5, color="#2A9D8F")

# ── 5. Knowledge Graph (top) + Graph builder ──────────────────────────
# knowledge graph blob top
draw_network_blob(ax, 12.1, 7.5, n=45, seed=7)
label(ax, 12.1, 8.55, "Knowledge Graph", fs=9, bold=True, color="#1a1a1a")

# Curved arrow from entity extraction up to knowledge graph
ax.annotate("", xy=(11.0, 7.5), xytext=(6.5, 6.35),
            arrowprops=dict(arrowstyle="-|>", color="#888",
                            lw=1.5, mutation_scale=13,
                            connectionstyle="arc3,rad=-0.3"), zorder=5)

# Graph builder box
rbox(ax, 11.5, Y, 1.6, 1.0, "Build\nGraph", fc="#2A9D8F", fs=9)
arr(ax, 12.3, Y, 13.1, Y)

# arrow from knowledge graph down into attack graph
ax.annotate("", xy=(13.5, 6.5), xytext=(12.5, 7.1),
            arrowprops=dict(arrowstyle="-|>", color="#888",
                            lw=1.5, mutation_scale=13), zorder=5)

# ── 6. Attack Graph (scenario graph with warning icons) ───────────────
draw_network_blob(ax, 14.3, Y, n=30, seed=12)
label(ax, 14.3, 3.35, "Attack Graph\n(Graph-based Matching)", fs=9,
      bold=True, color="#1a1a1a", va='top')

# warning triangles on attack graph
warn_triangle(ax, 13.7, 5.4, size=0.45, color='#16a34a')   # green
warn_triangle(ax, 14.5, 5.6, size=0.55, color='#E63946')   # red
warn_triangle(ax, 15.0, 4.8, size=0.5,  color='#C2550A')   # orange
warn_triangle(ax, 13.5, 4.6, size=0.45, color='#E63946')   # red

arr(ax, 15.45, Y, 16.2, Y)

# ── 7. Pattern Matching ───────────────────────────────────────────────
rbox(ax, 16.9, Y, 1.5, 1.1, "Pattern\nMatching",
     sublabel="core_effect", fc="#1D3557", fs=8.5)
arr(ax, 17.65, Y, 18.4, Y)

# ── 8. Stream ─────────────────────────────────────────────────────────
rbox(ax, 18.9, Y, 1.3, 1.0, "Stream", fc="#457B9D", fs=9)
arr(ax, 19.55, Y, 20.3, Y)

# ── 9. Warning ────────────────────────────────────────────────────────
warn_triangle(ax, 20.8, Y+0.1, size=0.9, color='#E63946')
label(ax, 20.8, 4.25, "Warning", fs=10, bold=True,
      color="#E63946", va='top')

# ── Title ─────────────────────────────────────────────────────────────
ax.text(11.0, 9.6,
        "Multi-Source Attack Graph — System Overview",
        ha='center', va='center', fontsize=14,
        fontweight='bold', color='#1a1a1a')

plt.tight_layout(pad=0.5)
out = "D:/NCKH_new/muilti-graph/system_architecture.png"
plt.savefig(out, dpi=160, bbox_inches='tight', facecolor='white')
print(f"Saved: {out}")
plt.show()
