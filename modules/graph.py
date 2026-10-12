# Graph — визуализация графа атаки (v3: SVG + attack path)

import sys
import os
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import networkx as nx
    HAS_GRAPH = True
except ImportError:
    HAS_GRAPH = False


COLOR_BG = "#0a0e14"
COLOR_TARGET = "#ff2b2b"
COLOR_CRIT = "#ff2b2b"
COLOR_HIGH = "#ff8800"
COLOR_MED = "#ffcc00"
COLOR_LOW = "#44cc44"
COLOR_NONE = "#666666"
COLOR_EDGE = "#4488cc"
COLOR_EXPLOIT_OK = "#00ff88"
COLOR_EXPLOIT_FAIL = "#884444"


def _severity_color(max_score):
    if max_score >= 9.0:
        return COLOR_CRIT
    if max_score >= 7.0:
        return COLOR_HIGH
    if max_score >= 4.0:
        return COLOR_MED
    if max_score > 0:
        return COLOR_LOW
    return COLOR_NONE


# ============================================================
# Граф 1: Target → Ports
# ============================================================

def build_attack_graph(target, ports):
    if not HAS_GRAPH:
        return None
    G = nx.DiGraph()
    G.add_node("__target__", label=f"TARGET\n{target}",
               color=COLOR_TARGET, size=5000)
    for p in ports:
        port = p["port"]
        svc = p.get("service", "?")
        ver = (p.get("version") or "")[:28]
        cve_count = p.get("cve_count", 0)
        max_score = p.get("max_score", 0)
        label = f"{port}/{svc}"
        if ver:
            label += f"\n{ver}"
        if cve_count:
            label += f"\nCVE: {cve_count} (max {max_score})"
        node_id = f"port_{port}"
        G.add_node(node_id, label=label,
                   color=_severity_color(max_score),
                   size=2200 + int(max_score * 150))
        G.add_edge("__target__", node_id)
    return G


def render_graph(G, output_path="reports/attack_graph.png", output_svg=None):
    if not HAS_GRAPH or G is None:
        return None
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    fig, ax = plt.subplots(figsize=(18, 12), facecolor=COLOR_BG)
    ax.set_facecolor(COLOR_BG)

    ports = [n for n in G.nodes() if n != "__target__"]
    pos = {"__target__": (0.5, 1.0)}
    n = len(ports)
    if n == 1:
        pos[ports[0]] = (0.5, 0.0)
    else:
        for i, node in enumerate(ports):
            x = i / (n - 1)
            pos[node] = (x, 0.0)

    node_colors = [G.nodes[n].get("color", "#ffffff") for n in G.nodes()]
    node_sizes = [G.nodes[n].get("size", 1500) for n in G.nodes()]
    labels = {n: G.nodes[n].get("label", n) for n in G.nodes()}

    nx.draw_networkx_edges(G, pos, edge_color=COLOR_EDGE,
                           arrows=True, arrowsize=25, width=2, alpha=0.6, ax=ax)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes,
                           alpha=0.95, edgecolors="#ffffff", linewidths=2, ax=ax)
    nx.draw_networkx_labels(G, pos, labels=labels,
                            font_size=9, font_color="white", font_weight="bold", ax=ax)

    target_label = G.nodes["__target__"]["label"].splitlines()[-1]
    title = (f"AEGIS — Attack Graph\n"
             f"Target: {target_label}  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    plt.title(title, color="white", fontsize=16, pad=20, fontweight="bold")

    legend_items = [
        mpatches.Patch(color=COLOR_CRIT, label="Critical (CVSS 9+)"),
        mpatches.Patch(color=COLOR_HIGH, label="High (CVSS 7-9)"),
        mpatches.Patch(color=COLOR_MED, label="Medium (CVSS 4-7)"),
        mpatches.Patch(color=COLOR_LOW, label="Low (CVSS 0-4)"),
        mpatches.Patch(color=COLOR_NONE, label="No CVE"),
    ]
    ax.legend(handles=legend_items, loc="lower left", fontsize=10,
              facecolor="#1a1e24", edgecolor="#444444", labelcolor="white")

    # Логотип AEGIS в правом нижнем углу
    ax.text(0.98, 0.02, "AEGIS", transform=ax.transAxes,
            fontsize=28, color="#cc0000", alpha=0.4,
            ha="right", va="bottom", fontweight="bold")

    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, facecolor=COLOR_BG, bbox_inches="tight")

    # SVG — если запрошен
    if output_svg is None:
        output_svg = output_path.replace(".png", ".svg")
    try:
        plt.savefig(output_svg, format="svg", facecolor=COLOR_BG, bbox_inches="tight")
    except Exception:
        output_svg = None

    plt.close()
    return output_path


# ============================================================
# Граф 2: Attack Path (target → CVE → exploit → impact)
# ============================================================

def build_attack_path(target, exploit_results, cracked_pairs=None):
    """
    Дерево атаки:
        TARGET
          ├─ CVE-2011-2523 (vsftpd backdoor)
          │     └─ EXPLOIT OK → uid=0(root)
          │            └─ /etc/shadow → 6 паролей
    """
    if not HAS_GRAPH:
        return None
    G = nx.DiGraph()
    G.add_node("target", label=f"TARGET\n{target}",
               color=COLOR_TARGET, size=4000)

    for i, r in enumerate(exploit_results or []):
        cve = r.get("cve", "?")
        name = (r.get("name") or "")[:40]
        success = r["result"]["success"]
        cve_id = f"cve_{i}"
        G.add_node(cve_id, label=f"{cve}\n{name}",
                   color=COLOR_HIGH if success else COLOR_NONE,
                   size=2500)
        G.add_edge("target", cve_id)

        if success:
            expl_id = f"expl_{i}"
            G.add_node(expl_id, label="EXPLOIT OK",
                       color=COLOR_EXPLOIT_OK, size=2000)
            G.add_edge(cve_id, expl_id)

            if cracked_pairs:
                crack_id = "cracked"
                G.add_node(crack_id,
                           label=f"/etc/shadow\n{cracked_pairs} паролей",
                           color=COLOR_EXPLOIT_OK, size=2200)
                G.add_edge(expl_id, crack_id)

    return G


def render_attack_path(G, output_path="reports/attack_path.png"):
    if not HAS_GRAPH or G is None:
        return None
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    fig, ax = plt.subplots(figsize=(16, 10), facecolor=COLOR_BG)
    ax.set_facecolor(COLOR_BG)

    try:
        pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
    except Exception:
        pos = nx.spring_layout(G, k=3, seed=42)

    node_colors = [G.nodes[n].get("color", "#ffffff") for n in G.nodes()]
    node_sizes = [G.nodes[n].get("size", 1500) for n in G.nodes()]
    labels = {n: G.nodes[n].get("label", n) for n in G.nodes()}

    nx.draw_networkx_edges(G, pos, edge_color=COLOR_EDGE,
                           arrows=True, arrowsize=25, width=2, alpha=0.7, ax=ax)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes,
                           alpha=0.95, edgecolors="#ffffff", linewidths=2, ax=ax)
    nx.draw_networkx_labels(G, pos, labels=labels,
                            font_size=9, font_color="white", font_weight="bold", ax=ax)

    title = f"AEGIS — Attack Path\n{datetime.now().strftime('%Y-%m-%d %H:%M')}"
    plt.title(title, color="white", fontsize=16, pad=20, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, facecolor=COLOR_BG, bbox_inches="tight")
    plt.close()
    return output_path


# ============================================================
# ASCII
# ============================================================

def ascii_graph(ports):
    lines = ["",
             "  ┌─────────────────────┐",
             "  │       TARGET        │",
             "  └──────────┬──────────┘"]
    for p in ports[:10]:
        if isinstance(p, dict):
            label = f"{p.get('port')}/{p.get('service', '?')}"
            if p.get("cve_count"):
                label += f" [{p['cve_count']} CVE]"
        else:
            label = str(p)
        lines += ["             │",
                  "             ▼",
                  "  ┌─────────────────────┐",
                  f"  │ {label:<19} │",
                  "  └─────────────────────┘"]
    return "\n".join(lines)


if __name__ == "__main__":
    demo = [
        {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4",
         "cve_count": 1, "max_score": 10.0},
        {"port": 22, "service": "ssh", "version": "OpenSSH 4.7",
         "cve_count": 2, "max_score": 6.5},
    ]
    print(ascii_graph(demo))
    G = build_attack_graph("192.168.64.7", demo)
    if G:
        p = render_graph(G, "reports/attack_graph_test.png")
        print("[+] Attack graph:", p)
        print("[+] SVG:", p.replace(".png", ".svg"))

    results = [
        {"cve": "CVE-2011-2523", "name": "vsftpd backdoor",
         "result": {"success": True}},
        {"cve": "CVE-2006-2369", "name": "VNC no-auth",
         "result": {"success": False}},
    ]
    G2 = build_attack_path("192.168.64.7", results, cracked_pairs=6)
    if G2:
        p2 = render_attack_path(G2, "reports/attack_path_test.png")
        print("[+] Attack path:", p2)
