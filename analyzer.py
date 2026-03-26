import re
import sys
import json
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import MaxNLocator
from collections import Counter
from datetime import datetime
from pathlib import Path


# load config
with open("config.json") as f:
    config = json.load(f)

LOGS_DIR = config.get("logs_dir", "logs")
BF_LIMIT = config["bruteforce_limit"]
DOS_LIMIT = config["dos_limit"]


# ---------------- CLI ----------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Log File Analyzer - Intrusion Detection Tool",
        epilog="""
examples:
  python analyzer.py                    analyze all logs in logs/ folder
  python analyzer.py ssh.log            analyze a single ssh log file
  python analyzer.py apache.log         analyze a single apache log file
  python analyzer.py ssh.log apache.log analyze multiple files at once
  python analyzer.py --ssh ssh.log      force treat file as ssh log
  python analyzer.py --apache a.log     force treat file as apache log
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "files",
        nargs="*",
        help="log files to analyze (auto-detected by filename)"
    )
    parser.add_argument(
        "--ssh",
        metavar="FILE",
        help="force treat this file as an ssh log"
    )
    parser.add_argument(
        "--apache",
        metavar="FILE",
        help="force treat this file as an apache log"
    )
    parser.add_argument(
        "--no-graph",
        action="store_true",
        help="skip generating the graph"
    )

    return parser.parse_args()


# ---------------- AUTO DETECT LOGS ----------------

def find_logs(logs_dir):
    folder = Path(logs_dir)

    if not folder.exists():
        print(f"[!] logs folder not found: {logs_dir}")
        return [], []

    all_files = list(folder.glob("*.log")) + list(folder.glob("*.txt"))

    apache_files = []
    ssh_files = []

    for f in all_files:
        name = f.name.lower()
        if any(k in name for k in ["apache", "access", "http"]):
            apache_files.append(f)
        elif any(k in name for k in ["ssh", "auth", "secure"]):
            ssh_files.append(f)

    print(f"[*] found {len(apache_files)} apache log(s): {[f.name for f in apache_files]}")
    print(f"[*] found {len(ssh_files)} ssh log(s):    {[f.name for f in ssh_files]}")

    return apache_files, ssh_files


def resolve_files(args):
    # if no args at all, fall back to auto-detect from logs folder
    if not args.files and not args.ssh and not args.apache:
        return find_logs(LOGS_DIR)

    apache_files = []
    ssh_files = []

    # forced file types via flags
    if args.apache:
        p = Path(args.apache)
        if not p.exists():
            print(f"[!] file not found: {args.apache}")
        else:
            apache_files.append(p)

    if args.ssh:
        p = Path(args.ssh)
        if not p.exists():
            print(f"[!] file not found: {args.ssh}")
        else:
            ssh_files.append(p)

    # positional files - auto-detect type by name
    for fname in args.files:
        p = Path(fname)
        if not p.exists():
            # also try looking inside logs/ folder
            p = Path(LOGS_DIR) / fname
        if not p.exists():
            print(f"[!] file not found: {fname}")
            continue

        name = p.name.lower()
        if any(k in name for k in ["apache", "access", "http"]):
            apache_files.append(p)
            print(f"[*] treating {p.name} as apache log")
        elif any(k in name for k in ["ssh", "auth", "secure"]):
            ssh_files.append(p)
            print(f"[*] treating {p.name} as ssh log")
        else:
            # unknown name - try to detect by content
            kind = detect_by_content(p)
            if kind == "ssh":
                ssh_files.append(p)
                print(f"[*] detected {p.name} as ssh log (by content)")
            elif kind == "apache":
                apache_files.append(p)
                print(f"[*] detected {p.name} as apache log (by content)")
            else:
                print(f"[!] could not detect type for {p.name}, skipping")

    return apache_files, ssh_files


def detect_by_content(filepath):
    # peek at first 20 lines to figure out the log type
    try:
        with open(filepath) as f:
            sample = [f.readline() for _ in range(20)]
    except Exception:
        return "unknown"

    ssh_hits = sum(1 for l in sample if "Failed password" in l or "sshd" in l)
    apache_hits = sum(1 for l in sample if re.search(r'"(GET|POST|PUT|DELETE)', l))

    if ssh_hits > apache_hits:
        return "ssh"
    elif apache_hits > ssh_hits:
        return "apache"
    return "unknown"


# ---------------- PARSERS ----------------

def parse_apache(files):
    pattern = r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(.*?)" (\d+)'
    data = []

    for file in files:
        with open(file) as f:
            for line in f:
                m = re.search(pattern, line)
                if m:
                    data.append([m.group(1), m.group(2), m.group(3), m.group(4)])

    return data


def parse_ssh(files):
    pattern = r'Failed password for \S+ from (\d+\.\d+\.\d+\.\d+)'
    ips = []

    for file in files:
        with open(file) as f:
            for line in f:
                m = re.search(pattern, line)
                if m:
                    ips.append(m.group(1))

    return ips


# ---------------- DETECTION ----------------

def detect_bruteforce(ip_list):
    counts = Counter(ip_list)
    alerts = []

    for ip, n in counts.items():
        if n >= BF_LIMIT:
            alerts.append((ip, n))

    return alerts


def detect_dos(data):
    if not data:
        return pd.Series(dtype=int)

    df = pd.DataFrame(data, columns=["ip", "time", "req", "status"])
    count = df["ip"].value_counts()
    return count[count >= DOS_LIMIT]


# ---------------- BLACKLIST ----------------

def load_blacklist(file="blacklist.txt"):
    p = Path(file)
    if not p.exists():
        print(f"[!] blacklist not found: {file}")
        return set()
    return set(p.read_text().splitlines())


def check_blacklist(ip_list, blacklist):
    return list(set(ip for ip in ip_list if ip in blacklist))


# ---------------- GRAPH ----------------

def plot_ips(data, blacklist=set(), bf_ips=set(), dos_ips=set()):
    if not data:
        print("[!] no apache data to plot")
        return

    Path("graphs").mkdir(exist_ok=True)

    df = pd.DataFrame(data, columns=["ip", "time", "req", "status"])
    counts = df["ip"].value_counts().head(10)

    colors = []
    for ip in counts.index:
        if ip in blacklist:
            colors.append("#c0392b")
        elif ip in bf_ips or ip in dos_ips:
            colors.append("#e67e22")
        else:
            colors.append("#2980b9")

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    bars = ax.bar(counts.index, counts.values, color=colors, edgecolor="#0f3460", linewidth=0.8, width=0.6)

    for bar, val in zip(bars, counts.values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            str(val),
            ha="center", va="bottom",
            fontsize=10, color="white", fontweight="bold"
        )

    ax.set_title("Top IP Access Count", fontsize=15, color="white", pad=16, fontweight="bold")
    ax.set_xlabel("IP Address", fontsize=11, color="#aaaaaa", labelpad=10)
    ax.set_ylabel("Number of Requests", fontsize=11, color="#aaaaaa", labelpad=10)

    ax.tick_params(colors="white", labelsize=9)
    ax.set_xticks(range(len(counts.index)))
    ax.set_xticklabels(counts.index, rotation=30, ha="right", color="white")

    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.yaxis.label.set_color("#aaaaaa")

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#333366")
    ax.spines["bottom"].set_color("#333366")

    ax.yaxis.grid(True, linestyle="--", alpha=0.3, color="#aaaaaa")
    ax.set_axisbelow(True)

    legend_patches = [
        mpatches.Patch(color="#c0392b", label="Blacklisted"),
        mpatches.Patch(color="#e67e22", label="Suspicious (DoS / Brute Force)"),
        mpatches.Patch(color="#2980b9", label="Normal"),
    ]
    ax.legend(
        handles=legend_patches,
        loc="upper right",
        fontsize=9,
        facecolor="#1a1a2e",
        edgecolor="#333366",
        labelcolor="white"
    )

    plt.tight_layout()
    plt.savefig("graphs/access.png", dpi=150, facecolor=fig.get_facecolor())
    plt.close()


# ---------------- REPORT ----------------

def save_report(bf, dos, bad):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    lines.append("=" * 40)
    lines.append("   Intrusion Detection Report")
    lines.append(f"   {timestamp}")
    lines.append("=" * 40)

    lines.append("\n[Brute Force - SSH]")
    if bf:
        for ip, n in bf:
            lines.append(f"  {ip}  ->  {n} failed attempts")
    else:
        lines.append("  no alerts")

    lines.append("\n[DoS Pattern - Apache]")
    if not dos.empty:
        for ip, n in dos.items():
            lines.append(f"  {ip}  ->  {n} requests")
    else:
        lines.append("  no alerts")

    lines.append("\n[Blacklisted IPs]")
    if bad:
        for ip in bad:
            lines.append(f"  {ip}")
    else:
        lines.append("  none found")

    report = "\n".join(lines)

    with open("report.txt", "w") as f:
        f.write(report)

    print(report)
    print("\n[*] report saved to report.txt")
    print("[*] graph saved to graphs/access.png")


# ---------------- MAIN ----------------

def main():
    args = parse_args()
    apache_files, ssh_files = resolve_files(args)

    apache = parse_apache(apache_files)
    ssh = parse_ssh(ssh_files)

    bf = detect_bruteforce(ssh)
    dos = detect_dos(apache)

    blacklist = load_blacklist("blacklist.txt")
    bad = check_blacklist(ssh, blacklist)

    bf_ips = set(ip for ip, _ in bf)
    dos_ips = set(dos.index) if not dos.empty else set()

    if not args.no_graph:
        plot_ips(apache, blacklist=blacklist, bf_ips=bf_ips, dos_ips=dos_ips)

    save_report(bf, dos, bad)


if __name__ == "__main__":
    main()
