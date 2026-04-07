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

# Configuration setup
with open("config.json") as f:
    config = json.load(f)

LOGS_DIR = config.get("logs_dir", "logs")
BF_LIMIT = config["bruteforce_limit"]
DOS_LIMIT = config["dos_limit"]

# ---------------- COMMAND LINE INTERFACE ----------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Log File Analyzer - Intrusion Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("files", nargs="*", help="Log files to analyze")
    parser.add_argument("--ssh", metavar="FILE", help="Force treat as SSH log")
    parser.add_argument("--apache", metavar="FILE", help="Force treat as Apache log")
    parser.add_argument("--no-graph", action="store_true", help="Skip graph generation")
    return parser.parse_args()

# ---------------- LOG DISCOVERY ----------------

def find_logs(logs_dir):
    folder = Path(logs_dir)
    if not folder.exists():
        print(f"[!] Directory not found: {logs_dir}")
        return [], []

    all_files = list(folder.glob("*.log")) + list(folder.glob("*.txt"))
    apache_files, ssh_files = [], []

    for f in all_files:
        name = f.name.lower()
        if any(k in name for k in ["apache", "access", "http"]):
            apache_files.append(f)
        elif any(k in name for k in ["ssh", "auth", "secure"]):
            ssh_files.append(f)

    return apache_files, ssh_files

def resolve_files(args):
    if not args.files and not args.ssh and not args.apache:
        return find_logs(LOGS_DIR)

    apache_files, ssh_files = [], []
    if args.apache:
        p = Path(args.apache)
        if p.exists(): apache_files.append(p)
    if args.ssh:
        p = Path(args.ssh)
        if p.exists(): ssh_files.append(p)

    for fname in args.files:
        p = Path(fname)
        if not p.exists(): p = Path(LOGS_DIR) / fname
        if not p.exists(): continue

        name = p.name.lower()
        if any(k in name for k in ["apache", "access", "http"]):
            apache_files.append(p)
        elif any(k in name for k in ["ssh", "auth", "secure"]):
            ssh_files.append(p)
    
    return apache_files, ssh_files

# ---------------- PARSING LOGIC ----------------

def parse_ssh(files):
    pattern = r'Failed password for .*? from (\d+\.\d+\.\d+\.\d+)'
    ips = []
    for file in files:
        with open(file) as f:
            for line in f:
                m = re.search(pattern, line)
                if m:
                    ips.append(m.group(1))
    return ips

def parse_apache(files):
    pattern = r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+)'
    data = []
    for file in files:
        with open(file) as f:
            for line in f:
                m = re.search(pattern, line)
                if m:
                    data.append([m.group(1), m.group(2), m.group(3), m.group(4)])
    return data

# ---------------- DETECTION ENGINES ----------------

def detect_bruteforce(ip_list):
    counts = Counter(ip_list)
    return [(ip, n) for ip, n in counts.items() if n >= BF_LIMIT]

def detect_dos(data):
    if not data:
        return pd.Series(dtype=int)
    df = pd.DataFrame(data, columns=["ip", "time", "req", "status"])
    count = df["ip"].value_counts()
    return count[count >= DOS_LIMIT]

# ---------------- THREAT INTELLIGENCE ----------------

def load_blacklist(file="blacklist.txt"):
    p = Path(file)
    return set(p.read_text().splitlines()) if p.exists() else set()

def check_blacklist(ip_list, blacklist):
    return list(set(ip for ip in ip_list if ip in blacklist))

# ---------------- VISUALIZATION ----------------

def plot_ips(data, blacklist=set(), bf_ips=set(), dos_ips=set()):
    if not data: return
    Path("graphs").mkdir(exist_ok=True)

    df = pd.DataFrame(data, columns=["ip", "time", "req", "status"])
    counts = df["ip"].value_counts().head(10)
    colors = ["#c0392b" if ip in blacklist else "#e67e22" if (ip in bf_ips or ip in dos_ips) else "#2980b9" for ip in counts.index]

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")
    ax.bar(counts.index, counts.values, color=colors)

    ax.set_title("Top IP Access Count", color="white", fontweight="bold")
    ax.tick_params(colors="white")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("graphs/access.png", facecolor=fig.get_facecolor())
    plt.close()

# ---------------- REPORTING ----------------

def save_report(bf, dos, bad):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = [f"{'='*40}\n Intrusion Detection Report\n {timestamp}\n{'='*40}"]

    output.append("\n[Brute Force - SSH]")
    output.extend([f"  {ip} -> {n} attempts" for ip, n in bf] if bf else ["  no alerts"])

    output.append("\n[DoS Pattern - Apache]")
    output.extend([f"  {ip} -> {n} requests" for ip, n in dos.items()] if not dos.empty else ["  no alerts"])

    output.append("\n[Blacklisted IPs]")
    output.extend([f"  {ip}" for ip in bad] if bad else ["  none found"])

    report_content = "\n".join(output)
    with open("report.txt", "w") as f:
        f.write(report_content)
    print(report_content)

# ---------------- EXECUTION ----------------

def main():
    args = parse_args()
    apache_files, ssh_files = resolve_files(args)

    apache_data = parse_apache(apache_files)
    ssh_data = parse_ssh(ssh_files)

    bf_alerts = detect_bruteforce(ssh_data)
    dos_alerts = detect_dos(apache_data)

    blacklist = load_blacklist()
    all_seen_ips = ssh_data + [row[0] for row in apache_data]
    blacklisted_found = check_blacklist(all_seen_ips, blacklist)

    if not args.no_graph:
        plot_ips(apache_data, blacklist, set(i for i, _ in bf_alerts), set(dos_alerts.index))

    save_report(bf_alerts, dos_alerts, blacklisted_found)

if __name__ == "__main__":
    main()
