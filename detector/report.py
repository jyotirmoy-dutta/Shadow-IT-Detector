import csv
import json
from tabulate import tabulate

def print_report(title, findings):
    if not findings:
        print(f"No {title} detected.")
        return
    print(f"\n{title}:")
    print(tabulate(findings, headers="keys"))

def export_csv(filename, findings):
    if not findings:
        return
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=findings[0].keys())
        writer.writeheader()
        writer.writerows(findings)

def export_json(filename, findings):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2) 