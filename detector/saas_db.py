import csv
import os

def load_saas_domains(csv_path=None):
    if csv_path is None:
        csv_path = os.path.join(os.path.dirname(__file__), '../data/saas_services.csv')
    saas_domains = set()
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row and not row[0].startswith('#'):
                saas_domains.add(row[0].strip().lower())
    return saas_domains 