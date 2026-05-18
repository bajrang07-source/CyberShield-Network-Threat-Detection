"""
Generate 10,000 labeled rows for the CyberShield ML training dataset.
Output: data/requests_labeled.csv (relative to project root, i.e., backend/data/)
"""
import os
import random
import numpy as np
import pandas as pd

random.seed(42)
np.random.seed(42)

COLUMNS = [
    "payload_length", "num_special_chars", "has_sql_keywords", "has_xss_patterns",
    "has_path_traversal", "request_rate_1m", "request_rate_5m", "is_known_bad_ua",
    "entropy_payload", "num_query_params", "method_is_post", "label", "attack_type"
]


def make_normal(n=7000):
    rows = []
    for _ in range(n):
        rows.append({
            "payload_length": random.randint(10, 200),
            "num_special_chars": random.randint(0, 3),
            "has_sql_keywords": 0,
            "has_xss_patterns": 0,
            "has_path_traversal": 0,
            "request_rate_1m": random.randint(1, 5),
            "request_rate_5m": random.randint(2, 15),
            "is_known_bad_ua": 0,
            "entropy_payload": round(random.uniform(2.0, 3.5), 4),
            "num_query_params": random.randint(0, 3),
            "method_is_post": random.randint(0, 1),
            "label": 0,
            "attack_type": "NORMAL",
        })
    return rows


def make_sqli(n=1500):
    rows = []
    for _ in range(n):
        rows.append({
            "payload_length": random.randint(50, 400),
            "num_special_chars": random.randint(5, 20),
            "has_sql_keywords": 1,
            "has_xss_patterns": 0,
            "has_path_traversal": 0,
            "request_rate_1m": random.randint(1, 10),
            "request_rate_5m": random.randint(2, 30),
            "is_known_bad_ua": random.randint(0, 1),
            "entropy_payload": round(random.uniform(3.5, 5.0), 4),
            "num_query_params": random.randint(1, 5),
            "method_is_post": random.randint(0, 1),
            "label": 1,
            "attack_type": "SQL_INJECTION",
        })
    return rows


def make_xss(n=1000):
    rows = []
    for _ in range(n):
        rows.append({
            "payload_length": random.randint(30, 300),
            "num_special_chars": random.randint(4, 15),
            "has_sql_keywords": 0,
            "has_xss_patterns": 1,
            "has_path_traversal": 0,
            "request_rate_1m": random.randint(1, 8),
            "request_rate_5m": random.randint(2, 25),
            "is_known_bad_ua": random.randint(0, 1),
            "entropy_payload": round(random.uniform(3.0, 4.5), 4),
            "num_query_params": random.randint(0, 4),
            "method_is_post": random.randint(0, 1),
            "label": 1,
            "attack_type": "XSS",
        })
    return rows


def make_brute_force(n=500):
    rows = []
    for _ in range(n):
        rows.append({
            "payload_length": random.randint(20, 80),
            "num_special_chars": random.randint(0, 5),
            "has_sql_keywords": 0,
            "has_xss_patterns": 0,
            "has_path_traversal": 0,
            "request_rate_1m": random.randint(11, 50),
            "request_rate_5m": random.randint(30, 200),
            "is_known_bad_ua": random.randint(0, 1),
            "entropy_payload": round(random.uniform(2.0, 3.5), 4),
            "num_query_params": random.randint(0, 2),
            "method_is_post": 1,
            "label": 1,
            "attack_type": "BRUTE_FORCE",
        })
    return rows


def main():
    rows = make_normal() + make_sqli() + make_xss() + make_brute_force()
    df = pd.DataFrame(rows, columns=COLUMNS)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Determine output path: backend/data/ relative to this script's parent (backend/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(script_dir)
    data_dir = os.path.join(backend_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    out_path = os.path.join(data_dir, "requests_labeled.csv")
    df.to_csv(out_path, index=False)
    print(f"[generate_dataset] Saved {len(df):,} rows to {out_path}")
    print(df["attack_type"].value_counts())


if __name__ == "__main__":
    main()
