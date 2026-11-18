"""Section 4.2: timestamp precision of the Monday and Tuesday label tables.

Output: results/label_timestamp_precision.csv
"""
import pandas as pd

from common import load_labels, parse_args, save


def main():
    a = parse_args(__doc__)
    rows = []
    for day in ("monday", "tuesday"):
        df = load_labels(a.labels, day)
        ts = df["Timestamp"]
        rows.append({
            "day": day,
            "records": len(df),
            "records_with_nonzero_seconds": int((ts.dt.second != 0).sum()),
            "records_with_nonzero_microseconds": int((ts.dt.microsecond != 0).sum()),
            "first_utc": ts.min(), "last_utc": ts.max(),
            "labels": "; ".join(f"{k}={v}" for k, v in df["Label"].value_counts().items()),
        })
    out = pd.DataFrame(rows)
    print(out.to_string(index=False))
    save(out, a.out, "label_timestamp_precision.csv")


if __name__ == "__main__":
    main()
