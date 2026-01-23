import csv
import io
import json
import hashlib
import os
import zipfile

import tldextract
from pybloom_live import BloomFilter

# Settings: good starter values
EXPECTED_ITEMS = 1_000_000
ERROR_RATE = 0.01

extractor = tldextract.TLDExtract(cache_dir=False)  # deterministic in CI


def etld1(host: str) -> str | None:
    host = (host or "").strip().lower().rstrip(".")
    if not host or " " in host:
        return None
    r = extractor(host)
    if not r.domain or not r.suffix:
        return None
    return f"{r.domain}.{r.suffix}"


def build(zip_path: str, out_bloom: str, out_meta: str):
    bloom = BloomFilter(capacity=EXPECTED_ITEMS, error_rate=ERROR_RATE)

    with zipfile.ZipFile(zip_path, "r") as z:
        csv_name = next(n for n in z.namelist() if n.endswith(".csv"))
        with z.open(csv_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="ignore"))
            for row in reader:
                if len(row) < 2:
                    continue
                d = etld1(row[1])
                if d:
                    bloom.add(d)

    os.makedirs(os.path.dirname(out_bloom), exist_ok=True)

    # Write bloom
    with open(out_bloom, "wb") as bf:
        bloom.tofile(bf)

    # Write meta with checksum
    bloom_bytes = open(out_bloom, "rb").read()
    sha256 = hashlib.sha256(bloom_bytes).hexdigest()

    meta = {
        "source": "tranco",
        "items_capacity": EXPECTED_ITEMS,
        "error_rate": ERROR_RATE,
        "sha256": sha256,
        "format": "pybloom_live.tofile",
    }
    with open(out_meta, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)


if __name__ == "__main__":
    build(
        "data/tranco_ZWJ8G-1m.csv.zip",
        "artifacts/tranco.bloom",
        "artifacts/tranco.meta.json",
    )
