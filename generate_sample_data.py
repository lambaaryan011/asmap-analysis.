"""
generate_sample_data.py
-----------------------
Generates two realistic ASmap text files (baseline + candidate)
so you can demo the tool without real .asmap files.

The candidate has realistic changes applied:
  - ~3% new prefixes added
  - ~2% prefixes removed
  - ~4% ASN reassignments

Usage:
    python generate_sample_data.py
    python main.py --baseline baseline.txt --candidate candidate.txt --top 10 --json --md
"""

import random
import ipaddress

random.seed(42)

ASN_POOL = [
    "AS13335", "AS15169", "AS16509", "AS8075",  "AS14618",
    "AS2906",  "AS32934", "AS24940", "AS20940", "AS3356",
    "AS1299",  "AS174",   "AS3257",  "AS6939",  "AS4134",
    "AS9808",  "AS4837",  "AS7018",  "AS5511",  "AS1273",
]

# Realistic IPv4 prefixes — use real-looking ranges
IPV4_FIRST_OCTETS = [
    1, 2, 5, 8, 14, 17, 23, 31, 37, 41,
    45, 51, 58, 62, 66, 71, 77, 80, 84, 89,
    91, 94, 96, 103, 104, 108, 109, 110, 113, 116,
    118, 119, 122, 124, 125, 128, 130, 131, 134, 136,
    139, 140, 141, 143, 144, 146, 148, 151, 152, 154,
    157, 158, 159, 160, 163, 164, 166, 167, 168, 170,
    171, 172, 173, 174, 176, 177, 178, 179, 180, 182,
    183, 185, 186, 187, 188, 190, 192, 193, 194, 195,
    196, 197, 198, 199, 200, 201, 202, 203, 204, 206,
    208, 210, 211, 212, 213, 216, 217, 218, 219, 220,
]

def random_prefix_v4():
    first  = random.choice(IPV4_FIRST_OCTETS)
    second = random.randint(0, 255)
    third  = random.randint(0, 255)
    length = random.choice([16, 20, 22, 24])
    net    = ipaddress.IPv4Network(f"{first}.{second}.{third}.0/{length}", strict=False)
    return str(net)

def random_prefix_v6():
    g1     = random.randint(0x2000, 0x3fff)
    g2     = random.randint(0, 0xffff)
    length = random.choice([32, 40, 48])
    net    = ipaddress.IPv6Network(f"{g1:x}:{g2:x}::/{length}", strict=False)
    return str(net)

def generate_baseline(n: int = 3000) -> dict:
    prefixes = set()
    while len(prefixes) < n:
        if random.random() < 0.75:
            prefixes.add(random_prefix_v4())
        else:
            prefixes.add(random_prefix_v6())
    return {p: random.choice(ASN_POOL) for p in prefixes}

def apply_changes(baseline: dict,
                  add_pct=0.03,
                  remove_pct=0.02,
                  change_pct=0.04) -> dict:
    candidate = dict(baseline)
    pfx_list  = list(baseline.keys())

    # Remove
    for p in random.sample(pfx_list, int(len(pfx_list) * remove_pct)):
        del candidate[p]

    # Change ASN
    for p in random.sample(list(candidate.keys()), int(len(candidate) * change_pct)):
        old = candidate[p]
        candidate[p] = random.choice([a for a in ASN_POOL if a != old])

    # Add
    new_pfxs: set = set()
    while len(new_pfxs) < int(len(baseline) * add_pct):
        pfx = random_prefix_v4() if random.random() < 0.75 else random_prefix_v6()
        if pfx not in candidate:
            new_pfxs.add(pfx)
    for p in new_pfxs:
        candidate[p] = random.choice(ASN_POOL)

    return candidate

def write_file(mapping: dict, path: str):
    with open(path, "w") as f:
        f.write("# ASmap text format — generated sample data\n")
        for prefix, asn in sorted(mapping.items()):
            f.write(f"{prefix} {asn}\n")
    print(f"  Written {len(mapping):,} prefixes  →  {path}")

if __name__ == "__main__":
    print("Generating sample ASmap data...")
    baseline  = generate_baseline(3000)
    candidate = apply_changes(baseline)
    write_file(baseline,  "baseline.txt")
    write_file(candidate, "candidate.txt")
    print("\nSample files ready. Now run:")
    print("  python main.py --baseline baseline.txt --candidate candidate.txt --top 10 --json --md")
